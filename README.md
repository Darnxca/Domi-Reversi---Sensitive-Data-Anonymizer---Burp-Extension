# Domi Reversi — estensione nativa per Burp

Questa cartella contiene il **port nativo in Java** dell'anonimizzatore, pensato
per essere **pubblicato sul BApp Store**. È **autonomo**: nessun Python a
runtime, nessun processo esterno, nessuna dipendenza da installare. Tutta la
logica gira dentro Burp e i pattern sono **risorse bundlate nel jar**.

È indipendente dalla via Jython (`../burp-extension/`), che resta valida per
l'uso personale/distribuzione fuori dallo store.

> Perché un port e non il ponte Jython? Il BApp Store richiede estensioni
> **self-contained / installazione one-click** e raccomanda **Montoya (Java)**;
> un'estensione che lancia `python3` verrebbe rifiutata. Il codice Python resta
> la **specifica di riferimento** e i suoi test i casi da riprodurre.

---

## Struttura

```
burp-bapp/
├── gradle
│   ├── gradle-wrapper.jar
│   ├── gradle-wrapper.properties
├── build.gradle            # build Gradle (Shadow: jar autonomo con Gson)
├── settings.gradle
├── src/main/java/com/domireversi/
│   ├── DomiReversiExtension.java   # entry point (BurpExtension, Montoya)
│   ├── DomiReversiMenu.java        # menu contestuale
│   ├── ui/DomiReversiTab.java      # UI Swing (usa il core, niente Montoya)
│   └── core/                       # LOGICA PURA (nessuna dipendenza Burp)
│       ├── Anonymizer.java         # motore: header + body + regex + host + deanon
│       ├── HttpMessage.java        # parsing/serializzazione HTTP robusti
│       ├── SubstitutionMap.java    # placeholder coerenti + mappa inversa
│       ├── Overrides.java          # override utente (extra/exclude)
│       ├── Config.java             # carica i JSON bundlati (Gson)
│       └── PatternDef.java
│   ├── src/main/resources/
│   │   ├── sensitive_headers.json      # copiati dal tool (stessa fonte di verità)
│   │   └── sensitive_patterns.json
├── src/test/java/com/domireversi/AnonymizerTest.java   # 29 test JUnit
├── build.sh                        # build del jar senza Gradle
└── selftest/SelfTest.java          # verifica locale rapida (senza JUnit)
```

Il `core` non importa nulla di Burp: è **testabile in isolamento** (i test
girano senza Montoya). Solo `DomiReversiExtension`/`DomiReversiMenu` toccano
l'API Montoya.

---

## Build

Serve un JDK 17+ (Burp gira su JRE recente). Con Gradle:

```bash
cd burp-bapp
gradle shadowJar         # oppure: ./gradlew shadowJar dopo 'gradle wrapper'
# -> build/libs/domi-reversi-burp-1.0.0.jar   (autonomo, Gson incluso)
```

Montoya è `compileOnly` (Burp la fornisce a runtime, non finisce nel jar); Gson
è bundlato e **rilocato** in `com.domireversi.shaded.gson` per evitare conflitti.

### Caricare in Burp
Extensions → Installed → **Add** → *Extension type*: **Java** → seleziona
`build/libs/domi-reversi-burp-1.0.0.jar`. Comparirà il tab **Domi Reversi** e la
voce di menu **“Anonimizza con Domi Reversi”** (tasto destro su una
request/response).

---

## Test

```bash
gradle test        # 29 test JUnit (com.domireversi.AnonymizerTest)
```

I test coprono gli stessi casi della versione Python: header, JSON per-chiave +
regex, provider key, domini nudi, coerenza, form, multipart (+base64), chunked
(+multibyte), HTML, GraphQL, de-anonimizzazione, Luhn, robustezza. (Verificati
anche via `selftest/SelfTest.java`, 41 asserzioni.)

### Test in Burp prima dell'invio (manuale)

La logica è coperta dai test automatici; l'interazione dentro Burp va provata a
mano:

1. **Costruisci il jar**: `./build.sh` (o `gradle shadowJar`).
2. **Carica**: Extensions → Add → *Extension type: Java* → seleziona
   `build/libs/domi-reversi-burp-1.0.0.jar`.
3. **Verifica il caricamento**: nell'**Output** compare il messaggio di avvio;
   l'**Errors** è vuoto; appare il tab **Domi Reversi** e la voce di menu
   contestuale.
4. **Prova funzionale**: naviga un sito (browser di Burp) per popolare la Proxy
   history → tasto destro su una richiesta → *Anonimizza con Domi Reversi* →
   controlla output, **Mappa sostituzioni**, e **De-anonimizza**. Casi utili:
   Authorization/Cookie in request, Set-Cookie/Server in response, body JSON con
   `password`/`email`, un upload **multipart**, una response **chunked**.
5. **Offline**: stacca la rete e verifica che funzioni comunque (tutto è
   bundlato, nessuna chiamata esterna).
6. **Robustezza**: incolla input malformato/grande → nessun crash.

> Prima della submission: repo GitHub pubblico + README + licenza; verifica sullo
> store che non esista già un'estensione equivalente.

---

## Copertura

Il port Java copre **gli stessi formati della versione desktop Python**:

- start line; header selettivi (host, auth, cookie/set-cookie, IP/forwarding,
  referer/origin/location, apikey/token, redact, host-scan, user-agent,
  auth-challenge, custom-scan, keep-list);
- **JSON** (redazione per-chiave + nidificata + regex sulle stringhe);
- **form-urlencoded** (con decodifica percent-encoding);
- **multipart/form-data**: per-parte, filename (quoted/`filename*=`/non quotato),
  redazione per nome-campo, **multipart annidato** e parti
  **`Content-Transfer-Encoding: base64`/`quoted-printable`** (decodifica →
  anonimizza → ri-codifica; blob binari redatti in blocco);
- **`Transfer-Encoding: chunked`**: ri-assemblato in **ottetti** (corretto anche
  con contenuto multibyte/emoji) e ri-codificato come chunked valido;
- **HTML/XML**: testo sotto tag dal nome sensibile, attributi `value`/`content`/
  `data-*`, host in `href`/`src`/`action`, più scansione dei nodi testo;
- **GraphQL**: literal inline nel campo `query` (e `application/graphql`) sotto
  argomenti sensibili, oltre alle `variables`;
- scansione regex generica su qualunque altro body; host noti/URL/domini nudi
  (allow-list TLD); coerenza dei placeholder; de-anonimizzazione.

**Extra (solo Burp):**
- **Lingua EN/IT** (selettore in alto; default English per lo store).
- Mappa sostituzioni in un **tab dedicato**, con una **spunta per valore**:
  togli la spunta per tenere quel valore in chiaro (si ri-anonimizza subito).
- **Anonimizzazione manuale**: seleziona testo in un input → tasto destro
  «Anonymize selection» o **Ctrl+Shift+A** → tutte le occorrenze → `CUSTOM_n`.
- Selettore **ambito** e menu contestuale a 3 voci: **request + response**,
  **solo request** o **solo response** (l'ambito scelto carica/anonimizza solo
  la parte richiesta).

> L'HTML/XML è gestito via regex (non un parser DOM come bs4): copre i casi
> comuni ed è coperto dalla scansione regex come rete di sicurezza. Un parser
> completo (jsoup) è un possibile miglioramento futuro.

Copertura verificata da **29 test JUnit** (`AnonymizerTest`) + `selftest`
(41 asserzioni), inclusi tutti i formati sopra.

---

## Pubblicazione sul BApp Store — checklist

1. **Sorgente su GitHub** (repo pubblico con questo progetto).
2. Apri una *New extension submission* sul repository
   **`PortSwigger/extension-portal`** con: link al repo, nome, descrizione, come
   funziona e istruzioni d'uso.
3. Requisiti di accettazione da soddisfare (già rispettati qui):
   - **Autonoma / one-click**: sì (jar unico, Gson incluso, nessun runtime esterno).
   - **Montoya API**: sì.
   - **Funziona offline**: sì (i pattern sono bundlati; nessuna chiamata di rete).
   - **Opera in sicurezza**, gestione errori graceful: sì (nessun crash su input malformato).
   - **Nessun duplicato**: da verificare sullo store che non esista già un'estensione equivalente.
   - Nome/descrizione chiari; niente “phone-home”.
4. PortSwigger valuta, **compila dal sorgente** e pubblica.

> La copertura dei formati è già allineata alla versione desktop (multipart,
> chunked, HTML/XML, GraphQL inclusi), quindi non offre meno del tool Python.
