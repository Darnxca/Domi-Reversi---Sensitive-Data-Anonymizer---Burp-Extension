package com.domireversi.core;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Motore di anonimizzazione.
 *
 * Pipeline: start line, header (strategie selettive), body per formato (JSON
 * tollerante, form, multipart, chunked, HTML/XML, GraphQL) e, su ogni testo
 * libero, la scansione generica: coppie chiave=valore sensibili, URL, pattern
 * (email, IP, carte, chiavi...), host noti e domini.
 *
 * Regole di robustezza: nessuna regex con gruppi ripetuti senza limite su input
 * arbitrario (niente blocchi o StackOverflow), host e domini riconosciuti con un
 * tokenizzatore lineare, i placeholder gia' emessi non vengono mai ri-anonimizzati.
 */
public final class Anonymizer {

    private final Config cfg;
    private final SubstitutionMap map;
    private final Overrides ov;

    private static final Set<String> SESSION_COOKIES = Set.of(
            "session", "sessionid", "sid", "jsessionid", "phpsessid",
            "aspnetsessionid", "aspxauth", "connectsid", "sessid", "authsession");

    private static final Set<String> ALLOWED_TLDS = Set.of(
            "com","net","org","edu","gov","mil","int","io","co","info","biz","name","pro",
            "app","dev","cloud","xyz","online","site","tech","store","ai","me","tv","gg",
            "ly","fm","us","uk","de","fr","es","it","ca","au","nl","be","ch","at",
            "se","no","dk","fi","pl","pt","ie","gr","cz","ru","ua","cn","jp","kr","in","br",
            "mx","ar","cl","za","tr","il","sa","ae","eu","asia","technology","solutions",
            "digital","agency","company","services","network","systems","group","global",
            "local","internal","corp","lan","intra","intranet","home","test","example","invalid","onion");

    /** URL con qualunque schema (http, postgres, redis, mongodb+srv, ...). */
    private static final Pattern URL_RE = Pattern.compile(
            "(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,20}://[^\\s\"'<>)\\]}`]+");
    private static final Pattern IPV4 = Pattern.compile("(?:\\d{1,3}\\.){3}\\d{1,3}");
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "^(Bearer|Basic|Digest|Negotiate|NTLM|Token|AWS4-HMAC-SHA256|HOBA|Mutual|SCRAM-SHA-256)\\s+(.+)$",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern DATA_URI = Pattern.compile(
            "data:[\\w.+-]{1,64}/[\\w.+-]{1,64}(?:;[\\w.=-]{1,64}){0,5};base64,[A-Za-z0-9+/=]+");
    private static final Pattern UUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern JSON_NUMBER = Pattern.compile("-?\\d{1,400}(?:\\.\\d{1,400})?(?:[eE][+-]?\\d{1,10})?");
    private static final Pattern DATE_LIKE = Pattern.compile(
            "\\d{4}[-/.]\\d{1,2}[-/.]\\d{1,2}|\\d{1,2}[-/.]\\d{1,2}[-/.]\\d{2,4}|\\d{4}\\s?-\\s?\\d{4}");
    private static final Pattern US_PHONE = Pattern.compile("\\(?\\d{3}\\)?[-. ]\\d{3}[-. ]\\d{4}");

    private static final Pattern AUTH_SCHEME_ONLY = Pattern.compile(
            "(?i)Bearer|Basic|Digest|Token|Negotiate|NTLM");
    private static final Pattern CODE_REF = Pattern.compile(
            "[A-Za-z_$][\\w$]{0,63}(?:\\.[A-Za-z_$][\\w$]{0,63}){1,8}(?:\\(\\))?");

    /** chiave + separatore di una coppia chiave/valore in testo libero. */
    private static final Pattern KV_KEY = Pattern.compile(
            "(?<![\\w-])([\"']?)([A-Za-z_][\\w.-]{0,63})\\1[ \\t]{0,10}(=>|:=|[:=])[ \\t]{0,10}");

    /** Tag di apertura HTML/XML (attributi limitati in lunghezza). */
    private static final Pattern TAG = Pattern.compile("<([A-Za-z_][\\w:.-]{0,63})(\\s[^<>]{0,16384})?>");
    private static final Pattern ATTR = Pattern.compile(
            "([\\w:.@-]{1,128})(\\s*=\\s*)(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))");
    private static final Pattern ELEM_TEXT = Pattern.compile(
            "(<([A-Za-z_][\\w:.-]{0,63})(?:\\s[^<>]{0,16384})?>)([^<]{0,100000})(</\\2\\s*>)");

    /** Chiavi sensibili solo dentro query string / form (nel JSON sono spesso innocue). */
    private static final Set<String> QUERY_ONLY_KEYS = Set.of(
            "code", "authcode", "ticket", "key", "samlresponse", "samlrequest", "accesscode");

    /** Prefissi esclusi dallo scanner chiave=valore sul testo libero (troppo ambigui). */
    private static final Set<String> KV_EXCLUDED_PREFIXES = Set.of("NAME", "ADDRESS");

    /** Parole che, nel nome di una chiave segreta, indicano metadati e non il segreto. */
    private static final String[] SAFE_SUBWORDS = {
            "expire", "ttl", "timeout", "lifetime", "maxage", "count", "length", "size", "type",
            "enabled", "required", "policy", "mode", "version", "url", "uri", "endpoint", "path",
            "header", "field", "param", "name", "label", "hint", "strength", "rule", "format",
            "method", "algorithm", "alg", "location", "domain", "secure", "samesite", "httponly",
            "prefix", "changed", "created", "updated", "issued", "reset"};
    private static final Set<String> SAFE_CHECK_TOKENS = Set.of(
            "token", "session", "sessionid", "cookie", "csrf", "xsrf", "jwt", "bearer", "password",
            "passwd", "pwd", "secret", "signature", "credential", "otpcode", "totp", "apikey",
            "authkey", "authtoken", "authorization", "passphrase");

    /** Chiavi identificative: "id", "order_id", "orderId", "user_ref", "X-Request-Id"... */
    private static final Pattern ID_KEY_SEP = Pattern.compile(
            "(?i:(?:^|[_\\-. ])(?:id|ids|ref|refs|reference|rev|uuid|guid))$"
            + "|[a-z0-9](?:Id|Ids|ID|IDs|Ref|Refs|Reference|Uuid|UUID|Guid|GUID)$");
    private static final String[] ID_FREE_SUFFIXES = {
            "uuid", "guid", "hash", "sha", "sha1", "sha256", "sha384", "sha512", "md5", "checksum",
            "digest", "etag", "commit", "revision", "integrity", "traceparent", "tracestate"};

    private static final Set<String> NAME_ATTRS = Set.of("name", "id", "property", "itemprop", "key", "http-equiv");
    private static final Set<String> URL_ATTRS = Set.of(
            "href", "src", "action", "formaction", "poster", "cite", "background", "data-src",
            "data-href", "data-url", "longdesc", "manifest", "codebase", "ping", "xlink:href");
    private static final Set<String> STRUCTURAL_ATTRS = Set.of(
            "name", "id", "class", "type", "for", "style", "rel", "lang", "dir", "role", "method",
            "target", "width", "height", "tabindex", "autocomplete", "charset", "media", "sizes",
            "crossorigin", "integrity", "referrerpolicy", "loading", "align", "valign", "border",
            "colspan", "rowspan", "scope", "enctype", "accept", "maxlength", "minlength", "size",
            "step", "min", "max", "pattern", "required", "disabled", "checked", "selected",
            "readonly", "hidden", "async", "defer", "xmlns", "version", "encoding", "xml:lang",
            "http-equiv", "property", "itemprop", "itemtype", "itemscope", "nonce", "slot", "is",
            "inputmode", "spellcheck", "draggable", "contenteditable", "translate", "decoding",
            "fetchpriority", "as", "shape", "coords", "span", "start", "reversed", "wrap", "rows",
            "cols", "frameborder", "allow", "sandbox", "allowfullscreen", "kind", "srclang", "label");

    public Anonymizer(Config cfg, SubstitutionMap map) {
        this(cfg, map, Overrides.empty());
    }

    public Anonymizer(Config cfg, SubstitutionMap map, Overrides overrides) {
        this.cfg = cfg;
        this.map = map;
        this.ov = overrides != null ? overrides : Overrides.empty();
        map.addExcluded(cfg.keepValues);
        map.setKeepFilter(this::keepReadable);
    }

    /**
     * Cosa resta leggibile anche quando un rilevatore lo vorrebbe nascondere:
     * i payload del tester e i blob serializzati che non contengono dati
     * (l'LLM deve vedere che e' un oggetto Java/.NET/pickle per aiutare).
     */
    private boolean keepReadable(String value, String prefix) {
        if (isAttackPayload(value)) return true;
        // solo i segreti generici: un cookie o un token serializzato resta una credenziale
        return "SECRET".equals(prefix) && isCleanSerializedBlob(value);
    }

    /** Firme dei formati di serializzazione (sui byte decodificati). */
    private static boolean serializedMagic(byte[] b) {
        if (b.length < 4) return false;
        int b0 = b[0] & 0xFF, b1 = b[1] & 0xFF, b2 = b[2] & 0xFF, b3 = b[3] & 0xFF;
        if (b0 == 0xAC && b1 == 0xED && b2 == 0x00 && b3 == 0x05) return true;           // Java
        if (b0 == 0x00 && b1 == 0x01 && b2 == 0x00 && b3 == 0x00 && b.length > 8
                && (b[5] & 0xFF) == 0xFF && (b[6] & 0xFF) == 0xFF) return true;            // .NET BinaryFormatter
        if (b0 == 0x80 && b1 >= 2 && b1 <= 5) return true;                                  // Python pickle
        if (b0 == 0x04 && b1 == 0x08) return true;                                           // Ruby Marshal
        return (b0 == 'O' || b0 == 'a' || b0 == 's') && b1 == ':' && Character.isDigit(b2); // PHP serialize
    }

    /**
     * Blob base64/hex di un oggetto serializzato le cui stringhe interne non
     * contengono nulla di sensibile per le regole attuali: resta leggibile.
     */
    private boolean isCleanSerializedBlob(String v) {
        if (v == null || v.length() < 16 || v.length() > 200_000) return false;
        byte[] raw = null;
        String s = v.trim();
        try {
            if (s.matches("(?i)(?:ac ?ed ?00 ?05)[0-9a-f ]*") && s.replace(" ", "").length() % 2 == 0) {
                String h = s.replace(" ", "");
                raw = new byte[h.length() / 2];
                for (int i = 0; i < raw.length; i++) raw[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
            } else if (s.matches("[A-Za-z0-9+/_-]+={0,2}")) {
                String b64 = s.replace('-', '+').replace('_', '/');
                raw = java.util.Base64.getMimeDecoder().decode(b64);
            }
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (raw == null || !serializedMagic(raw)) return false;
        // stringhe stampabili (come `strings`): e' li' che starebbero email, nomi, host
        StringBuilder strs = new StringBuilder();
        int run = 0, start = 0;
        for (int i = 0; i <= raw.length; i++) {
            int c = i < raw.length ? raw[i] & 0xFF : 0;
            if (c >= 0x20 && c < 0x7F) { if (run++ == 0) start = i; continue; }
            if (run >= 4) strs.append(new String(raw, start, run, StandardCharsets.ISO_8859_1)).append('\n');
            run = 0;
        }
        String text = strs.toString();
        if (text.isEmpty()) return true;
        SubstitutionMap snap = map.snapshot();
        java.util.function.BiPredicate<String, String> keep = keepFilterOff();
        try {
            return scanSecrets(text).equals(text);
        } finally {
            map.restore(snap);
            map.setKeepFilter(keep);
        }
    }

    /** Disattiva il filtro durante una prova (evita la ricorsione) e restituisce quello attivo. */
    private java.util.function.BiPredicate<String, String> keepFilterOff() {
        java.util.function.BiPredicate<String, String> k = this::keepReadable;
        map.setKeepFilter(null);
        return k;
    }

    // ------------------------------------------------------------------ JWT
    /**
     * JWT leggibile per l'analisi (alg:none, kid, jku, ruoli, scadenze) senza
     * che diventi una credenziale: la FIRMA e' sempre sostituita, quindi il token
     * non si puo' riusare. Header e claims restano in chiaro solo se, decodificati,
     * non contengono nulla di sensibile per le regole attuali; altrimenti si
     * nasconde la parte che li contiene. Reversibile come tutto il resto.
     */
    private String maskJwt(String token, String prefix) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !parts[0].startsWith("eyJ")) return map.placeholder(token, prefix);
        String head = decodeJwtPart(parts[0]);
        if (head == null || !jwtJsonIsClean(head)) return map.placeholder(token, prefix);
        String body = decodeJwtPart(parts[1]);
        if (body == null || !jwtJsonIsClean(body)) {
            String ph = map.placeholder(parts[1] + "." + parts[2], "JWT");
            return ph.equals(parts[1] + "." + parts[2]) ? token : parts[0] + "." + ph;
        }
        if (parts[2].isEmpty()) return token;   // alg:none con claims innocui: niente da nascondere
        String sig = map.placeholder(parts[2], "JWT_SIG");
        return parts[0] + "." + parts[1] + "." + sig;
    }

    /**
     * Claim d'identita' (context.jwt_identity_claims: sub, upn, preferred_username...)
     * con un valore che indica una persona: numeri, UUID e utenze generiche (admin,
     * test) non lo sono, "mrossi" si'.
     */
    private boolean hasPersonalClaim(String json) {
        try {
            com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(json);
            if (!el.isJsonObject()) return false;
            for (Map.Entry<String, com.google.gson.JsonElement> e : el.getAsJsonObject().entrySet()) {
                if (!cfg.jwtIdentityClaims.contains(normKey(e.getKey()))) continue;
                com.google.gson.JsonElement v = e.getValue();
                if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString()) continue;
                String s = v.getAsString().trim();
                if (s.isEmpty() || s.chars().allMatch(Character::isDigit) || UUID.matcher(s).matches()) continue;
                if (cfg.commonUsers.contains(s.toLowerCase(Locale.ROOT))) continue;
                return true;
            }
            return false;
        } catch (RuntimeException ex) {
            return true;
        }
    }

    private static String decodeJwtPart(String p) {
        try {
            String s = new String(java.util.Base64.getUrlDecoder().decode(p.replace('+', '-').replace('/', '_')
                    .replace("=", "")), StandardCharsets.UTF_8);
            String t = s.trim();
            return t.startsWith("{") && t.endsWith("}") ? s : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Il JSON decodificato resta identico passando per l'anonimizzazione? (prova senza effetti) */
    private boolean jwtJsonIsClean(String json) {
        if (hasPersonalClaim(json)) return false;
        SubstitutionMap snap = map.snapshot();
        java.util.function.BiPredicate<String, String> keep = keepFilterOff();
        try {
            return rewriteJson(json, 0).equals(json);
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        } finally {
            map.restore(snap);
            map.setKeepFilter(keep);
        }
    }

    /**
     * Valore con sintassi d'attacco (SSTI, SQLi, XSS, CRLF, traversal, JNDI...):
     * e' un payload scritto dal tester, non un dato del cliente, e l'LLM deve
     * poterlo leggere. Marcatori in context.attack_markers.
     */
    public boolean isAttackPayload(String v) {
        if (v == null || v.length() < 3 || v.length() > 8192) return false;
        for (Pattern p : cfg.attackMarkers) if (p.matcher(v).find()) return true;
        return false;
    }

    public SubstitutionMap getMap() { return map; }

    public String anonymizeRequest(String raw) { return anonymizeMessage(raw); }
    public String anonymizeResponse(String raw) { return isTranscript(raw) ? anonymizeTranscript(raw) : anonymizeMessage(raw); }

    /** Body gzip/deflate decompressi finora (la UI lo segnala). */
    private int decompressedBodies;

    public int decompressedBodies() {
        return decompressedBodies;
    }

    /** Decompressione gzip/deflate del body (byte come caratteri 0-255); null se non si puo'. */
    static String inflateBody(String body, String contentEncoding) {
        if (body == null || body.length() < 2 || contentEncoding == null) return null;
        String ce = contentEncoding.trim().toLowerCase(Locale.ROOT);
        boolean gzip = ce.equals("gzip") || ce.equals("x-gzip");
        if (!gzip && !ce.equals("deflate")) return null;
        byte[] raw = new byte[body.length()];
        for (int i = 0; i < raw.length; i++) {
            char c = body.charAt(i);
            if (c > 0xFF) return null; // non sono byte grezzi: niente da decomprimere
            raw[i] = (byte) c;
        }
        try {
            java.io.InputStream in = gzip
                    ? new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(raw))
                    : new java.util.zip.InflaterInputStream(new java.io.ByteArrayInputStream(raw),
                            new java.util.zip.Inflater((raw[0] & 0x0F) != 8)); // deflate grezzo o zlib
            byte[] out;
            try (in) {
                out = in.readNBytes(20_000_000);
            }
            java.nio.charset.CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder();
            try {
                return dec.decode(java.nio.ByteBuffer.wrap(out)).toString();
            } catch (java.nio.charset.CharacterCodingException notUtf8) {
                return new String(out, StandardCharsets.ISO_8859_1);
            }
        } catch (java.io.IOException | RuntimeException e) {
            return null;
        }
    }

    // ------------------------------------------------------------ trascritti
    // Contenuti che passano da Burp ma non sono una coppia request/response:
    // messaggi WebSocket, issue dello Scanner. Il testo e' diviso in blocchi da righe
    // "### ..." (intestazioni, che si scansionano come testo) e ogni blocco si
    // anonimizza secondo il suo contenuto (JSON, Socket.IO, HTML, testo).

    public static final String TRANSCRIPT_HEAD = "### Domi Reversi";
    private static final Pattern TRANSCRIPT_LINE = Pattern.compile("(?m)^### [^\\r\\n]*");
    private static final Pattern SOCKETIO_PREFIX = Pattern.compile("^(\\s*\\d{1,3}(?:/[\\w./-]{0,100},)?\\d{0,10})(?=[\\[{])");

    public static boolean isTranscript(String s) {
        return s != null && s.startsWith(TRANSCRIPT_HEAD);
    }

    public String anonymizeTranscript(String text) {
        if (text == null) return "";
        reserveLiterals(text);
        try {
            StringBuilder out = new StringBuilder(text.length() + 64);
            Matcher m = TRANSCRIPT_LINE.matcher(text);
            int last = 0;
            while (m.find()) {
                out.append(anonTranscriptBlock(text.substring(last, m.start())));
                out.append(scanSecrets(m.group()));
                last = m.end();
            }
            out.append(anonTranscriptBlock(text.substring(last)));
            return contextPass(applyForced(out.toString()));
        } catch (Throwable t) {
            try {
                return contextPass(applyForced(scanSecrets(text)));
            } catch (Throwable t2) {
                return "[Domi Reversi] Impossibile anonimizzare questo contenuto in modo sicuro.";
            }
        }
    }

    /** Un blocco: a capo iniziali e finali restano, il contenuto si anonimizza per tipo. */
    private String anonTranscriptBlock(String block) {
        if (block.trim().isEmpty()) return block;
        int s = 0, e = block.length();
        while (s < e && (block.charAt(s) == '\n' || block.charAt(s) == '\r')) s++;
        while (e > s && (block.charAt(e - 1) == '\n' || block.charAt(e - 1) == '\r')) e--;
        String body = block.substring(s, e);
        String prefix = "";
        Matcher sio = SOCKETIO_PREFIX.matcher(body);
        if (sio.find()) {                       // Socket.IO: 42["evento",{...}]
            prefix = sio.group(1);
            body = body.substring(prefix.length());
        }
        String trimmed = body.trim();
        String ct = trimmed.startsWith("{") || trimmed.startsWith("[") ? "application/json"
                : trimmed.startsWith("<") ? "text/html" : "";
        return block.substring(0, s) + prefix + anonymizeBody(body, ct) + block.substring(e);
    }

    private static final Pattern LITERAL_PLACEHOLDER = Pattern.compile(
            "(?<![A-Za-z0-9_])[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\\d{1,9}(?![A-Za-z0-9_])");

    /**
     * Riserva i testi gia' presenti nei messaggi che hanno la forma di un
     * placeholder (es. un valore letterale "EMAIL_1"): non verranno mai generati,
     * quindi restano distinguibili e la decodifica non li tocca. Per una sessione
     * request + response chiamarlo su entrambi PRIMA di anonimizzare.
     */
    public void reserveLiterals(String... texts) {
        if (texts == null) return;
        for (String t : texts) {
            if (t == null || t.isEmpty()) continue;
            Matcher m = LITERAL_PLACEHOLDER.matcher(t);
            while (m.find()) map.reserve(m.group());

            // anche la forma con l'underscore escapato da markdown ("EMAIL\_1"), che la
            // de-anonimizzazione accetta: un letterale cosi' non deve collidere
            if (t.indexOf("\\_") >= 0) {
                Matcher e = LITERAL_ESCAPED.matcher(t);
                while (e.find()) map.reserve(e.group().replace("\\_", "_"));
            }
        }
    }

    private static final Pattern LITERAL_ESCAPED = Pattern.compile(
            "(?<![A-Za-z0-9_\\\\])[A-Z][A-Z0-9]{0,40}(?:\\\\?_[A-Z][A-Z0-9]{0,40}){0,8}\\\\?_\\d{1,9}(?![A-Za-z0-9_])");

    private String anonymizeMessage(String raw) {
        if (raw == null) return "";
        reserveLiterals(raw);
        try {
            return contextPass(applyForced(anonymizeStructured(raw)));
        } catch (Throwable t) {
            try {
                return contextPass(applyForced(scanSecrets(raw)));
            } catch (Throwable t2) {
                // mai restituire il contenuto originale se non si e' riusciti a ripulirlo
                return "[Domi Reversi] Impossibile anonimizzare questo contenuto in modo sicuro.";
            }
        }
    }

    private String anonymizeStructured(String raw) {
        HttpMessage msg = HttpMessage.parse(raw);
        if (msg.isEmpty) return "";
        msg.startLine = anonStartLine(msg.startLine);
        String fullCt = msg.get("Content-Type");
        if (fullCt == null) fullCt = msg.contentType();
        String te = msg.get("Transfer-Encoding");
        boolean chunked = te != null && te.toLowerCase(Locale.ROOT).contains("chunked");

        String body = msg.body;
        Chunked framing = chunked ? Chunked.parse(body) : null;
        String dechunked = framing != null ? framing.data() : (chunked ? dechunk(body) : null);
        if (dechunked != null) body = dechunked;
        String prevName = null;
        for (HttpMessage.Header h : msg.headers) {
            if (h.name.isEmpty() && prevName != null && !h.value.isEmpty()
                    && (h.value.charAt(0) == ' ' || h.value.charAt(0) == '\t')) {
                // continuazione (obs-fold) dell'header precedente: stessa strategia,
                // altrimenti la seconda riga di un token resterebbe in chiaro
                String inner = h.value.trim();
                if (!inner.isEmpty()) {
                    int lead = h.value.indexOf(inner);
                    String[] nv = anonHeader(prevName, inner);
                    h.value = h.value.substring(0, lead) + nv[1] + h.value.substring(lead + inner.length());
                }
                continue;
            }
            String origName = h.name;
            String[] nv = anonHeader(h.name, h.value);
            h.name = nv[0];
            h.value = nv[1];
            prevName = origName.isEmpty() ? null : origName;
        }
        String inflated = inflateBody(body, msg.get("Content-Encoding"));
        if (inflated != null) {
            // body gzip/deflate: si mostra decompresso e anonimizzato. L'LLM deve leggere il
            // contenuto; la ricostruzione restituisce il testo, non i byte compressi.
            decompressedBodies++;
            msg.body = anonymizeBody(inflated, fullCt);
            return msg.serialize();
        }
        String anonBody = anonymizeBody(body, fullCt);
        // Content-Length resta quello originale: il messaggio anonimizzato deve
        // tornare identico byte per byte con la de-anonimizzazione.
        if (framing != null) anonBody = reframe(framing, anonBody, fullCt, msg.newline);
        else if (dechunked != null) anonBody = rechunk(anonBody, msg.newline);
        msg.body = anonBody;
        return msg.serialize();
    }

    /** Ultima passata: sostituisce le stringhe scelte a mano dall'utente
     *  (selezione + "Anonimizza") con CUSTOM_n, in TUTTE le occorrenze e
     *  ignorando maiuscole/minuscole. */
    private String applyForced(String text) {
        if (ov.forceValues.isEmpty() || text == null || text.isEmpty()) return text;
        List<String> vals = new ArrayList<>(ov.forceValues);
        vals.sort((a, b) -> Integer.compare(b.length(), a.length()));
        for (String v : vals) {
            if (v == null || v.isEmpty()) continue;
            Pattern p = Pattern.compile(Pattern.quote(v), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
            if (!p.matcher(text).find()) continue;
            String ph = map.placeholder(v, "CUSTOM");
            if (ph.equals(v)) continue; // escluso dall'utente
            text = p.matcher(text).replaceAll(Matcher.quoteReplacement(ph));
        }
        return text;
    }

    // -------------------------------------------------------------- start line
    private String anonStartLine(String line) {
        if (line == null || line.isEmpty()) return line;
        if (line.regionMatches(true, 0, "HTTP/", 0, 5)) return line; // status line
        String[] parts = line.split(" ", -1);
        if (parts.length >= 2) {
            parts[1] = scanUrlValue(parts[1]);
            return String.join(" ", parts);
        }
        return scanSecrets(line);
    }

    // -------------------------------------------------------------------- header
    private String[] anonHeader(String name, String value) {
        String low = name.toLowerCase(Locale.ROOT);
        if (ov.excludeHeaders.contains(low)) {
            return new String[]{name, value};
        }
        if (low.equals("host") || low.equals(":authority")) {
            // il dominio di destinazione identifica il cliente: il suo nome base
            // ("acme-corp") va nascosto anche fuori dagli host (path, header, testo)
            map.addOrgTerm(orgLabel(value));
        }
        if (ov.extraHeaders.contains(low) && !value.trim().isEmpty()) { // scelta esplicita dell'utente
            return new String[]{name, map.placeholder(value.trim(), "CUSTOM")};
        }
        if (!name.isEmpty() && isPreservedKey(name)) {
            return new String[]{name, value};
        }
        String strategy = cfg.headerStrategy.get(low);
        if ("user_agent".equals(strategy) && !cfg.anonymizeUserAgent) {
            return new String[]{name, keepHeaderValue(value)};
        }
        if (strategy != null) {
            return new String[]{name, applyHeaderStrategy(strategy, value)};
        }
        if (ov.extraHeaders.contains(low) && !value.trim().isEmpty()) {
            return new String[]{name, map.placeholder(value.trim(), "CUSTOM")};
        }
        if (name.isEmpty()) {
            return new String[]{name, scanSecrets(value)};
        }
        if (cfg.keepHeaders.contains(low)) {
            return new String[]{name, keepHeaderValue(value)};
        }
        String byName = sensitiveKeyPrefix(name);
        if (byName != null && !value.trim().isEmpty()) {
            return new String[]{name, stratAuthToken(value, byName)};
        }
        if (isIdKey(name)) {
            // X-Request-Id, X-Correlation-Id, traceparent...: utili per il debugging
            return new String[]{name, strictId(name, value.trim())
                    ? placeholderTrim(value, "ID") : keepHeaderValue(value)};
        }
        return new String[]{name, scanSecrets(value)};
    }

    private String keepHeaderValue(String value) {
        return replaceHostTokens(replaceUrlHosts(value), false, false);
    }

    private String applyHeaderStrategy(String strategy, String value) {
        try {
            switch (strategy) {
                case "host": return anonHostValue(value);
                case "ip": return stratIp(value);
                case "host_scan": return stratHostScan(value);
                case "auth_token": return stratAuthToken(value, "AUTH_TOKEN");
                case "apikey": return placeholderTrim(value, "APIKEY");
                case "token": return stratAuthToken(value, "TOKEN");
                case "cookie": return stratCookie(value);
                case "set_cookie": return stratSetCookie(value);
                case "referer_origin":
                case "location": return scanUrlValue(value);
                case "auth_challenge": return stratAuthChallenge(value);
                case "redact": return value.trim().isEmpty() ? value
                        : map.placeholder(value.trim(), "REDACTED"); // numerato: reversibile
                case "user_agent": return placeholderTrim(value, "USER_AGENT");
                default: return scanSecrets(value);
            }
        } catch (Exception e) {
            return scanSecrets(value);
        }
    }

    private String placeholderTrim(String value, String prefix) {
        return value.trim().isEmpty() ? value : map.placeholder(value.trim(), prefix);
    }

    private String stratIp(String value) {
        value = applyPatterns(value, false);
        value = replaceUrlHosts(value);
        value = replaceHostTokens(value, true, false);
        return value;
    }

    private String stratHostScan(String value) {
        value = replaceUrlHosts(value);
        value = replaceHostTokens(value, true, false);
        return value;
    }

    private String stratAuthToken(String value, String prefix) {
        String v = value.trim();
        if (v.isEmpty()) return value;
        Matcher m = AUTH_SCHEME.matcher(v);
        if (m.matches()) {
            String tok = m.group(2).trim();
            return m.group(1) + " " + (JWT_SHAPE.matcher(tok).matches() ? maskJwt(tok, prefix) : map.placeholder(tok, prefix));
        }
        return JWT_SHAPE.matcher(v).matches() ? maskJwt(v, prefix) : map.placeholder(v, prefix);
    }

    private boolean isSessionCookie(String name) {
        String n = name.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        return SESSION_COOKIES.contains(n);
    }

    /** Valori di cookie innocui (preferenze) restano leggibili. */
    private boolean harmlessCookie(String name, String value) {
        if (isSessionCookie(name) || sensitiveKeyPrefix(name) != null) return false;
        String v = value.trim();
        return v.matches("[A-Za-z]{1,12}") || v.matches("\\d{1,3}")
                || v.equalsIgnoreCase("true") || v.equalsIgnoreCase("false");
    }

    private String cookiePair(String k, String v) {
        String kname = k.trim();
        String lead = k.substring(0, k.length() - stripLeading(k).length());
        if (v.trim().isEmpty() || harmlessCookie(kname, v)) return lead + kname + "=" + v;
        String prefix = isSessionCookie(kname) ? "SESSION" : "COOKIE";
        String byName = sensitiveKeyPrefix(kname);
        if (byName != null && !prefix.equals("SESSION")) prefix = byName;
        String tv = v.trim();
        return lead + kname + "=" + (JWT_SHAPE.matcher(tv).matches() ? maskJwt(tv, prefix) : map.placeholder(tv, prefix));
    }

    private static final Pattern JWT_SHAPE = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");

    private String stratCookie(String value) {
        String[] parts = value.split(";", -1);
        List<String> out = new ArrayList<>();
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq >= 0) {
                out.add(cookiePair(part.substring(0, eq), part.substring(eq + 1)));
            } else if (!part.trim().isEmpty()) {
                String lead = part.substring(0, part.length() - stripLeading(part).length());
                out.add(lead + map.placeholder(part.trim(), "COOKIE"));
            } else {
                out.add(part);
            }
        }
        return String.join(";", out);
    }

    private String stratSetCookie(String value) {
        String[] segs = value.split(";", -1);
        if (segs.length == 0) return value;
        List<String> out = new ArrayList<>();
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            int eq = seg.indexOf('=');
            if (i == 0 && eq >= 0) {
                out.add(cookiePair(seg.substring(0, eq), seg.substring(eq + 1)).trim());
            } else if (eq >= 0 && seg.substring(0, eq).trim().equalsIgnoreCase("domain")) {
                String d = seg.substring(eq + 1).trim();
                String dot = d.startsWith(".") ? "." : "";
                out.add(seg.substring(0, eq) + "=" + dot + anonHostValue(d.substring(dot.length())));
            } else if (eq >= 0 && seg.substring(0, eq).trim().equalsIgnoreCase("path")) {
                out.add(seg.substring(0, eq) + "=" + applyPatterns(seg.substring(eq + 1), false));
            } else {
                out.add(seg);
            }
        }
        return String.join(";", out);
    }

    private static final Pattern QUOTED_VALUE = Pattern.compile("\"([^\"]{0,4096})\"");

    private String stratAuthChallenge(String value) {
        // realm="ACME Intranet", nonce="...": ogni valore tra virgolette diventa
        // REDACTED_n (numerato, quindi reversibile come gli altri segnaposto)
        String redacted = regexReplace(value, QUOTED_VALUE, m -> m.group(1).isEmpty() ? m.group()
                : "\"" + map.placeholder(m.group(1), "REDACTED") + "\"");
        return applyPatterns(redacted, false);
    }

    // ------------------------------------------------------------ host helpers
    private static String stripLeading(String s) {
        int i = 0;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return s.substring(i);
    }

    private static boolean isIp(String host) {
        String h = host.replace("[", "").replace("]", "");
        if (IPV4.matcher(h).matches()) {
            for (String p : h.split("\\.")) {
                try { if (Integer.parseInt(p) > 255) return false; } catch (Exception e) { return false; }
            }
            return true;
        }
        return h.matches("[0-9A-Fa-f:.]+") && countChar(h, ':') >= 2;
    }

    private static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    private String anonHostValue(String value) {
        value = value.trim();
        if (value.isEmpty() || map.looksLikePlaceholder(value)) return value;
        String host = value;
        String port = "";
        boolean hasPort = false;
        if (value.startsWith("[")) {
            int close = value.indexOf(']');
            if (close > 0) {
                host = value.substring(0, close + 1);
                String rest = value.substring(close + 1);
                if (rest.startsWith(":") && rest.length() > 1) { port = rest.substring(1); hasPort = true; }
            }
        } else if (countChar(value, ':') == 1) {
            int c = value.indexOf(':');
            host = value.substring(0, c);
            port = value.substring(c + 1);
            hasPort = true;
        }
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || map.looksLikePlaceholder(host)) return value;
        if (PUBLIC_STANDARD_DOMAINS.contains(host.toLowerCase(Locale.ROOT))) return value;
        String bare = host.replace("[", "").replace("]", "");
        String prefix = isIp(bare) ? "IP" : "HOST";
        String ph = map.placeholder((prefix.equals("IP") ? bare : host).toLowerCase(Locale.ROOT), prefix);
        if (host.startsWith("[")) ph = "[" + ph + "]";
        return hasPort && !port.isEmpty() ? ph + ":" + port : ph;
    }

    private static boolean isHostChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '.' || c == '-' || c == '_';
    }

    /** Domini pubblici di standard/namespace: anonimizzarli toglie solo contesto. */
    private static final Set<String> PUBLIC_STANDARD_DOMAINS = Set.of(
            "www.w3.org", "w3.org", "schemas.xmlsoap.org", "xmlsoap.org", "schemas.microsoft.com",
            "schemas.openxmlformats.org", "purl.org", "json-schema.org", "schema.org", "ns.adobe.com",
            "docs.oasis-open.org", "www.springframework.org", "java.sun.com", "xmlns.jcp.org",
            "maven.apache.org", "www.wapforum.org", "ogp.me");

    /** Prime etichette tipiche di espressioni JavaScript (window.App, user.name...). */
    private static final Set<String> CODE_IDENTS = Set.of(
            "window", "document", "this", "self", "user", "data", "res", "req", "config", "options",
            "opts", "props", "state", "item", "el", "obj", "module", "exports", "process", "console",
            "error", "err", "event", "evt", "response", "request", "result", "value", "node",
            "element", "ctx", "context", "params", "args", "settings", "model", "view", "page",
            "form", "input", "target", "app", "file", "files", "img", "image", "math", "json",
            "object", "array", "string", "number", "location", "navigator", "history", "global",
            "globalthis", "e", "t", "n", "r", "i", "o", "a", "s", "u", "c", "l", "d", "f", "p", "m");

    /** Nome a dominio plausibile (almeno due etichette, TLD alfabetico). */
    private static boolean isDomain(String tok, boolean strict) {
        if (tok.length() < 4 || tok.length() > 253 || tok.indexOf('_') >= 0) return false;
        int dot = tok.lastIndexOf('.');
        if (dot <= 0) return false;
        String tld = tok.substring(dot + 1);
        if (tld.length() < 2 || tld.length() > 24) return false;
        for (int i = 0; i < tld.length(); i++) if (!Character.isLetter(tld.charAt(i))) return false;
        if (strict) {
            if (!ALLOWED_TLDS.contains(tld.toLowerCase(Locale.ROOT))) return false;
            // codice, non domini: window.App, myApp.config, user.name
            boolean tldAllUpper = tld.equals(tld.toUpperCase(Locale.ROOT));
            if (!tldAllUpper && Character.isUpperCase(tld.charAt(0))) return false;
            for (int i = 1; i < tok.length(); i++) {
                if (Character.isUpperCase(tok.charAt(i)) && Character.isLowerCase(tok.charAt(i - 1))) return false;
            }
            int firstDot = tok.indexOf('.');
            if (firstDot == dot && CODE_IDENTS.contains(tok.substring(0, firstDot).toLowerCase(Locale.ROOT))) {
                return false;
            }
        }
        int start = 0;
        while (start <= tok.length()) {
            int end = tok.indexOf('.', start);
            if (end < 0) end = tok.length();
            int len = end - start;
            if (len < 1 || len > 63) return false;
            if (tok.charAt(start) == '-' || tok.charAt(end - 1) == '-') return false;
            start = end + 1;
        }
        return true;
    }

    /**
     * Sostituisce in un solo passaggio lineare gli host/IP gia' noti e, se
     * richiesto, i domini "nudi" (strict = solo TLD in elenco).
     */
    private String replaceHostTokens(String text, boolean bare, boolean strict) {
        if (text == null || text.isEmpty()) return text;
        Map<String, String> idx = map.hostIndex();
        if (idx.isEmpty() && !bare) return text;
        StringBuilder out = null;
        int n = text.length(), i = 0, last = 0;
        while (i < n) {
            if (!isHostChar(text.charAt(i))) { i++; continue; }
            int s = i;
            while (i < n && isHostChar(text.charAt(i))) i++;
            int ts = s, te = i;
            while (ts < te && text.charAt(ts) == '.') ts++;
            while (te > ts && text.charAt(te - 1) == '.') te--;
            if (te - ts < 2) continue;
            String tok = text.substring(ts, te);
            String repl = idx.get(tok.toLowerCase(Locale.ROOT));
            if (repl == null && bare && (s == 0 || text.charAt(s - 1) != '@')
                    && isDomain(tok, strict) && !map.looksLikePlaceholder(tok)) {
                repl = anonHostValue(tok);
            }
            if (repl != null && !repl.equals(tok)) {
                if (out == null) out = new StringBuilder(n + 16);
                out.append(text, last, ts).append(repl);
                last = te;
            }
        }
        if (out == null) return text;
        out.append(text, last, n);
        return out.toString();
    }

    private String anonQuery(String query) {
        if (query == null || query.isEmpty()) return query;
        String[] pairs = query.split("&", -1);
        List<String> out = new ArrayList<>();
        for (String p : pairs) {
            int eq = p.indexOf('=');
            if (eq >= 0) {
                String k = p.substring(0, eq);
                String v = p.substring(eq + 1);
                String dec = urlDecode(v);
                String dk = urlDecode(k);
                if (isPreservedKey(dk)) { out.add(p); continue; }
                String prefix = queryKeyPrefix(dk);
                if (prefix != null && !dec.isEmpty() && !skipValue(dec)) {
                    out.add(k + "=" + keyedToken(dec, v, prefix));
                } else if (strictId(dk, dec)) {
                    out.add(k + "=" + keyedToken(dec, v, "ID"));
                } else {
                    out.add(k + "=" + encodedScan(v, s -> scanValue(s, dk, 0)));
                }
            } else {
                out.add(encodedScan(p, s -> applyPatterns(s, false)));
            }
        }
        return String.join("&", out);
    }

    /** Valore mascherato per nome di chiave: variante esatta se era percent-encoded. */
    private String keyedToken(String dec, String raw, String prefix) {
        String token = map.placeholder(dec, prefix);
        if (token.equals(dec)) return raw;
        return raw.equals(dec) ? token : map.variant(token, raw, "URL");
    }

    /** Scansione di un valore percent-encoded che conserva la codifica originale. */
    private String encodedScan(String raw, java.util.function.UnaryOperator<String> scanner) {
        if (raw.indexOf('%') < 0 && raw.indexOf('+') < 0) return scanner.apply(raw);
        String spliced = spliceScan(raw, urlDecodeMapped(raw), scanner, "URL");
        if (spliced != null) return spliced;
        String dec = urlDecode(raw);
        String scanned = scanner.apply(dec);
        return scanned.equals(dec) ? raw : urlEncode(scanned);
    }

    /** Valori che non ha senso mascherare (letterali vuoti/booleani). */
    private static boolean skipValue(String v) {
        String t = v.trim();
        if (t.isEmpty()) return true;
        switch (t.toLowerCase(Locale.ROOT)) {
            case "true": case "false": case "null": case "undefined": case "none": case "nil":
                return true;
            default:
                return false;
        }
    }

    private String replaceUrlHosts(String text) {
        if (text == null || text.indexOf("://") < 0) return text;
        Matcher m = URL_RE.matcher(text);
        StringBuilder sb = new StringBuilder();
        boolean changed = false;
        while (m.find()) {
            String url = m.group(0);
            String trail = "";
            int e = url.length();
            while (e > 0 && ".,;:!?".indexOf(url.charAt(e - 1)) >= 0) e--;
            if (e < url.length()) { trail = url.substring(e); url = url.substring(0, e); }
            String repl;
            try {
                repl = anonUrl(url) + trail;
            } catch (Exception ex) {
                repl = url + trail;
            }
            if (!repl.equals(m.group(0))) changed = true;
            m.appendReplacement(sb, Matcher.quoteReplacement(repl));
        }
        if (!changed) return text;
        m.appendTail(sb);
        return sb.toString();
    }

    private String anonUrl(String url) {
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) return url;
        String scheme = url.substring(0, schemeEnd);
        String rest = url.substring(schemeEnd + 3);
        int cut = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?' || c == '#') { cut = i; break; }
        }
        String netloc = rest.substring(0, cut);
        String tail = rest.substring(cut);
        String userinfo = "";
        int at = netloc.lastIndexOf('@');
        if (at >= 0) {
            String ui = netloc.substring(0, at);
            userinfo = (ui.isEmpty() ? "" : map.placeholder(ui, "AUTH_TOKEN")) + "@";
            netloc = netloc.substring(at + 1);
        }
        StringBuilder hosts = new StringBuilder();
        String[] hs = netloc.split(",", -1);
        for (int i = 0; i < hs.length; i++) {
            if (i > 0) hosts.append(',');
            hosts.append(hs[i].isEmpty() ? hs[i] : anonHostValue(hs[i]));
        }
        String path = tail, query = "", frag = "";
        int hash = path.indexOf('#');
        if (hash >= 0) { frag = path.substring(hash); path = path.substring(0, hash); }
        int qm = path.indexOf('?');
        if (qm >= 0) { query = path.substring(qm + 1); path = path.substring(0, qm); }
        if (frag.length() > 1 && frag.indexOf('=') > 0) frag = "#" + anonQuery(frag.substring(1));
        return scheme + "://" + userinfo + hosts + path + (qm >= 0 ? "?" + anonQuery(query) : "") + frag;
    }

    /** Valore che e' (o contiene) un URL, anche relativo: host, query, frammento, pattern. */
    private String scanUrlValue(String v) {
        if (v == null || v.isEmpty()) return v;
        String lv = v.trim().toLowerCase(Locale.ROOT);
        if (lv.startsWith("data:image/") || lv.startsWith("data:font/")) return v; // risorsa incorporata
        String t = replaceUrlHosts(v);
        if (!URL_RE.matcher(v).find()) {
            String frag = "";
            int hash = t.indexOf('#');
            if (hash >= 0) { frag = t.substring(hash); t = t.substring(0, hash); }
            int q = t.indexOf('?');
            if (q >= 0) t = t.substring(0, q) + "?" + anonQuery(t.substring(q + 1));
            if (frag.length() > 1 && frag.indexOf('=') > 0) frag = "#" + anonQuery(frag.substring(1));
            t = t + frag;
        }
        t = applyPatterns(t, false);
        t = replaceHostTokens(t, true, true);
        return t;
    }

    // ---------------------------------------------------------------- body
    public String anonymizeBody(String body, String contentType) {
        if (body == null || body.isEmpty()) return body;
        try {
            String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);

            String bin = anonBinaryFormat(body, ct);
            if (bin != null) return bin;
            String u16 = anonUtf16Body(body, contentType);
            if (u16 != null) return u16;
            String trimmedStart = body.stripLeading();
            if (ct.contains("vcard") || ct.contains("calendar") || trimmedStart.startsWith("BEGIN:VCARD")
                    || trimmedStart.startsWith("BEGIN:VCALENDAR")) {
                return scanSecrets(anonDirectoryText(body));
            }
            if (body.contains("<methodCall") || body.contains("<methodResponse")) {
                List<String> saved = new ArrayList<>();
                String x = protectAll(anonXmlRpc(body), XR_NAME_TAG, saved);  // <name>password</name> e' un nome di campo
                return restore(anonHtml(x), saved);
            }
            if (ct.contains("csv") || ct.contains("tab-separated")) {
                String r = anonDelimited(body);
                if (r != null) return r;
            }

            if (ct.contains("multipart/")) {
                String boundary = extractBoundary(contentType);
                if (boundary == null) boundary = detectBoundaryFromBody(body);
                if (boundary != null) {
                    String r = anonMultipartBody(body, boundary);
                    if (r != null) return r;
                }
            }

            String stripped = body.stripLeading();
            char first = stripped.isEmpty() ? '\0' : stripped.charAt(0);

            if (ct.contains("graphql") && first != '{' && first != '[') {
                return anonGraphqlDoc(body);
            }
            if (ct.contains("json") || ((first == '{' || first == '[') && looksLikeJsonDoc(stripped))) {
                // introspezione GraphQL: "name" e' il nome di un tipo o di un campo, non di una persona
                boolean prev = introspection;
                introspection = prev || body.contains("\"__schema\"") || body.contains("\"__type\"");
                try {
                    return rewriteJson(body, 0);
                } finally {
                    introspection = prev;
                }
            }
            boolean isForm = ct.contains("x-www-form-urlencoded")
                    || (ct.isEmpty() && body.length() < 100_000
                        && body.trim().matches("[^\\s=&]+=[^&\\s]*(?:&[^\\s=&]+=[^&\\s]*)*"));
            if (isForm) {
                String r = anonFormBody(body);
                if (r != null) return r;
            }
            if (ct.contains("html") || ct.contains("xml") || ct.contains("svg") || first == '<') {
                return anonHtml(body);
            }
            if (looksBinary(body)) return scanSecrets(anonBinaryRuns(body));
            return scanSecrets(body);
        } catch (StackOverflowError | RuntimeException e) {
            return scanSecrets(body);
        }
    }

    // ------------------------------------------------- formati binari decodificati
    /** Body binari decodificati (protobuf, gRPC, MessagePack): la UI lo segnala. */
    private int decodedBodies;

    public int decodedBodies() {
        return decodedBodies;
    }

    /**
     * gRPC / gRPC-web / gRPC-web-text / protobuf / MessagePack: decodificati senza
     * schema in testo leggibile e anonimizzati. Null se il tipo non c'entra o se i
     * byte non si decodificano (si passa alla scansione generica).
     */
    private String anonBinaryFormat(String body, String ct) {
        boolean grpcText = ct.contains("grpc-web-text");
        boolean grpc = !grpcText && ct.contains("grpc");
        boolean proto = ct.contains("protobuf") || ct.contains("x-proto");
        boolean msgpack = ct.contains("msgpack");
        if (!grpcText && !grpc && !proto && !msgpack) return null;
        byte[] data;
        if (grpcText) {
            data = decodeGrpcWebText(body);
        } else {
            data = BinaryFormats.latin1(body);
        }
        if (data == null || data.length == 0) return null;
        String out;
        String label;
        if (msgpack) {
            String json = BinaryFormats.msgpackJson(data);
            if (json == null) return null;
            StringBuilder sb = new StringBuilder();
            for (String line : json.split("\n", -1)) sb.append(rewriteJson(line, 0)).append('\n');
            out = sb.toString();
            label = "MessagePack";
        } else if (grpc || grpcText) {
            out = BinaryFormats.grpcText(data, this::anonProtoString, this::scanSecrets);
            if (out == null) out = BinaryFormats.protobufText(data, this::anonProtoString); // senza frame
            label = grpcText ? "gRPC-web-text" : "gRPC";
        } else {
            out = BinaryFormats.protobufText(data, this::anonProtoString);
            label = "protobuf";
        }
        if (out == null) return null;
        decodedBodies++;
        // l'LLM legge la struttura; la ricostruzione restituisce questo testo, non i byte
        return "### Domi Reversi · " + label + (msgpack ? " decodificato in JSON" : " decodificato senza schema (numero di campo: valore)")
                + "\n" + out;
    }

    /** gRPC-web-text: frame in base64, anche piu' blocchi base64 concatenati (ognuno col suo padding). */
    private static byte[] decodeGrpcWebText(String body) {
        String s = body.replaceAll("\\s", "");
        if (s.isEmpty() || !s.matches("[A-Za-z0-9+/=]+")) return null;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        Matcher m = Pattern.compile("[A-Za-z0-9+/]+={0,2}").matcher(s);
        try {
            while (m.find()) out.write(java.util.Base64.getDecoder().decode(m.group()));
        } catch (IllegalArgumentException | java.io.IOException e) {
            return null;
        }
        return out.toByteArray();
    }

    /** Stringa dentro un messaggio protobuf: chiave precedente (map/Struct), regole, forma da segreto o da nome. */
    private String anonProtoString(String prevKey, String value) {
        if (value.isEmpty() || map.looksLikePlaceholder(value)) return value;
        if (looksLikeKeyName(prevKey)) {
            String kp = sensitiveKeyPrefix(prevKey);
            if (kp != null && !skipValue(value)) return map.placeholder(value, kp);
        }
        String s = scanValue(value, null, 0);
        if (!s.equals(value)) return s;
        return secretOrNameShaped(value);
    }

    private static final Pattern KEY_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]{0,63}");

    /** Un nome di campo vero (password, user_email, spring.datasource.password), non un valore. */
    private static boolean looksLikeKeyName(String k) {
        if (k == null || !KEY_NAME.matcher(k).matches()) return false;
        return k.chars().filter(Character::isDigit).count() <= 2; // "Pb0Pwd2024" e' un valore, non un campo
    }

    /** Senza nomi di campo: una stringa con la forma di una password o di un nome e cognome. */
    private String secretOrNameShaped(String v) {
        if (looksSecretShaped(v)) return map.placeholder(v, "SECRET");
        if (TWO_WORD_NAME.matcher(v).matches() && plausiblePersonName(v)) return map.placeholder(v, "NAME");
        return v;
    }

    private static final Pattern TWO_WORD_NAME = Pattern.compile("\\p{Lu}\\p{Ll}{1,30}(?: \\p{Lu}\\p{Ll}{1,30}){1,2}");

    private boolean looksSecretShaped(String v) {
        if (v.length() < 8 || v.length() > 256 || v.indexOf(' ') >= 0) return false;
        if (v.contains("://") || v.startsWith("/") || v.matches("[\\w.-]+\\.(?:png|jpe?g|gif|svg|js|css|html?|json|xml|pdf)")) return false;
        if (VERSIONISH.matcher(v).matches()) return false;
        return charClasses(v) >= 3;
    }

    // --- binari generici con nomi di campo (BSON, AMF, Hessian, WCF msbin1, Thrift...) ---
    /** Abbastanza caratteri di controllo da non essere testo. */
    static boolean looksBinary(String s) {
        int ctl = 0, n = Math.min(s.length(), 65_536);
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || (c >= 0x7F && c <= 0x9F)) ctl++;
        }
        return ctl >= 3 && ctl * 100 >= n;
    }

    /**
     * Sequenze stampabili di un body binario, nell'ordine: se una e' il nome di un
     * campo sensibile (password, email...) la successiva e' il suo valore; altrimenti
     * si nasconde cio' che ha la forma di un segreto. Sostituzione sul posto: la
     * de-anonimizzazione restituisce gli stessi byte.
     */
    private String anonBinaryRuns(String body) {
        StringBuilder out = new StringBuilder(body.length());
        String prevRun = null;
        int i = 0, n = body.length();
        while (i < n) {
            char c = body.charAt(i);
            if (c < 0x20 || c > 0x7E) { out.append(c); i++; continue; }
            int s = i;
            while (i < n && body.charAt(i) >= 0x20 && body.charAt(i) <= 0x7E) i++;
            String run = body.substring(s, i);
            String repl = run;
            if (run.length() >= 3 && !map.looksLikePlaceholder(run)) {
                String kp = looksLikeKeyName(prevRun == null ? null : prevRun.trim()) ? sensitiveKeyPrefix(prevRun.trim()) : null;
                if (kp != null && !skipValue(run)) repl = map.placeholder(run, kp);
                else repl = secretOrNameShaped(run);
            }
            out.append(repl);
            prevRun = run;
        }
        return out.toString();
    }

    // ------------------------------------------------------------ XML-RPC
    // I parametri sono posizionali e senza nome: wp.getUsers(blog_id, username, password).
    // Le posizioni delle credenziali per metodo stanno in context.xmlrpc_credentials;
    // i membri di <struct> si trattano per nome come le chiavi JSON.

    private static final Pattern XR_NAME_TAG = Pattern.compile("<name>[^<]{0,200}</name>|<methodName>[^<]{0,200}</methodName>");
    private static final Pattern XR_METHOD = Pattern.compile("<methodName>\\s*([^<\\s]{1,200})\\s*</methodName>");
    private static final Pattern XR_PARAM_VALUE = Pattern.compile(
            "<param>\\s*<value>\\s*(?:<(\\w{1,20})>([^<]{0,4096})</\\1>|([^<]{0,4096}))\\s*</value>\\s*</param>");
    private static final Pattern XR_MEMBER = Pattern.compile(
            "(<member>\\s*<name>\\s*([^<]{1,200}?)\\s*</name>\\s*<value>\\s*(?:<string>)?)([^<]{1,4096})(?=(?:</string>)?\\s*</value>)");
    private static final Pattern XR_MULTICALL = Pattern.compile(
            "<name>\\s*methodName\\s*</name>\\s*<value>\\s*(?:<string>)?([^<]{1,200})(?:</string>)?\\s*</value>\\s*</member>\\s*<member>\\s*<name>\\s*params\\s*</name>\\s*<value>\\s*<array>\\s*<data>(.*?)</data>",
            Pattern.DOTALL);
    private static final Pattern XR_DATA_VALUE = Pattern.compile("<value>\\s*(?:<(\\w{1,20})>([^<]{0,4096})</\\1>|([^<]{0,4096}))\\s*</value>");

    private String anonXmlRpc(String body) {
        // membri di struct per nome
        body = regexReplace(body, XR_MEMBER, m -> {
            String prefix = sensitiveKeyPrefix(m.group(2));
            String v = m.group(3);
            if (prefix == null || v.trim().isEmpty() || skipValue(v.trim())) return m.group();
            return m.group(1) + map.placeholder(v, prefix);
        });
        // parametri posizionali della chiamata principale
        Matcher mm = XR_METHOD.matcher(body);
        if (mm.find()) {
            int[] pos = xmlRpcPositions(mm.group(1));
            int[] idx = {0};
            body = regexReplace(body, XR_PARAM_VALUE, m -> {
                idx[0]++;                                     // ogni parametro conta, anche <int>
                if (m.group(1) != null && !m.group(1).equals("string")) return m.group();
                String v = m.group(2) != null ? m.group(2) : m.group(3);
                int start = m.group(2) != null ? m.start(2) : m.start(3);
                String rep = xmlRpcValue(v, idx[0], pos);
                if (rep.equals(v)) return m.group();
                String whole = m.group();
                int off = start - m.start();
                return whole.substring(0, off) + rep + whole.substring(off + v.length());
            });
        }
        // system.multicall: ogni chiamata annidata con i suoi parametri
        return regexReplace(body, XR_MULTICALL, m -> {
            int[] pos = xmlRpcPositions(m.group(1).trim());
            int[] idx = {0};
            String data = regexReplace(m.group(2), XR_DATA_VALUE, d -> {
                idx[0]++;
                if (d.group(1) != null && !d.group(1).equals("string")) return d.group();
                String v = d.group(2) != null ? d.group(2) : d.group(3);
                int start = d.group(2) != null ? d.start(2) : d.start(3);
                String rep = xmlRpcValue(v, idx[0], pos);
                if (rep.equals(v)) return d.group();
                String whole = d.group();
                int off = start - d.start();
                return whole.substring(0, off) + rep + whole.substring(off + v.length());
            });
            String whole = m.group();
            int off = m.start(2) - m.start();
            return whole.substring(0, off) + data + whole.substring(off + m.group(2).length());
        });
    }

    /** {posizione username, posizione password} (1-based) per il metodo, o {0,0}. */
    private int[] xmlRpcPositions(String method) {
        String best = null;
        for (String k : cfg.xmlrpcCredentials.keySet()) {
            if ((method.equals(k) || (k.endsWith(".") && method.startsWith(k))) && (best == null || k.length() > best.length())) best = k;
        }
        return best == null ? new int[]{0, 0} : cfg.xmlrpcCredentials.get(best);
    }

    private String xmlRpcValue(String v, int index, int[] pos) {
        String t = v.trim();
        if (t.isEmpty() || map.looksLikePlaceholder(t)) return v;
        String rep = null;
        if (index == pos[0]) rep = map.placeholder(t, "USERNAME");
        else if (index == pos[1]) rep = map.placeholder(t, "PASSWORD");
        if (rep == null) {
            String s = scanValue(t, null, 0);
            rep = s.equals(t) ? secretOrNameShaped(t) : s;
        }
        if (rep.equals(t)) return v;
        int lead = v.indexOf(t);
        return v.substring(0, lead) + rep + v.substring(lead + t.length());
    }

    // ------------------------------------------------------- vCard / iCalendar
    // CardDAV / CalDAV, export di contatti e inviti: proprieta' "NOME;PARAM=..:valore".
    // Le proprieta' sensibili (context.vcard_properties) si nascondono per intero,
    // il parametro CN (nome di organizzatore e partecipanti) diventa NAME_n, il resto
    // (SUMMARY, DESCRIPTION, mailto:) si scansiona come testo.

    private static final Pattern VCARD_LINE = Pattern.compile("(?m)^([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)?)((?:;[^:\\r\\n]*)?):([^\\r\\n]*)");
    private static final Pattern VCARD_CN = Pattern.compile("(?i)(;CN=)(\"[^\"]*\"|[^;:]*)");

    private String anonDirectoryText(String body) {
        return regexReplace(body, VCARD_LINE, m -> {
            String name = m.group(1);
            String prop = name.contains(".") ? name.substring(name.indexOf('.') + 1) : name;
            String params = m.group(2);
            String value = m.group(3);
            if (!params.isEmpty()) {
                params = regexReplace(params, VCARD_CN, c -> {
                    String cn = c.group(2);
                    boolean q = cn.startsWith("\"") && cn.endsWith("\"") && cn.length() >= 2;
                    String inner = q ? cn.substring(1, cn.length() - 1) : cn;
                    if (inner.trim().isEmpty()) return c.group();
                    String ph = map.placeholder(inner.trim(), "NAME");
                    return c.group(1) + (q ? "\"" + ph + "\"" : ph);
                });
            }
            String prefix = cfg.vcardProperties.get(prop.toUpperCase(Locale.ROOT));
            String newValue;
            if (prefix != null && !value.trim().isEmpty() && !value.replace(";", "").trim().isEmpty()) {
                newValue = map.placeholder(value, prefix);
            } else {
                newValue = value; // il resto lo scansiona scanSecrets sul body intero
            }
            return name + params + ":" + newValue;
        });
    }

    // --- UTF-16 ---
    // Il caso peggiore non e' il testo illeggibile ma quello che a schermo sembra
    // normale e ai rilevatori no: "m\0a\0r\0i\0o\0". Si decodifica, si anonimizza
    // e si ricodifica uguale; la de-anonimizzazione fa il percorso inverso.

    /** 0 = no, 1 = UTF-16LE (zero dopo il carattere), 2 = UTF-16BE (zero prima). */
    static int utf16Kind(String s, int from, int len) {
        if (len < 8) return 0;
        int even = 0, odd = 0, pairs = len / 2;
        for (int i = 0; i + 1 < len; i += 2) {
            char a = s.charAt(from + i), b = s.charAt(from + i + 1);
            if (a > 0xFF || b > 0xFF) return 0;
            if (b == 0 && a != 0) odd++;
            else if (a == 0 && b != 0) even++;
        }
        if (odd >= pairs * 0.6) return 1;
        if (even >= pairs * 0.6) return 2;
        return 0;
    }

    private String anonUtf16Body(String body, String contentType) {
        int bom = 0;
        if (body.length() >= 2 && ((body.charAt(0) == 0xFF && body.charAt(1) == 0xFE)
                || (body.charAt(0) == 0xFE && body.charAt(1) == 0xFF))) bom = 2;
        int kind = utf16Kind(body, bom, body.length() - bom);
        if (kind == 0 || (body.length() - bom) % 2 != 0) return null;
        String text = decodeUtf16(body.substring(bom), kind);
        if (text == null) return null;
        String ct = contentType == null ? "" : contentType.replaceAll("(?i);?\\s*charset=[^;]*", "");
        String anon = anonymizeBody(text, ct);
        return body.substring(0, bom) + encodeUtf16(anon, kind);
    }

    static String decodeUtf16(String latin, int kind) {
        byte[] b = new byte[latin.length()];
        for (int i = 0; i < b.length; i++) {
            char c = latin.charAt(i);
            if (c > 0xFF) return null;
            b[i] = (byte) c;
        }
        return new String(b, kind == 1 ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_16BE);
    }

    static String encodeUtf16(String s, int kind) {
        byte[] b = s.getBytes(kind == 1 ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_16BE);
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    // --- CSV / TSV (export di dati: tipico di un IDOR su /export.csv) ---
    // L'intestazione dice cosa c'e' in ogni colonna: "cognome" rende sensibili
    // tutte le celle sotto, come una chiave JSON. Separatori, virgolette e a capo
    // originali restano identici.

    private String anonDelimited(String body) {
        int firstNl = body.indexOf('\n');
        String head = firstNl < 0 ? body : body.substring(0, firstNl);
        int tabs = count(head, '\t'), commas = count(head, ','), semis = count(head, ';');
        char delim = tabs > 0 ? '\t' : (semis > commas ? ';' : ',');
        if (count(head, delim) == 0) return null;
        List<String> header = new ArrayList<>();
        StringBuilder out = new StringBuilder(body.length() + 64);
        int i = 0, n = body.length(), col = 0, row = 0;
        while (true) {
            // un campo: tra virgolette ("" come escape, a capo ammessi) oppure semplice
            int start = i;
            if (i < n && body.charAt(i) == '"') {
                i++;
                while (i < n) {
                    if (body.charAt(i) == '"') {
                        if (i + 1 < n && body.charAt(i + 1) == '"') { i += 2; continue; }
                        i++;
                        break;
                    }
                    i++;
                }
            }
            while (i < n && body.charAt(i) != delim && body.charAt(i) != '\n' && body.charAt(i) != '\r') i++;
            String raw = body.substring(start, i);
            if (row == 0) {
                header.add(unquoteCsv(raw));
                out.append(raw);
            } else {
                out.append(anonCsvCell(raw, col < header.size() ? header.get(col) : null));
            }
            if (i >= n) break;
            char c = body.charAt(i);
            if (c == delim) {
                out.append(c);
                i++;
                col++;
            } else {
                int e = i;
                if (c == '\r' && e + 1 < n && body.charAt(e + 1) == '\n') e++;
                out.append(body, i, e + 1);
                i = e + 1;
                col = 0;
                row++;
                if (i >= n) break;
            }
        }
        return out.toString();
    }

    private static int count(String s, char c) {
        int k = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) k++;
        return k;
    }

    private static String unquoteCsv(String raw) {
        String r = raw.trim();
        if (r.length() >= 2 && r.startsWith("\"") && r.endsWith("\"")) r = r.substring(1, r.length() - 1).replace("\"\"", "\"");
        return r;
    }

    private String anonCsvCell(String raw, String column) {
        if (raw.isEmpty()) return raw;
        boolean quoted = raw.length() >= 2 && raw.startsWith("\"") && raw.endsWith("\"");
        String inner = quoted ? raw.substring(1, raw.length() - 1) : raw;
        if (inner.isEmpty()) return raw;
        String prefix = column == null ? null : sensitiveKeyPrefix(column);
        String done;
        if (prefix != null && !skipValue(inner.trim())) {
            String v = inner.trim();
            int lead = inner.indexOf(v);
            String ph = map.placeholder(v, prefix);
            done = inner.substring(0, lead) + ph + inner.substring(lead + v.length());
        } else {
            done = scanValue(inner, column, 0);
        }
        return quoted ? "\"" + done + "\"" : done;
    }

    // --- JSON (riscrittura tollerante che preserva la formattazione) ---

    private static final class Frame {
        final boolean obj;
        final String inherited;  // prefisso ereditato dal contenitore
        final String ctxKey;     // chiave sotto cui sta il contenitore
        String key;
        boolean expectKey;

        Frame(boolean obj, String inherited, String ctxKey) {
            this.obj = obj;
            this.inherited = inherited;
            this.ctxKey = ctxKey;
            this.expectKey = obj;
        }
    }

    private static boolean looksLikeJsonDoc(String s) {
        if (s.isEmpty()) return false;
        char f = s.charAt(0);
        int i = 1;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        if (i >= s.length()) return false;
        char c = s.charAt(i);
        if (f == '{') return c == '"' || c == '}';
        if (f == '[') return c == '{' || c == '[' || c == '"' || c == ']' || c == '-'
                || Character.isDigit(c) || c == 't' || c == 'f' || c == 'n';
        return false;
    }

    private String memberKey(Frame top) {
        if (top == null) return null;
        return top.obj ? top.key : top.ctxKey;
    }

    private String valuePrefix(Frame top) {
        if (top == null) return null;
        if (top.obj && top.key != null) {
            String p = sensitiveKeyPrefix(top.key);
            if (p != null) return p;
        }
        return top.inherited;
    }

    private String rewriteJson(String s, int depth) {
        StringBuilder out = new StringBuilder(s.length() + 32);
        List<Frame> st = new ArrayList<>();
        boolean malformed = false;
        int i = 0, n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            Frame top = st.isEmpty() ? null : st.get(st.size() - 1);
            if (c == '"') {
                int j = i + 1;
                boolean closed = false;
                while (j < n) {
                    char d = s.charAt(j);
                    if (d == '\\') { j += 2; continue; }
                    if (d == '"') { closed = true; break; }
                    j++;
                }
                if (j > n) j = n;
                String raw = s.substring(i + 1, Math.min(j, n));
                int end = closed ? j + 1 : n;
                if (!closed) malformed = true;
                if (top != null && top.obj && top.expectKey) {
                    top.key = decodeJsonString(raw);
                    top.expectKey = false;
                    out.append(s, i, end);
                } else {
                    out.append(rewriteJsonString(raw, closed, top, depth));
                }
                i = end;
                continue;
            }
            if (c == '{' || c == '[') {
                String p = valuePrefix(top);
                // un oggetto sotto "user"/"login" e' un profilo: decidono le sue chiavi
                if (c == '{' && "USERNAME".equals(p)) p = null;
                st.add(new Frame(c == '{', p, memberKey(top)));
                out.append(c);
                i++;
                continue;
            }
            if (c == '}' || c == ']') {
                if (!st.isEmpty()) st.remove(st.size() - 1); else malformed = true;
                out.append(c);
                i++;
                continue;
            }
            if (c == ',') {
                if (top != null && top.obj) { top.expectKey = true; top.key = null; }
                out.append(c);
                i++;
                continue;
            }
            if (c == ':') {
                if (top != null && top.obj) top.expectKey = false;
                out.append(c);
                i++;
                continue;
            }
            if (Character.isWhitespace(c)) {
                out.append(c);
                i++;
                continue;
            }
            int j = i;
            while (j < n) {
                char d = s.charAt(j);
                if (d == '"' || d == '{' || d == '}' || d == '[' || d == ']' || d == ','
                        || d == ':' || Character.isWhitespace(d)) break;
                j++;
            }
            String tok = s.substring(i, j);
            if (top != null && top.obj && top.expectKey) {
                top.key = tok;
                top.expectKey = false;
                out.append(tok);
                malformed = true;
            } else {
                if (!isJsonLiteral(tok)) malformed = true;
                out.append(rewriteJsonBare(tok, top));
            }
            i = j;
        }
        if (!st.isEmpty()) malformed = true;
        String res = out.toString();
        // JSON non valido (troncato, JS...): rete di sicurezza sulle coppie chiave/valore
        if (malformed) res = replaceKeyValues(res);
        return res;
    }

    private static boolean isJsonLiteral(String tok) {
        return tok.equals("true") || tok.equals("false") || tok.equals("null")
                || JSON_NUMBER.matcher(tok).matches();
    }

    private String rewriteJsonString(String raw, boolean closed, Frame top, int depth) {
        boolean esc = raw.indexOf('\\') >= 0;
        String v = esc ? decodeJsonString(raw) : raw;
        String key = memberKey(top);
        String q = closed ? "\"" : "";
        if (isPreservedKey(key)) return "\"" + raw + q;
        String prefix = valuePrefix(top);
        // "name": "spring.datasource.password" e' il nome di una proprieta', non di una persona
        if ("NAME".equals(prefix) && (looksLikePropertyName(v) || (introspection && GQL_IDENT.matcher(v).matches()))) prefix = null;
        if (prefix != null || strictId(key, v)) {
            if (v.isEmpty()) return "\"" + raw + q;
            String token = map.placeholder(v, prefix != null ? prefix : "ID");
            if (token.equals(v)) return "\"" + raw + q;
            // valore con escape: variante esatta, cosi' la decodifica ricrea l'escape originale
            return "\"" + (esc ? map.variant(token, raw, "JSON") : token) + q;
        }
        java.util.function.UnaryOperator<String> branch = (key != null && isGraphqlKey(key) && looksLikeGraphql(v))
                ? this::anonGraphqlDoc
                : s -> scanValue(s, key, depth);
        if (!esc) {
            String nv = branch.apply(v);
            return "\"" + (nv.equals(v) ? raw : encodeJsonString(nv)) + q;
        }
        String spliced = spliceScan(raw, jsonDecodeMapped(raw), branch, "JSON");
        if (spliced != null) return "\"" + spliced + q;
        String nv = branch.apply(v);
        return "\"" + (nv.equals(v) ? raw : encodeJsonString(nv)) + q;
    }

    /** Dentro una risposta d'introspezione GraphQL (__schema / __type). */
    private boolean introspection;
    private static final Pattern GQL_IDENT = Pattern.compile("[_A-Za-z][_0-9A-Za-z]{0,100}");
    private static final Pattern PROPERTY_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)+");

    /** Identificativo con separatori che e' a sua volta una chiave sensibile o un percorso a.b.c. */
    private boolean looksLikePropertyName(String v) {
        if (v.length() > 128 || !PROPERTY_NAME.matcher(v).matches()) return false;
        if (sensitiveKeyPrefix(v) != null || isHostKey(v)) return true;
        int dots = 0;
        for (int i = 0; i < v.length(); i++) if (v.charAt(i) == '.') dots++;
        return dots >= 2;
    }

    private static boolean isGraphqlKey(String key) {
        return key.equalsIgnoreCase("query") || key.equalsIgnoreCase("mutation");
    }

    // ------------------------------------------------ decodifica con posizioni
    /** Testo decodificato + indice nel testo grezzo di ogni carattere (idx.length = text.length()+1). */
    private static final class Decoded {
        final String text;
        final int[] idx;
        Decoded(String text, int[] idx) { this.text = text; this.idx = idx; }
    }

    private static Decoded jsonDecodeMapped(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        int[] idx = new int[raw.length() + 1];
        int n = raw.length(), k = 0;
        for (int i = 0; i < n; i++) {
            char c = raw.charAt(i);
            int start = i;
            if (c == '\\' && i + 1 < n) {
                char e = raw.charAt(i + 1);
                char out;
                switch (e) {
                    case '"': out = '"'; i++; break;
                    case '\\': out = '\\'; i++; break;
                    case '/': out = '/'; i++; break;
                    case 'b': out = '\b'; i++; break;
                    case 'f': out = '\f'; i++; break;
                    case 'n': out = '\n'; i++; break;
                    case 'r': out = '\r'; i++; break;
                    case 't': out = '\t'; i++; break;
                    case 'u':
                        if (i + 6 <= n) {
                            try {
                                out = (char) Integer.parseInt(raw.substring(i + 2, i + 6), 16);
                                i += 5;
                                break;
                            } catch (RuntimeException ignored) {
                            }
                        }
                        out = c;
                        break;
                    default: out = c;
                }
                idx[k++] = start;
                sb.append(out);
            } else {
                idx[k++] = start;
                sb.append(c);
            }
        }
        idx[k] = n;
        return new Decoded(sb.toString(), Arrays.copyOf(idx, k + 1));
    }

    /** Percent-decoding UTF-8 ('+' come spazio), con mappa delle posizioni. */
    private static Decoded urlDecodeMapped(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        int[] idx = new int[raw.length() + 1];
        int n = raw.length(), k = 0, i = 0;
        while (i < n) {
            char c = raw.charAt(i);
            if (c == '%' && i + 2 < n
                    && Character.digit(raw.charAt(i + 1), 16) >= 0 && Character.digit(raw.charAt(i + 2), 16) >= 0) {
                int s = i;
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                while (i + 2 < n && raw.charAt(i) == '%'
                        && Character.digit(raw.charAt(i + 1), 16) >= 0 && Character.digit(raw.charAt(i + 2), 16) >= 0) {
                    bytes.write((Character.digit(raw.charAt(i + 1), 16) << 4) | Character.digit(raw.charAt(i + 2), 16));
                    i += 3;
                }
                byte[] b = bytes.toByteArray();
                String dec = decodeUtf8Strict(b);
                if (dec == null) { // byte non UTF-8: lascia il testo cosi' com'e'
                    for (int j = s; j < i; j++) { idx[k++] = j; sb.append(raw.charAt(j)); }
                    continue;
                }
                int pos = s;
                for (int j = 0; j < dec.length(); ) {
                    int cp = dec.codePointAt(j);
                    int units = Character.charCount(cp);
                    int blen = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8).length;
                    for (int u = 0; u < units; u++) { idx[k++] = pos; sb.append(dec.charAt(j + u)); }
                    pos += 3 * blen;
                    j += units;
                }
                continue;
            }
            idx[k++] = i;
            sb.append(c == '+' ? ' ' : c);
            i++;
        }
        idx[k] = n;
        return new Decoded(sb.toString(), Arrays.copyOf(idx, k + 1));
    }

    private static final Pattern ENTITY = Pattern.compile(
            "&(?:#(\\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|(amp|lt|gt|quot|apos|commat|period|num|colon|sol));");

    /** Entita' HTML (&#64; &amp; ...) con mappa delle posizioni. */
    private static Decoded entityDecodeMapped(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        int[] idx = new int[raw.length() + 1];
        int k = 0, last = 0;
        Matcher m = ENTITY.matcher(raw);
        while (m.find()) {
            for (int j = last; j < m.start(); j++) { idx[k++] = j; sb.append(raw.charAt(j)); }
            String rep;
            try {
                if (m.group(1) != null) rep = new String(Character.toChars(Integer.parseInt(m.group(1))));
                else if (m.group(2) != null) rep = new String(Character.toChars(Integer.parseInt(m.group(2), 16)));
                else {
                    switch (m.group(3)) {
                        case "amp": rep = "&"; break;
                        case "lt": rep = "<"; break;
                        case "gt": rep = ">"; break;
                        case "quot": rep = "\""; break;
                        case "apos": rep = "'"; break;
                        case "commat": rep = "@"; break;
                        case "period": rep = "."; break;
                        case "num": rep = "#"; break;
                        case "colon": rep = ":"; break;
                        default: rep = "/";
                    }
                }
            } catch (RuntimeException e) {
                rep = m.group();
                for (int j = m.start(); j < m.end(); j++) { idx[k++] = j; sb.append(raw.charAt(j)); }
                last = m.end();
                continue;
            }
            for (int u = 0; u < rep.length(); u++) { idx[k++] = m.start(); sb.append(rep.charAt(u)); }
            last = m.end();
        }
        for (int j = last; j < raw.length(); j++) { idx[k++] = j; sb.append(raw.charAt(j)); }
        idx[k] = raw.length();
        return new Decoded(sb.toString(), Arrays.copyOf(idx, k + 1));
    }

    private static boolean isWordChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    }

    private static boolean isHex(char c) {
        return Character.digit(c, 16) >= 0;
    }

    /** Inizio di parola, oppure subito dopo una sequenza %XX / %25XX (come in deanonymize). */
    private static boolean tokenBoundary(String s, int i) {
        if (i == 0 || !isWordChar(s.charAt(i - 1))) return true;
        if (i < 3 || !isHex(s.charAt(i - 1)) || !isHex(s.charAt(i - 2))) return false;
        int k = i - 3;
        for (int level = 0; level <= 3 && k >= 0; level++) {
            if (s.charAt(k) == '%') return true;
            if (k >= 2 && s.charAt(k) == '5' && s.charAt(k - 1) == '2') k -= 2; else return false;
        }
        return false;
    }

    /** Posizioni dei placeholder emessi (o letterali riservati) presenti nel testo. */
    private List<int[]> findTokens(String sc) {
        List<int[]> toks = new ArrayList<>();
        int n = sc.length(), i = 0;
        while (i < n) {
            char c = sc.charAt(i);
            if (c >= 'A' && c <= 'Z' && tokenBoundary(sc, i)) {
                int j = i + 1;
                while (j < n && isWordChar(sc.charAt(j)) && j - i < 64) j++;
                String t = sc.substring(i, j);
                if (map.isEmitted(t) || t.equals("REDACTED") || map.looksLikePlaceholder(t)) {
                    toks.add(new int[]{i, j});
                    i = j;
                    continue;
                }
            }
            i++;
        }
        return toks;
    }

    /**
     * Scansiona la forma decodificata ma sostituisce sul testo GREZZO: le parti
     * non sensibili restano byte per byte come nell'originale e ogni valore
     * sostituito riceve un placeholder (o una sua variante esatta) che la
     * de-anonimizzazione riporta alla rappresentazione originale.
     * Ritorna null se l'allineamento non e' possibile (il chiamante ripiega).
     */
    private String spliceScan(String raw, Decoded d, java.util.function.UnaryOperator<String> scanner, String kind) {
        String dec = d.text;
        String sc = scanner.apply(dec);
        if (sc.equals(dec)) return raw;
        List<int[]> toks = findTokens(sc);
        StringBuilder out = new StringBuilder(raw.length() + 16);
        int dp = 0, sp = 0;
        for (int ti = 0; ti < toks.size(); ti++) {
            int ts = toks.get(ti)[0], te = toks.get(ti)[1];
            String lit = sc.substring(sp, ts);
            if (!dec.startsWith(lit, dp)) return null;
            out.append(raw, d.idx[dp], d.idx[dp + lit.length()]);
            dp += lit.length();
            String tok = sc.substring(ts, te);
            String next = sc.substring(te, ti + 1 < toks.size() ? toks.get(ti + 1)[0] : sc.length());
            String orig = map.originalOf(tok);
            int end;
            if (dec.startsWith(tok, dp) && (orig == null || !dec.regionMatches(true, dp, orig, 0, orig.length()))) {
                end = dp + tok.length(); // placeholder letterale gia' presente
            } else if (orig != null && dec.regionMatches(true, dp, orig, 0, orig.length())) {
                end = dp + orig.length();
            } else if (!next.isEmpty()) {
                end = dec.indexOf(next, dp);
                if (end < 0) return null;
            } else if (ti == toks.size() - 1) {
                end = dec.length();
            } else {
                return null;
            }
            String decSpan = dec.substring(dp, end);
            String rawSpan = raw.substring(d.idx[dp], d.idx[end]);
            if (decSpan.equals(tok) || rawSpan.equals(tok)) out.append(rawSpan);
            else if (rawSpan.equals(decSpan)) out.append(tok);
            else out.append(map.variant(tok, rawSpan, kind));
            dp = end;
            sp = te;
        }
        String tail = sc.substring(sp);
        if (!dec.substring(dp).equals(tail)) return null;
        out.append(raw, d.idx[dp], raw.length());
        return out.toString();
    }

    private String rewriteJsonBare(String tok, Frame top) {
        if (tok.equals("true") || tok.equals("false") || tok.equals("null")) return tok;
        if (isPreservedKey(memberKey(top))) return tok;
        String prefix = valuePrefix(top);
        if (JSON_NUMBER.matcher(tok).matches()) {
            // segnaposto SENZA virgolette: un numero tra virgolette non tornerebbe
            // identico con la de-anonimizzazione ("lat": GEO_1 -> "lat": 45.46)
            if (prefix != null && !prefix.equals("USERNAME")) return map.placeholder(tok, prefix);
            if (prefix == null && strictId(memberKey(top), tok)) return map.placeholder(tok, "ID");
            if (!isIdKey(memberKey(top)) && validCard(tok)) return map.placeholder(tok, "CARD");
            return tok;
        }
        return prefix != null ? map.placeholder(tok, prefix) : scanSecrets(tok);
    }

    /** Scansiona un valore che puo' contenere a sua volta JSON, URL, query string... */
    private String scanValue(String v, String key, int depth) {
        if (v == null || v.isEmpty()) return v;
        String t = v.trim();
        if (isHostKey(key) && looksLikeInternalHost(t)) {
            // "db_host": "srv-sql-prod01": nome di server interno senza TLD
            int lead = v.indexOf(t);
            return v.substring(0, lead) + anonHostValue(t) + v.substring(lead + t.length());
        }
        if (depth < 6 && !t.isEmpty() && (t.charAt(0) == '{' || t.charAt(0) == '[') && looksLikeJsonDoc(t)) {
            return rewriteJson(v, depth + 1);
        }
        if (isAttackPayload(t)) {
            // payload del tester: niente mascheramento per chiave (Set-Cookie: ... in una
            // CRLF injection), ma email, IP e segreti al suo interno si cercano comunque
            return scanPayload(v);
        }
        return scan(v, isIdKey(key));
    }

    private String scanPayload(String text) {
        List<String> saved = new ArrayList<>();
        String t = protect(text, DATA_URI, saved);
        t = replaceUrlHosts(t);
        t = applyPatterns(t, true);
        t = replaceKnownValues(t);
        t = replaceHostTokens(t, false, false);
        return restore(t, saved);
    }

    private static String decodeJsonString(String raw) {
        if (raw.indexOf('\\') < 0) return raw;
        StringBuilder sb = new StringBuilder(raw.length());
        int n = raw.length();
        for (int i = 0; i < n; i++) {
            char c = raw.charAt(i);
            if (c != '\\' || i + 1 >= n) { sb.append(c); continue; }
            char e = raw.charAt(++i);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (i + 4 < n) {
                        try {
                            sb.append((char) Integer.parseInt(raw.substring(i + 1, i + 5), 16));
                            i += 4;
                            break;
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    sb.append("\\u");
                    break;
                default: sb.append('\\').append(e);
            }
        }
        return sb.toString();
    }

    private static String encodeJsonString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    // --- form-urlencoded ---
    private String anonFormBody(String body) {
        if (!body.contains("=")) return null;
        String[] pairs = body.split("&", -1);
        List<String> out = new ArrayList<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                String k = pair.substring(0, eq);
                String v = pair.substring(eq + 1);
                String dec = urlDecode(v);
                String dk = urlDecode(k);
                if (isPreservedKey(dk)) { out.add(pair); continue; }
                String prefix = queryKeyPrefix(dk);
                if (prefix != null && !dec.isEmpty() && !skipValue(dec)) {
                    out.add(k + "=" + keyedToken(dec, v, prefix));
                } else if (strictId(dk, dec)) {
                    out.add(k + "=" + keyedToken(dec, v, "ID"));
                } else if (!dec.isEmpty()) {
                    out.add(k + "=" + encodedScan(v, s -> scanValue(s, dk, 0)));
                } else {
                    out.add(pair);
                }
            } else {
                out.add(encodedScan(pair, this::scanSecrets));
            }
        }
        return String.join("&", out);
    }

    // ------------------------------------------------------ chiavi sensibili
    private static String normKey(String key) {
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '_' || c == '-' || c == '.' || Character.isWhitespace(c)) continue;
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private String exactKeyPrefix(String norm) {
        if (cfg.keyExact.contains(norm)) return cfg.keyPrefixMap.getOrDefault(norm, "SECRET");
        return null;
    }

    private String sensitiveKeyPrefix(String key) {
        if (key == null || key.isEmpty() || key.length() > 128) return null;
        String norm = normKey(key);
        if (norm.isEmpty()) return null;
        if (ov.excludeKeys.contains(norm)) return null;
        if (ov.extraKeys.contains(norm)) return "CUSTOM";
        String p = exactKeyPrefix(norm);
        if (p != null) return p;
        if (norm.length() > 3 && norm.endsWith("s")) {
            p = exactKeyPrefix(norm.substring(0, norm.length() - 1));
            if (p != null) return p;
        }
        for (String token : cfg.keyContains) {
            if (norm.contains(token)) {
                if (SAFE_CHECK_TOKENS.contains(token) && hasSafeSubword(norm, token)) return null;
                return cfg.keyPrefixMap.getOrDefault(token, "SECRET");
            }
        }
        return null;
    }

    private static boolean hasSafeSubword(String norm, String token) {
        String rest = norm.replace(token, " ");
        for (String w : SAFE_SUBWORDS) if (rest.contains(w)) return true;
        return false;
    }

    /** Chiave in query string / form / multipart: include le chiavi OAuth ("code"...). */
    private String queryKeyPrefix(String key) {
        String p = sensitiveKeyPrefix(key);
        if (p == null && key != null && QUERY_ONLY_KEYS.contains(normKey(key))) p = "TOKEN";
        return p;
    }

    private static boolean isIdKey(String key) {
        if (key == null || key.isEmpty() || key.length() > 128) return false;
        if (ID_KEY_SEP.matcher(key).find()) return true;
        String norm = normKey(key);
        for (String suf : ID_FREE_SUFFIXES) if (norm.endsWith(suf)) return true;
        return false;
    }

    /** Campo/header che l'utente vuole sempre in chiaro (options.preserve_keys). */
    private boolean isPreservedKey(String key) {
        return key != null && !cfg.preserveKeys.isEmpty() && cfg.preserveKeys.contains(normKey(key));
    }

    /** Livello "strict": un identificativo non sensibile diventa ID_n. */
    private boolean strictId(String key, String value) {
        return cfg.strictIds() && isIdKey(key) && value != null && !value.isEmpty() && !skipValue(value);
    }

    // ------------------------------------------------------------ scan generico
    public String scanSecrets(String text) {
        return scan(text, false);
    }

    /** limited = sotto chiavi identificative: niente pattern generici/carte/telefoni. */
    private String scan(String text, boolean limited) {
        if (text == null || text.isEmpty()) return text;
        List<String> saved = new ArrayList<>();
        String t = protect(text, DATA_URI, saved);
        t = replaceKeyValues(t);
        t = replaceUrlHosts(t);
        t = applyPatterns(t, limited);
        t = replaceKnownValues(t);
        t = replaceHostTokens(t, true, true);
        return restore(t, saved);
    }

    // --- propagazione dei valori gia' noti (es. "Mario Rossi" trovato nel campo
    //     "name" viene sostituito anche nel testo libero) ---
    private static final Set<String> PROPAGATE_TYPES = Set.of(
            "NAME", "ADDRESS", "SECRET", "TOKEN", "AUTH_TOKEN", "SESSION", "APIKEY", "COOKIE",
            "USERNAME", "CF", "JWT", "CUSTOM", "SSN", "ID");
    private static final int MAX_PROPAGATED = 300;
    private final List<String> knownValues = new ArrayList<>();
    private int knownScanned = 0;
    private Pattern knownValuesRe;

    private String replaceKnownValues(String text) {
        if (text == null || text.isEmpty()) return text;
        if (knownValues.size() < MAX_PROPAGATED && knownScanned < map.size()) {
            boolean added = false;
            for (SubstitutionMap.Entry e : map.entriesFrom(knownScanned)) {
                String o = e.original;
                if (knownValues.size() >= MAX_PROPAGATED) break;
                if (!PROPAGATE_TYPES.contains(e.type) || o.length() < 6 || o.length() > 300
                        || o.indexOf('\n') >= 0 || o.trim().length() != o.length()
                        || map.looksLikePlaceholder(o) || o.chars().allMatch(Character::isDigit)) continue;
                knownValues.add(o);
                added = true;
            }
            knownScanned = map.size();
            if (added) {
                List<String> sorted = new ArrayList<>(knownValues);
                sorted.sort((a, b) -> Integer.compare(b.length(), a.length()));
                StringBuilder alt = new StringBuilder();
                for (String v : sorted) {
                    if (alt.length() > 0) alt.append('|');
                    alt.append(Pattern.quote(v));
                }
                knownValuesRe = Pattern.compile("(?<![A-Za-z0-9_])(?:" + alt + ")(?![A-Za-z0-9_])");
            }
        }
        if (knownValuesRe == null) return text;
        return regexReplace(text, knownValuesRe, m -> {
            String ph = map.placeholder(m.group(), "SECRET");
            return ph == null ? m.group() : ph;
        });
    }

    private static String protect(String text, Pattern p, List<String> saved) {
        if (text.indexOf("base64,") < 0) return text;
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        boolean any = false;
        while (m.find()) {
            any = true;
            m.appendReplacement(sb, "\uE000" + saved.size() + "\uE001");
            saved.add(m.group());
        }
        if (!any) return text;
        m.appendTail(sb);
        return sb.toString();
    }

    /** Come protect, per qualunque pattern (protect e' specializzato sui data URI). */
    private static String protectAll(String text, Pattern p, List<String> saved) {
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        boolean any = false;
        while (m.find()) {
            any = true;
            m.appendReplacement(sb, "\uE000" + saved.size() + "\uE001");
            saved.add(m.group());
        }
        if (!any) return text;
        m.appendTail(sb);
        return sb.toString();
    }

    private static String restore(String text, List<String> saved) {
        for (int i = 0; i < saved.size(); i++) {
            text = text.replace("\uE000" + i + "\uE001", saved.get(i));
        }
        return text;
    }

    /**
     * Coppie chiave/valore in testo libero: key=value, key: value, "key": "value",
     * key => 'value'... Il valore viene mascherato se la chiave e' sensibile.
     */
    private String replaceKeyValues(String text) {
        if (text == null || text.isEmpty() || (text.indexOf('=') < 0 && text.indexOf(':') < 0)) return text;
        Matcher m = KV_KEY.matcher(text);
        StringBuilder out = null;
        int n = text.length(), last = 0, from = 0;
        while (from < n && m.find(from)) {
            from = m.end();
            int vs = m.end();
            if (vs >= n) break;
            String sep = m.group(3);
            char before = m.start() > 0 ? text.charAt(m.start() - 1) : '\0';
            boolean queryCtx = before == '?' || before == '&' || before == '#';
            String prefix = kvPrefix(m.group(2), queryCtx);
            boolean hostKey = prefix == null && isHostKey(m.group(2));
            if (prefix == null && !hostKey) continue;
            if (sep.equals(":") && text.startsWith("//", vs)) continue;
            int valStart, valEnd;
            char q = text.charAt(vs);
            if (q == '"' || q == '\'') {
                int j = vs + 1;
                while (j < n) {
                    char d = text.charAt(j);
                    if (d == '\\') { j += 2; continue; }
                    if (d == q || d == '\n' || d == '\r') break;
                    j++;
                }
                if (j >= n || text.charAt(j) != q) continue;
                valStart = vs + 1;
                valEnd = j;
            } else {
                boolean colon = sep.equals(":");
                int j = vs;
                while (j < n) {
                    char d = text.charAt(j);
                    if (d == '\r' || d == '\n') break;
                    if (colon) {
                        if (d == ',' || d == ';' || d == '}' || d == ']' || d == '&' || d == '<'
                                || d == '"' || d == '\'') break;
                    } else if (Character.isWhitespace(d) || d == '&' || d == ';' || d == ','
                            || d == '"' || d == '\'' || d == '<' || d == '>' || d == ')'
                            || d == '}' || d == ']' || d == '#') {
                        break;
                    }
                    j++;
                }
                while (j > vs && Character.isWhitespace(text.charAt(j - 1))) j--;
                valStart = vs;
                valEnd = j;
            }
            if (valEnd <= valStart) continue;
            String raw = text.substring(valStart, valEnd);
            char c0 = raw.charAt(0);
            if (skipValue(raw) || c0 == '{' || c0 == '[' || c0 == '(' || raw.startsWith("${")
                    || raw.startsWith("{{") || raw.indexOf('\uE000') >= 0
                    || AUTH_SCHEME_ONLY.matcher(raw.trim()).matches()) {
                continue;
            }
            // codice: obj.token = other.session (assegnazione tra riferimenti, non un segreto)
            if (q != '"' && q != '\'' && m.group(2).indexOf('.') > 0 && CODE_REF.matcher(raw).matches()) {
                continue;
            }
            // il valore non deve inglobare un segnaposto gia' emesso ("CN=Mario Rossi:mailto:EMAIL_1"):
            // la de-anonimizzazione e' a passata singola e non lo ricostruirebbe
            Matcher inner = LITERAL_PLACEHOLDER.matcher(raw);
            while (inner.find()) {
                if (!map.isEmitted(inner.group())) continue;
                String head = raw.substring(0, inner.start());
                int cut = head.length();
                for (char d : new char[]{':', ';', ',', '<', '(', '|'}) {
                    int k = head.indexOf(d);
                    if (k >= 0 && k < cut) cut = k;
                }
                raw = head.substring(0, cut).stripTrailing();
                valEnd = valStart + raw.length();   // il resto (":mailto:EMAIL_1") resta com'e'
                break;
            }
            if (raw.isEmpty()) continue;
            String repl;
            Matcher am = AUTH_SCHEME.matcher(raw);
            if (hostKey) {
                if (!looksLikeInternalHost(raw.trim())) continue;
                repl = anonHostValue(raw);
            } else if (am.matches()) repl = am.group(1) + " " + map.placeholder(am.group(2).trim(), prefix);
            else repl = map.placeholder(raw, prefix);
            from = valEnd;
            if (repl.equals(raw)) continue;
            if (out == null) out = new StringBuilder(n + 32);
            out.append(text, last, valStart).append(repl);
            last = valEnd;
        }
        if (out == null) return text;
        out.append(text, last, n);
        return out.toString();
    }

    private String kvPrefix(String key, boolean queryCtx) {
        String k = key;
        int dot = k.lastIndexOf('.');
        if (dot >= 0 && dot < k.length() - 1) k = k.substring(dot + 1);
        String p = queryCtx ? queryKeyPrefix(k) : sensitiveKeyPrefix(k);
        if (p != null && KV_EXCLUDED_PREFIXES.contains(p)) return null;
        return p;
    }

    private String applyPatterns(String text, boolean limited) {
        if (text == null || text.isEmpty()) return text;
        String t = applyPatternsRaw(text, limited);
        if (t.indexOf('%') >= 0) t = applyPatternsEncoded(t, limited);
        if (t.indexOf('&') >= 0) t = applyPatternsEntities(t, limited);
        t = applyPatternsBase64(t, limited);
        return t;
    }

    private static final Pattern B64_CANDIDATE = Pattern.compile(
            "(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{12,4096}={0,2}(?![A-Za-z0-9+/=_-])");

    /** Base64 che, decodificato, contiene un dato sensibile (es. un'email): mascherato per intero. */
    private String applyPatternsBase64(String text, boolean limited) {
        if (text.length() < 12) return text;
        return regexReplace(text, B64_CANDIDATE, m -> {
            String tok = m.group();
            if (map.looksLikePlaceholder(tok) || tok.length() % 4 == 1) return tok;
            String body = tok.replace("=", "");
            boolean letter = false, digitOrCase = false;
            for (int i = 0; i < body.length(); i++) {
                char c = body.charAt(i);
                if (Character.isLetter(c)) letter = true;
                if (Character.isDigit(c) || Character.isUpperCase(c)) digitOrCase = true;
            }
            if (!letter || !digitOrCase) return tok;
            byte[] raw;
            try {
                raw = (tok.indexOf('-') >= 0 || tok.indexOf('_') >= 0)
                        ? Base64.getUrlDecoder().decode(body) : Base64.getDecoder().decode(padB64(body));
            } catch (IllegalArgumentException e) {
                return tok;
            }
            String dec = decodeUtf8Strict(raw);
            if (dec == null || dec.length() < 6) return tok;
            for (int i = 0; i < dec.length(); i++) {
                char c = dec.charAt(i);
                if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') return tok; // binario, non testo
            }
            String scanned = applyPatternsRaw(dec, limited);
            if (scanned.equals(dec)) return tok;
            return map.placeholder(tok, "SECRET");
        });
    }

    private static String padB64(String s) {
        int r = s.length() % 4;
        if (r == 2) return s + "==";
        if (r == 3) return s + "=";
        return s; // r == 1: non e' base64 valido, il decoder lo rifiuta
    }

    private String applyPatternsRaw(String text, boolean limited) {
        text = maskPrintedIbans(text);
        for (PatternDef pat : cfg.patterns) {
            if (limited && isLimitedSkip(pat)) continue;
            text = applyOnePattern(text, pat);
        }
        return text;
    }

    // ---- IBAN nel formato di stampa (ISO 13616) ----
    // Dove finisce un IBAN a gruppi non si deduce dalla forma: senza la lunghezza
    // attesa per il paese o si inghiotte la parola dopo o si lascia in chiaro la coda.
    private static final Map<String, Integer> IBAN_LEN = new java.util.HashMap<>();
    static {
        for (String c : ("AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 "
                + "DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 "
                + "GT28 HN28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 "
                + "LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 "
                + "PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 "
                + "SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30").split(" ")) {
            IBAN_LEN.put(c.substring(0, 2), Integer.parseInt(c.substring(2)));
        }
    }
    private static final Pattern IBAN_HEAD = Pattern.compile("(?<![A-Za-z0-9])[A-Za-z]{2}\\d{2}");

    private String maskPrintedIbans(String text) {
        if (text.length() < 15) return text;
        Matcher h = IBAN_HEAD.matcher(text);
        StringBuilder out = null;
        int last = 0, from = 0;
        while (from < text.length() && h.find(from)) {
            int start = h.start();
            Integer n = IBAN_LEN.get(text.substring(start, start + 2).toUpperCase(Locale.ROOT));
            from = h.end();
            if (n == null) continue;
            int i = start, got = 0, sep = 0, run = 0, newlines = 0;
            boolean grouped = false;
            while (i < text.length() && got < n) {
                char c = text.charAt(i);
                if (c < 128 && Character.isLetterOrDigit(c)) {
                    got++;
                    run++;
                    sep = 0;
                } else if (sep < 3 && run <= 5 && (c == ' ' || c == '\t' || c == '.' || c == '-' || c == '\r' || c == '\n')) {
                    if (c == '\n' && ++newlines > 1) break;  // va a capo una volta, non a ogni cella
                    sep++;
                    run = 0;
                    grouped = true;
                } else {
                    break;
                }
                i++;
            }
            if (got < n || !grouped) continue;               // le forme compatte le fa il pattern
            if (i < text.length() && text.charAt(i) < 128 && Character.isLetterOrDigit(text.charAt(i))) continue;
            String cand = text.substring(start, i);
            if (map.looksLikePlaceholder(cand) || !validIban(cand.replaceAll("[\\s.\\-]", ""))) continue;
            if (out == null) out = new StringBuilder(text.length());
            out.append(text, last, start).append(map.placeholder(cand, "IBAN"));
            last = i;
            from = i;
        }
        if (out == null) return text;
        return out.append(text, last, text.length()).toString();
    }

    private static boolean isGeneric(PatternDef pat) {
        return pat.name.startsWith("generic_") || "hex".equals(pat.validate)
                || "b64".equals(pat.validate) || "b64secret".equals(pat.validate);
    }

    private static boolean isLimitedSkip(PatternDef pat) {
        return isGeneric(pat) || "card".equals(pat.validate) || "luhn".equals(pat.validate)
                || "phone".equals(pat.validate) || "piva".equals(pat.validate) || "plate".equals(pat.validate);
    }

    private static boolean isUrlChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '~' || c == '%' || c == '+' || c == '-';
    }

    /** Valori percent-encoded (path, query relative, Location...): decodifica e scansiona. */
    private String applyPatternsEncoded(String text, boolean limited) {
        StringBuilder out = null;
        int n = text.length(), i = 0, last = 0;
        while (i < n) {
            if (!isUrlChar(text.charAt(i))) { i++; continue; }
            int s = i;
            boolean pct = false;
            while (i < n && isUrlChar(text.charAt(i))) {
                if (text.charAt(i) == '%' && i + 2 < n
                        && Character.digit(text.charAt(i + 1), 16) >= 0
                        && Character.digit(text.charAt(i + 2), 16) >= 0) pct = true;
                i++;
            }
            if (!pct) continue;
            String run = text.substring(s, i);
            Decoded d = urlDecodeMapped(run);
            if (d.text.equals(run)) continue; // niente di decodificabile (es. byte UTF-8 non validi)
            // ricorsivo: gestisce anche la doppia codifica (%2540 -> %40 -> @), con limite di profondita'
            String repl;
            if (encodedDepth >= 4) {
                repl = run;
            } else {
                encodedDepth++;
                try {
                    repl = spliceScan(run, d, t -> applyPatterns(t, limited), "URL");
                    if (repl == null) {
                        String scanned = applyPatternsRaw(d.text, limited);
                        repl = scanned.equals(d.text) ? run : urlEncode(scanned);
                    }
                } finally {
                    encodedDepth--;
                }
            }
            if (repl.equals(run)) continue;
            if (out == null) out = new StringBuilder(n + 16);
            out.append(text, last, s).append(repl);
            last = i;
        }
        if (out == null) return text;
        out.append(text, last, n);
        return out.toString();
    }

    private int encodedDepth = 0;

    private static boolean isEntityRunChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '%' || c == '+' || c == '-' || c == '&' || c == '#' || c == ';';
    }

    /** Valori con entita' HTML (mario&#64;x.it): decodifica, scansiona, sostituisce sul grezzo. */
    private String applyPatternsEntities(String text, boolean limited) {
        StringBuilder out = null;
        int n = text.length(), i = 0, last = 0;
        while (i < n) {
            if (!isEntityRunChar(text.charAt(i))) { i++; continue; }
            int s = i;
            while (i < n && isEntityRunChar(text.charAt(i))) i++;
            String run = text.substring(s, i);
            if (run.indexOf('&') < 0 || !ENTITY.matcher(run).find()) continue;
            String repl = spliceScan(run, entityDecodeMapped(run), t -> applyPatternsRaw(t, limited), "HTML");
            if (repl == null || repl.equals(run)) continue;
            if (out == null) out = new StringBuilder(n + 16);
            out.append(text, last, s).append(repl);
            last = i;
        }
        if (out == null) return text;
        out.append(text, last, n);
        return out.toString();
    }

    private boolean validates(PatternDef pat, String whole) {
        if (pat.validate == null) return true;
        switch (pat.validate) {
            case "luhn":
            case "card": return validCard(whole);
            case "phone": return plausiblePhone(whole);
            case "iban": return validIban(whole);
            case "hex": return validHex(whole);
            case "b64": return validB64(whole);
            case "b64secret": return validB64Secret(whole);
            case "cf": return plausibleCodiceFiscale(whole);
            case "piva": return validPartitaIva(whole);
            case "plate": return !map.looksLikePlaceholder(whole);
            default: return true;
        }
    }

    private static final int[] CF_ODD_VAL = {1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16,
            10, 22, 25, 24, 23};

    /**
     * Codice fiscale, anche omocodico (cifre sostituite da LMNPQRSTUV): carattere
     * di controllo corretto, oppure abbastanza cifre da non essere una parola.
     * Algoritmo ufficiale; se la forma e' specifica si redige comunque:
     * meglio nascondere un CF con un refuso.
     */
    static boolean plausibleCodiceFiscale(String s) {
        String c = s.toUpperCase(Locale.ROOT);
        if (c.length() != 16) return false;
        int sum = 0;
        for (int i = 0; i < 15; i++) {
            char ch = c.charAt(i);
            int v;
            if (i % 2 == 0) { // posizioni dispari (1-based)
                int idx = Character.isDigit(ch) ? ch - '0' : ch - 'A';
                if (idx < 0 || idx > 25) return false;
                v = CF_ODD_VAL[idx];
            } else {
                v = Character.isDigit(ch) ? ch - '0' : ch - 'A';
            }
            sum += v;
        }
        if ((char) ('A' + sum % 26) == c.charAt(15)) return true;
        int digits = 0;
        for (int i = 0; i < 16; i++) if (Character.isDigit(c.charAt(i))) digits++;
        return digits >= 4;
    }

    /** Partita IVA: algoritmo ufficiale del carattere di controllo. */
    static boolean validPartitaIva(String s) {
        String d = s.replaceAll("\\D", "");
        if (d.length() != 11 || d.chars().allMatch(c -> c == '0')) return false;
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            int n = d.charAt(i) - '0';
            if (i % 2 == 1) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
        }
        return (10 - sum % 10) % 10 == d.charAt(10) - '0';
    }

    /** Validazioni sul solo valore (la parte dopo il gruppo conservato). */
    private boolean validatesSecret(PatternDef pat, String secret) {
        if (pat.validate == null || secret.isEmpty()) return true;
        switch (pat.validate) {
            case "username": return plausibleUsername(secret);
            case "aduser": return plausibleAdUser(secret);
            case "personname": return plausiblePersonName(secret);
            case "hostname": return secret.length() >= 3 && !map.looksLikePlaceholder(secret);
            case "pathtoken": return plausiblePathToken(secret);
            default: return true;
        }
    }

    private String applyOnePattern(String text, PatternDef pat) {
        try {
            Matcher m = pat.regex.matcher(text);
            StringBuilder sb = null;
            int last = 0;
            boolean generic = isGeneric(pat);
            while (m.find()) {
                String whole = m.group(0);
                if (whole.isEmpty() || map.looksLikePlaceholder(whole)) continue;
                if (generic && UUID.matcher(whole).matches()) continue;
                int end = m.end();
                if (pat.keepGroup != null && m.groupCount() >= pat.keepGroup && m.group(pat.keepGroup) != null
                        && !validatesSecret(pat, whole.substring(m.end(pat.keepGroup) - m.start()).strip())) {
                    continue;
                }
                if (!validates(pat, whole)) {
                    if (!"iban".equals(pat.validate)) continue;
                    // IBAN seguito da altro testo: riprova accorciando dai gruppi finali
                    String w = whole;
                    int sp;
                    boolean ok = false;
                    while ((sp = w.lastIndexOf(' ')) > 0) {
                        w = w.substring(0, sp);
                        if (validIban(w)) { ok = true; break; }
                    }
                    if (!ok) continue;
                    whole = w;
                    end = m.start() + w.length();
                }
                String replacement;
                if (pat.keepGroup != null && m.groupCount() >= pat.keepGroup && m.group(pat.keepGroup) != null) {
                    String scheme = m.group(pat.keepGroup);
                    String rest = whole.substring(m.end(pat.keepGroup) - m.start());
                    String secret = rest.stripLeading();
                    if (secret.isEmpty() || map.looksLikePlaceholder(secret)) continue;
                    String ws = rest.substring(0, rest.length() - secret.length());
                    // "Bearer" + segreto attaccato: separa; "/users/", "\\" e simili restano attaccati
                    if (ws.isEmpty() && Character.isLetterOrDigit(scheme.charAt(scheme.length() - 1))) ws = " ";
                    replacement = scheme + ws + map.placeholder(secret, pat.prefix);
                } else {
                    replacement = "JWT".equals(pat.prefix) ? maskJwt(whole, "JWT") : map.placeholder(whole, pat.prefix);
                }
                if (replacement.equals(whole)) continue;
                if (sb == null) sb = new StringBuilder(text.length() + 16);
                sb.append(text, last, m.start()).append(replacement);
                last = end;
            }
            if (sb == null) return text;
            sb.append(text, last, text.length());
            return sb.toString();
        } catch (RuntimeException e) {
            return text;
        }
    }

    // -------------------------------------------------------------- validazioni
    public static boolean luhnValid(String number) {
        int n = 0;
        for (int i = 0; i < number.length(); i++) if (Character.isDigit(number.charAt(i))) n++;
        if (n < 12 || n > 19) return false;
        int checksum = 0, idx = 0;
        int parity = n % 2;
        for (int i = 0; i < number.length(); i++) {
            char c = number.charAt(i);
            if (!Character.isDigit(c)) continue;
            int d = c - '0';
            if (idx % 2 == parity) { d *= 2; if (d > 9) d -= 9; }
            checksum += d;
            idx++;
        }
        return checksum % 10 == 0;
    }

    /** Carta di pagamento: Luhn + prefisso e lunghezza di un circuito reale. */
    static boolean validCard(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) sb.append(c);
            else if (c != ' ' && c != '-' && c != '.') return false; // anche 4111.1111.1111.1111
        }
        String d = sb.toString();
        int len = d.length();
        if (len < 12 || len > 19 || !luhnValid(d)) return false;
        if (d.chars().distinct().count() <= 1) return false;
        int p2 = Integer.parseInt(d.substring(0, 2));
        int p3 = Integer.parseInt(d.substring(0, 3));
        int p4 = Integer.parseInt(d.substring(0, 4));
        if (d.charAt(0) == '4') return len == 13 || len == 16 || len == 19;
        if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return len == 16;
        if (p2 == 34 || p2 == 37) return len == 15;
        if (p4 == 6011 || p2 == 65 || (p3 >= 644 && p3 <= 649)) return len >= 16;
        if (p4 >= 3528 && p4 <= 3589) return len >= 16;
        if ((p3 >= 300 && p3 <= 305) || p2 == 36 || p2 == 38 || p2 == 39) return len >= 14;
        if (p2 == 62) return len >= 16;
        if (p2 == 50 || (p2 >= 56 && p2 <= 69)) return len >= 12;
        return false;
    }

    /** IBAN: lunghezza plausibile e controllo mod 97. */
    static boolean validIban(String s) {
        String v = s.replace(" ", "").toUpperCase(Locale.ROOT);
        if (v.length() < 15 || v.length() > 34) return false;
        if (!Character.isLetter(v.charAt(0)) || !Character.isLetter(v.charAt(1))
                || !Character.isDigit(v.charAt(2)) || !Character.isDigit(v.charAt(3))) return false;
        String r = v.substring(4) + v.substring(0, 4);
        int mod = 0;
        for (int i = 0; i < r.length(); i++) {
            char c = r.charAt(i);
            int val;
            if (Character.isDigit(c)) val = c - '0';
            else if (c >= 'A' && c <= 'Z') val = c - 'A' + 10;
            else return false;
            mod = val >= 10 ? (mod * 100 + val) % 97 : (mod * 10 + val) % 97;
        }
        return mod == 1;
    }

    /** Telefono: esclude date, versioni, timestamp e numeri generici. */
    static boolean plausiblePhone(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (Character.isDigit(s.charAt(i))) n++;
        boolean plus = s.startsWith("+");
        if (n < 8 || n > 15) return false;
        if (DATE_LIKE.matcher(s).matches()) return false;
        if (s.indexOf('.') >= 0 && !plus) return false;
        boolean sep = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ' ' || c == '-' || c == '(' || c == ')') { sep = true; break; }
        }
        String digits = s.replaceAll("\\D", "");
        char first = digits.charAt(0);
        if (plus) return true;
        if (!sep) {
            if ((n == 9 || n == 10) && (first == '3' || first == '0')) return true;
            if ((n == 11 || n == 12) && digits.startsWith("39")) return true;
            return n >= 12 && n <= 14 && digits.startsWith("00");
        }
        if (US_PHONE.matcher(s).matches()) return true;
        return n <= 12 && (first == '0' || first == '3' || s.charAt(0) == '(');
    }

    private static boolean validHex(String s) {
        boolean letter = false, digit = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) digit = true;
            else letter = true;
        }
        return letter && digit;
    }

    private static boolean validB64(String whole) {
        String s = whole.replace("=", "");
        boolean up = false, low = false, digit = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') up = true;
            else if (c >= 'a' && c <= 'z') low = true;
            else if (c >= '0' && c <= '9') digit = true;
        }
        if (!digit || !(up || low)) return false;
        return (up && low) || s.length() >= 40;
    }

    private static boolean validB64Secret(String whole) {
        String s = whole.replace("=", "");
        if (s.startsWith("/") || s.contains("//")) return false;
        boolean up = false, low = false, digit = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') up = true;
            else if (c >= 'a' && c <= 'z') low = true;
            else if (c >= '0' && c <= '9') digit = true;
        }
        if (!(up && low && digit)) return false;
        if (s.indexOf('+') >= 0 || whole.endsWith("=")) return true;
        if (s.indexOf('/') < 0) return false;
        String[] segs = s.split("/");
        if (segs.length > 4) return false;
        for (String g : segs) if (g.length() < 6) return false;
        return true;
    }

    // -------------------------------------------------------------- URL codec
    private static String urlDecode(String s) {
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String urlEncode(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    // ------------------------------------------------------------ util regex
    private static String regexReplace(String text, Pattern p,
                                       java.util.function.Function<Matcher, String> repl) {
        Matcher m = p.matcher(text);
        StringBuilder sb = null;
        int last = 0;
        while (m.find()) {
            String r = repl.apply(m);
            if (r.equals(m.group())) continue;
            if (sb == null) sb = new StringBuilder(text.length() + 16);
            sb.append(text, last, m.start()).append(r);
            last = m.end();
        }
        if (sb == null) return text;
        sb.append(text, last, text.length());
        return sb.toString();
    }

    // ------------------------------------------------------ Transfer chunked
    /**
     * Body chunked scomposto senza perdere nulla: righe di dimensione originali,
     * dati, separatori, chunk finale con eventuali trailer e soprattutto quello che
     * segue il chunk finale (in una request smuggling e' la richiesta contrabbandata).
     */
    private static final class Chunked {
        final List<String[]> chunks = new ArrayList<>(); // {riga dimensione, dati, separatore}
        String last = "";  // "0" + trailer + riga vuota
        String tail = "";  // dati dopo il chunk finale

        String data() {
            StringBuilder sb = new StringBuilder();
            for (String[] c : chunks) sb.append(c[1]);
            return sb.toString();
        }

        static Chunked parse(String body) {
            if (body == null || body.isEmpty()) return null;
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            Chunked c = new Chunked();
            int i = 0, n = b.length;
            while (i < n) {
                int j = indexOfByte(b, (byte) '\n', i);
                if (j < 0) return null;
                int lineEnd = (j > i && b[j - 1] == '\r') ? j - 1 : j;
                String token = new String(b, i, lineEnd - i, StandardCharsets.ISO_8859_1).split(";", 2)[0].trim();
                if (!token.matches("[0-9A-Fa-f]{1,15}")) return null;
                long size;
                try { size = Long.parseLong(token, 16); } catch (Exception e) { return null; }
                if (size == 0) {
                    // chunk finale + trailer fino alla riga vuota
                    int k = j + 1;
                    while (k < n) {
                        int e = indexOfByte(b, (byte) '\n', k);
                        if (e < 0) { k = n; break; }
                        boolean empty = e == k || (e == k + 1 && b[k] == '\r');
                        k = e + 1;
                        if (empty) break;
                    }
                    c.last = new String(b, i, k - i, StandardCharsets.UTF_8);
                    c.tail = new String(b, k, n - k, StandardCharsets.UTF_8);
                    break;
                }
                int ds = j + 1;
                if (size > n - ds) return null;
                int de = ds + (int) size;
                int se = de;
                if (se + 1 < n && b[se] == '\r' && b[se + 1] == '\n') se += 2;
                else if (se < n && b[se] == '\n') se += 1;
                c.chunks.add(new String[]{new String(b, i, ds - i, StandardCharsets.UTF_8),
                        new String(b, ds, de - ds, StandardCharsets.UTF_8),
                        new String(b, de, se - de, StandardCharsets.UTF_8)});
                i = se;
            }
            if (c.chunks.isEmpty() && c.last.isEmpty()) return null;
            // un confine di chunk dentro un carattere multibyte non si puo' ricomporre: rinuncia
            StringBuilder all = new StringBuilder();
            for (String[] ch : c.chunks) all.append(ch[0]).append(ch[1]).append(ch[2]);
            all.append(c.last).append(c.tail);
            return all.toString().equals(body) ? c : null;
        }
    }

    /**
     * Rimette il body anonimizzato nel framing ORIGINALE (stesse righe di
     * dimensione, come per Content-Length): la de-anonimizzazione ricostruisce
     * il messaggio byte per byte. Con piu' chunk ogni pezzo si anonimizza da solo
     * e si accetta il risultato solo se e' identico all'anonimizzazione del body
     * intero (cosi' un segreto a cavallo di due chunk non puo' sfuggire);
     * altrimenti un unico chunk.
     */
    private String reframe(Chunked f, String anonBody, String ct, String nl) {
        String last = f.last.isEmpty() ? "" : scanSecrets(f.last);
        String tail = f.tail.isEmpty() ? "" : anonymizeTail(f.tail);
        if (f.chunks.size() == 1) {
            String[] c = f.chunks.get(0);
            return c[0] + anonBody + c[2] + last + tail;
        }
        if (f.chunks.size() > 1 && f.chunks.size() <= 512) {
            SubstitutionMap snap = map.snapshot();
            List<String> knownSnap = new ArrayList<>(knownValues);
            int scannedSnap = knownScanned;
            Pattern reSnap = knownValuesRe;
            StringBuilder parts = new StringBuilder(), framed = new StringBuilder();
            try {
                for (String[] c : f.chunks) {
                    String a = anonymizeBody(c[1], ct);
                    parts.append(a);
                    framed.append(c[0]).append(a).append(c[2]);
                }
            } catch (RuntimeException e) {
                parts.setLength(0);
            }
            if (parts.toString().equals(anonBody)) return framed + last + tail;
            map.restore(snap);
            knownValues.clear();
            knownValues.addAll(knownSnap);
            knownScanned = scannedSnap;
            knownValuesRe = reSnap;
        }
        String one = rechunk(anonBody, nl);
        return (f.chunks.isEmpty() ? (last.isEmpty() ? one : last) : one) + tail;
    }

    /** Dati dopo il chunk finale (request smuggling): spesso un'altra richiesta HTTP. */
    private String anonymizeTail(String tail) {
        try {
            if (tail.trim().isEmpty()) return tail;
            String s = anonymizeStructured(tail);
            if (Anonymizer.deanonymize(s, map.reverseMap()).equals(tail)) return s;
        } catch (RuntimeException ignored) {
        }
        return scanSecrets(tail);
    }
    /** Ri-assembla un body chunked (in OTTETTI, corretto anche con multibyte). */
    private static String dechunk(String body) {
        if (body == null || body.isEmpty()) return null;
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        int i = 0, n = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        boolean sawTerm = false;
        while (i < n) {
            int j = indexOfByte(data, (byte) '\n', i);
            if (j < 0) return null;
            int lineEnd = (j > i && data[j - 1] == '\r') ? j - 1 : j;
            String line = new String(data, i, lineEnd - i, StandardCharsets.ISO_8859_1);
            String sizeToken = line.split(";", 2)[0].trim();
            if (!sizeToken.matches("[0-9A-Fa-f]{1,15}")) return null;
            long size;
            try { size = Long.parseLong(sizeToken, 16); } catch (Exception e) { return null; }
            i = j + 1;
            if (size == 0) { sawTerm = true; break; }
            if (size > n - i) return null;
            out.write(data, i, (int) size);
            i += (int) size;
            if (i + 1 < n && data[i] == '\r' && data[i + 1] == '\n') i += 2;
            else if (i < n && data[i] == '\n') i += 1;
        }
        if (!sawTerm && out.size() == 0) return null;
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static int indexOfByte(byte[] a, byte b, int from) {
        for (int i = from; i < a.length; i++) if (a[i] == b) return i;
        return -1;
    }

    /** Ri-codifica come chunked in un unico chunk con dimensione (ottetti) corretta. */
    private static String rechunk(String text, String nl) {
        if (nl == null || nl.isEmpty()) nl = "\r\n";
        if (text.isEmpty()) return "0" + nl + nl;
        String size = Integer.toHexString(text.getBytes(StandardCharsets.UTF_8).length);
        return size + nl + text + nl + "0" + nl + nl;
    }

    // ------------------------------------------------------ multipart/form-data
    private static String extractBoundary(String ct) {
        if (ct == null) return null;
        Matcher m = Pattern.compile("boundary=(?:\"([^\"]+)\"|([^;,\\s]+))", Pattern.CASE_INSENSITIVE).matcher(ct);
        if (!m.find()) return null;
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    private static String detectBoundaryFromBody(String body) {
        if (body == null) return null;
        Matcher m = Pattern.compile("(?m)^--([^\\r\\n]{1,200})").matcher(body);
        if (!m.find()) return null;
        String cand = m.group(1).replaceAll("\\s+$", "");
        if (cand.endsWith("--")) cand = cand.substring(0, cand.length() - 2);
        return cand.isEmpty() ? null : cand;
    }

    private String anonMultipartBody(String body, String boundary) {
        String delim = "--" + boundary;
        if (!body.contains(delim)) return null;
        String nl = body.contains("\r\n") ? "\r\n" : "\n";
        String[] segments = body.split(Pattern.quote(delim), -1);
        List<String> out = new ArrayList<>();
        for (String seg : segments) {
            if (seg.isEmpty() || seg.equals("--") || seg.equals("--" + nl) || seg.equals(nl)
                    || seg.stripLeading().startsWith("--")) {
                out.add(scanSecrets(seg));
            } else {
                out.add(anonMultipartPart(seg, nl));
            }
        }
        return String.join(delim, out);
    }

    private String anonMultipartPart(String seg, String nl) {
        String sep = nl + nl;
        int idx = seg.indexOf(sep);
        if (idx < 0) return scanSecrets(seg);
        String head = seg.substring(0, idx);
        String content = seg.substring(idx + sep.length());
        String trailing = "";
        if (content.endsWith(nl)) {
            trailing = nl;
            content = content.substring(0, content.length() - nl.length());
        }

        String fieldName = "";
        Matcher cd = Pattern.compile("content-disposition:[^\\r\\n]*", Pattern.CASE_INSENSITIVE).matcher(head);
        if (cd.find()) {
            Matcher fn = Pattern.compile("(?<![\\w*])name=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE).matcher(cd.group());
            if (fn.find()) fieldName = fn.group(1);
        }
        String partCt = "";
        Matcher pct = Pattern.compile("content-type:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE).matcher(head);
        if (pct.find()) partCt = pct.group(1).trim();
        String cte = "";
        Matcher mcte = Pattern.compile("content-transfer-encoding:\\s*([^\\r\\n;]+)", Pattern.CASE_INSENSITIVE).matcher(head);
        if (mcte.find()) cte = mcte.group(1).trim().toLowerCase(Locale.ROOT);

        head = regexReplace(head, Pattern.compile("(filename=\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2), "FILENAME") + m.group(3));
        head = regexReplace(head, Pattern.compile("(filename\\*=)([^\\r\\n;]+)", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2).trim(), "FILENAME"));
        head = regexReplace(head, Pattern.compile("(filename=)(?!\")([^;\\r\\n]+)", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2).trim(), "FILENAME"));

        StringBuilder hb = new StringBuilder();
        String[] hlines = head.split(Pattern.quote(nl), -1);
        for (int i = 0; i < hlines.length; i++) {
            if (i > 0) hb.append(nl);
            String low = hlines[i].toLowerCase(Locale.ROOT);
            if (low.startsWith("content-type:") || low.startsWith("content-disposition:")) hb.append(hlines[i]);
            else hb.append(scanSecrets(hlines[i]));
        }
        head = hb.toString();

        String prefix = fieldName.isEmpty() ? null : queryKeyPrefix(fieldName);
        String newContent;
        if (prefix != null && !content.trim().isEmpty()) {
            newContent = map.placeholder(content.trim(), prefix);
        } else if (cte.equals("base64") || cte.equals("quoted-printable")) {
            newContent = anonEncodedContent(content, cte, partCt);
        } else {
            newContent = partCt.isEmpty() ? scanValue(content, fieldName, 0) : anonymizeBody(content, partCt);
        }
        return head + sep + newContent + trailing;
    }

    private String anonEncodedContent(String content, String cte, String partCt) {
        byte[] raw;
        try {
            raw = cte.equals("base64") ? Base64.getMimeDecoder().decode(content) : qpDecode(content);
        } catch (Exception e) {
            return scanSecrets(content);
        }
        String text = decodeUtf8Strict(raw);
        if (text == null) {
            return map.placeholder(content.trim(), "FILE");
        }
        String anon = anonymizeBody(text, partCt);
        if (anon.equals(text)) return content;
        try {
            if (cte.equals("base64")) return Base64.getEncoder().encodeToString(anon.getBytes(StandardCharsets.UTF_8));
            return qpEncode(anon);
        } catch (Exception e) {
            return anon;
        }
    }

    private static String decodeUtf8Strict(byte[] b) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return dec.decode(ByteBuffer.wrap(b)).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] qpDecode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0, n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (c == '=' && i + 2 < n) {
                char a = s.charAt(i + 1), b = s.charAt(i + 2);
                if (a == '\r' && b == '\n') { i += 3; continue; }
                int hi = Character.digit(a, 16), lo = Character.digit(b, 16);
                if (hi >= 0 && lo >= 0) { out.write((hi << 4) | lo); i += 3; continue; }
            }
            if (c == '=' && i + 1 < n && s.charAt(i + 1) == '\n') { i += 2; continue; }
            out.write(c & 0xFF);
            i++;
        }
        return out.toByteArray();
    }

    private static String qpEncode(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (byte bb : bytes) {
            int v = bb & 0xFF;
            if (v == '=') sb.append("=3D");
            else if (v == ' ') sb.append(' ');
            else if (v >= 33 && v <= 126) sb.append((char) v);
            else sb.append(String.format("=%02X", v));
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- HTML/XML
    private String anonHtml(String body) {
        // attributi dei tag: name/id sensibile -> value/content; attributo sensibile; URL
        String out = regexReplace(body, TAG, m -> rewriteTag(m.group(0)));
        // testo sotto un tag dal nome sensibile: <password>...</password>
        out = regexReplace(out, ELEM_TEXT, m -> {
            String prefix = sensitiveKeyPrefix(m.group(2));
            String txt = m.group(3);
            if (prefix != null && !txt.trim().isEmpty()) {
                return m.group(1) + map.placeholder(txt.trim(), prefix) + m.group(4);
            }
            return m.group(0);
        });
        // testo, script, commenti, CDATA (gli hash SRI restano intatti)
        List<String> saved = new ArrayList<>();
        Matcher im = SRI_ATTR.matcher(out);
        StringBuilder sb = null;
        int last = 0;
        while (im.find()) {
            if (sb == null) sb = new StringBuilder(out.length());
            sb.append(out, last, im.start()).append('\uE002').append(saved.size()).append('\uE003');
            saved.add(im.group());
            last = im.end();
        }
        if (sb != null) out = sb.append(out, last, out.length()).toString();
        out = scanSecrets(out);
        for (int i = 0; i < saved.size(); i++) out = out.replace("\uE002" + i + "\uE003", saved.get(i));
        return out;
    }

    private static final Pattern SRI_ATTR = Pattern.compile(
            "\\bintegrity\\s*=\\s*([\"'])sha(?:256|384|512)-[A-Za-z0-9+/=\\s-]{1,1024}\\1", Pattern.CASE_INSENSITIVE);

    private String rewriteTag(String tag) {
        if (tag.indexOf('=') < 0) return tag;
        Matcher am = ATTR.matcher(tag);
        String nameVal = null, typeVal = null;
        while (am.find()) {
            String an = am.group(1).toLowerCase(Locale.ROOT);
            String av = attrValue(am);
            if (nameVal == null && NAME_ATTRS.contains(an) && !av.isEmpty()) nameVal = av;
            if (an.equals("type")) typeVal = av;
        }
        final String namePrefix = nameVal == null ? null : queryKeyPrefix(nameVal);
        final boolean pwdInput = "password".equalsIgnoreCase(typeVal);
        return regexReplace(tag, ATTR, m -> {
            String an = m.group(1).toLowerCase(Locale.ROOT);
            String av = attrValue(m);
            if (av.isEmpty()) return m.group(0);
            String nv;
            if (an.equals("value") || an.equals("content")) {
                if (namePrefix != null) nv = map.placeholder(av, namePrefix);
                else if (pwdInput && an.equals("value")) nv = map.placeholder(av, "SECRET");
                else nv = scanSecrets(av);
            } else if (URL_ATTRS.contains(an)) {
                nv = scanUrlValue(av);
            } else if (STRUCTURAL_ATTRS.contains(an) || an.startsWith("aria-") || an.startsWith("xmlns")
                    || an.startsWith("on")) {
                nv = an.startsWith("on") ? scanSecrets(av) : av;
            } else {
                String p = sensitiveKeyPrefix(an);
                nv = p != null ? map.placeholder(av, p) : scanSecrets(av);
            }
            if (nv.equals(av)) return m.group(0);
            String q = m.group(3) != null ? "\"" : m.group(4) != null ? "'" : "";
            return m.group(1) + m.group(2) + q + nv + q;
        });
    }

    private static String attrValue(Matcher m) {
        if (m.group(3) != null) return m.group(3);
        if (m.group(4) != null) return m.group(4);
        return m.group(5) != null ? m.group(5) : "";
    }

    // ---------------------------------------------------------------- GraphQL
    private static final Pattern GQL_MARKERS =
            Pattern.compile("\\b(query|mutation|subscription|fragment)\\b");

    private static boolean looksLikeGraphql(String text) {
        if (!text.contains("{")) return false;
        return GQL_MARKERS.matcher(text).find() || (text.contains("(") && text.contains(":"));
    }

    /**
     * Documento GraphQL analizzato con un lexer (specifica GraphQL): keyword,
     * nomi di operazioni, variabili, tipi, campi, argomenti, alias, direttive e
     * frammenti restano intatti; vengono trattati SOLO i valori letterali
     * (stringhe e block string) e i commenti. Un argomento dal nome sensibile
     * (password: "...") viene mascherato per intero.
     */
    private String anonGraphqlDoc(String doc) {
        StringBuilder out = new StringBuilder(doc.length() + 16);
        int n = doc.length(), i = 0;
        String lastName = null, argKey = null;
        while (i < n) {
            char c = doc.charAt(i);
            if (c == '#') { // commento fino a fine riga
                int j = doc.indexOf('\n', i);
                if (j < 0) j = n;
                out.append(scanSecrets(doc.substring(i, j)));
                i = j;
                continue;
            }
            if (doc.startsWith("\"\"\"", i)) { // block string
                int j = i + 3;
                while (j < n && !doc.startsWith("\"\"\"", j)) {
                    j += (doc.charAt(j) == '\\' && doc.startsWith("\"\"\"", j + 1)) ? 4 : 1;
                }
                boolean closed = j < n;
                String content = doc.substring(i + 3, Math.min(j, n));
                out.append("\"\"\"").append(gqlStringValue(content, argKey, false)).append(closed ? "\"\"\"" : "");
                i = closed ? j + 3 : n;
                continue;
            }
            if (c == '"') { // stringa
                int j = i + 1;
                while (j < n) {
                    char d = doc.charAt(j);
                    if (d == '\\') { j += 2; continue; }
                    if (d == '"' || d == '\n') break;
                    j++;
                }
                if (j > n) j = n;
                boolean closed = j < n && doc.charAt(j) == '"';
                String raw = doc.substring(i + 1, Math.min(j, n));
                out.append('"').append(gqlStringValue(raw, argKey, true)).append(closed ? "\"" : "");
                i = closed ? j + 1 : Math.min(j, n);
                continue;
            }
            if (Character.isLetter(c) || c == '_' || c == '$' || c == '@') { // nome, $variabile, @direttiva
                int j = i + 1;
                while (j < n && (Character.isLetterOrDigit(doc.charAt(j)) || doc.charAt(j) == '_')) j++;
                lastName = doc.substring(i, j);
                out.append(lastName);
                i = j;
                continue;
            }
            if (c == ':') {
                argKey = lastName == null ? null : lastName.replaceFirst("^[$@]", "");
            } else if (c == '{' || c == '}' || c == '(' || c == ')') {
                argKey = null;
                lastName = null;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    private String gqlStringValue(String raw, String argKey, boolean escapes) {
        if (raw.isEmpty()) return raw;
        String prefix = argKey == null ? null : sensitiveKeyPrefix(argKey);
        boolean esc = escapes && raw.indexOf('\\') >= 0;
        String v = esc ? decodeJsonString(raw) : raw;
        if (prefix != null) {
            String token = map.placeholder(v, prefix);
            if (token.equals(v)) return raw;
            return esc ? map.variant(token, raw, "JSON") : token;
        }
        if (!esc) return scanSecrets(raw);
        String s = spliceScan(raw, jsonDecodeMapped(raw), this::scanSecrets, "JSON");
        return s != null ? s : raw;
    }

    // ------------------------------------------- identita' del cliente e contesto
    //
    // Un pentester non deve mai far uscire il nome del cliente ne' la topologia
    // interna. Il dominio diventa HOST_n, ma il suo nome base ("acme-corp") compare
    // anche in path, header custom, package Java, testo libero. L'ultima passata
    // lavora sull'intero messaggio gia' anonimizzato e sostituisce ovunque:
    //  - il nome dell'organizzazione (dall'header Host e dai termini dell'utente) -> ORG_n
    //  - host, nomi e username gia' scoperti altrove, rimasti in chiaro per l'ordine
    //    di elaborazione (es. path della start line elaborato prima dell'header Host)
    //  - password nei commenti HTML / JS ("admin / Adm1nPwd!")
    //
    // Le liste che seguono (servizi terzi, suffissi pubblici, chiavi di host, parole
    // che non sono nomi...) stanno nella sezione "context" di sensitive_patterns.json.

    /** Nome base dell'organizzazione da un host ("app.acme-corp.co.uk:443" -> "acme-corp"). */
    String orgLabel(String hostValue) {
        if (hostValue == null) return null;
        String h = hostValue.trim().toLowerCase(Locale.ROOT);
        if (h.isEmpty() || h.startsWith("[")) return null;
        int colon = h.indexOf(':');
        if (colon >= 0) h = h.substring(0, colon);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (isIp(h)) return null;
        String[] labels = h.split("\\.");
        if (labels.length < 2) return null;
        int n = labels.length;
        String label = (n >= 3 && cfg.twoLevelSuffixes.contains(labels[n - 2] + "." + labels[n - 1]))
                ? labels[n - 3] : labels[n - 2];
        if (!label.matches("[a-z0-9][a-z0-9-]{1,62}") || label.chars().allMatch(Character::isDigit)) return null;
        if (cfg.orgStop.contains(label)) return null;
        // nomi corti senza trattini/cifre sono spesso parole comuni ("data", "poste"):
        // si possono aggiungere a mano come termini del cliente
        boolean marked = label.indexOf('-') >= 0 || label.chars().anyMatch(Character::isDigit);
        if (label.length() < cfg.orgMinLength && !marked) return null;
        return label;
    }

    /** Forme con cui un nome compare nel testo: "acme-corp" -> acme-corp, acmecorp, acme_corp, acme corp, acme.corp. */
    static List<String> orgVariants(String term) {
        List<String> out = new ArrayList<>();
        if (term == null) return out;
        String t = term.trim().toLowerCase(Locale.ROOT);
        if (t.length() < 3) return out;
        out.add(t);
        String[] words = t.split("[\\s._-]+");
        List<String> w = new ArrayList<>();
        for (String s : words) if (!s.isEmpty()) w.add(s);
        if (w.size() > 1 && w.size() <= 6) {
            for (String sep : new String[]{"", "-", "_", " ", "."}) {
                String v = String.join(sep, w);
                if (v.length() >= 4 && !out.contains(v)) out.add(v);
            }
        }
        return out;
    }

    private static final Set<String> CONTEXT_TYPES = Set.of("HOST", "ORG", "NAME", "USERNAME");

    /** Ultima passata sull'intero messaggio (vedi sopra). Reversibile come le altre. */
    private String contextPass(String text) {
        if (text == null || text.isEmpty()) return text;
        text = maskCommentCredentials(text);
        text = maskNamedValues(text);
        // segreti, token e nomi trovati piu' avanti nel messaggio (es. sotto la chiave
        // "password") vanno nascosti anche dove comparivano prima, in chiaro
        text = replaceKnownValues(text);
        Map<String, String> terms = new java.util.LinkedHashMap<>();
        for (String t : ov.orgTerms) for (String v : orgVariants(t)) terms.putIfAbsent(v, "ORG");
        for (String t : map.orgTerms()) for (String v : orgVariants(t)) terms.putIfAbsent(v, "ORG");
        for (SubstitutionMap.Entry e : map.entries()) {
            if (!CONTEXT_TYPES.contains(e.type)) continue;
            String o = e.original;
            if (o == null || o.length() > 200 || map.looksLikePlaceholder(o)) continue;
            boolean plain = o.matches("[\\p{L}0-9][\\p{L}0-9 ._@'-]*[\\p{L}0-9]");
            if (!plain) continue;
            switch (e.type) {
                case "HOST":
                    if (o.length() >= 4 && !isIp(o)) terms.putIfAbsent(o.toLowerCase(Locale.ROOT), "HOST");
                    break;
                case "ORG":
                    if (o.length() >= 3) terms.putIfAbsent(o.toLowerCase(Locale.ROOT), "ORG");
                    break;
                case "NAME":
                    // nome e cognome: un nome di battesimo da solo e' troppo comune
                    if (o.length() >= 6 && o.indexOf(' ') > 0) {
                        terms.putIfAbsent(o.toLowerCase(Locale.ROOT).replaceAll("\\s+", " "), "NAME");
                    }
                    break;
                default: // USERNAME: solo forme distintive (m.rossi, mrossi85, m_rossi)
                    if (o.length() >= 5 && o.matches(".*[._0-9].*") && o.indexOf(' ') < 0) {
                        terms.putIfAbsent(o.toLowerCase(Locale.ROOT), "USERNAME");
                    }
            }
        }
        if (terms.isEmpty()) return text;
        // indice per prima parola: scansione lineare anche con migliaia di host noti
        // (una regex con migliaia di alternative diventa quadratica)
        Map<String, List<String>> byFirstWord = new java.util.HashMap<>();
        for (String t : terms.keySet()) {
            String fw = firstWord(t, 0);
            if (fw.isEmpty()) continue;
            byFirstWord.computeIfAbsent(fw, k -> new ArrayList<>()).add(t);
        }
        for (List<String> l : byFirstWord.values()) l.sort((a, b) -> Integer.compare(b.length(), a.length()));
        StringBuilder out = null;
        int n = text.length(), i = 0, last = 0;
        while (i < n) {
            char c = text.charAt(i);
            // stessi confini della de-anonimizzazione: ORG_1 deve tornare indietro esatto
            if (!Character.isLetterOrDigit(c) || (i > 0 && isWordBoundaryChar(text.charAt(i - 1)))) { i++; continue; }
            String fw = firstWord(text, i);
            List<String> cands = byFirstWord.get(fw);
            String hit = null;
            int hitEnd = -1;
            if (cands != null) {
                for (String t : cands) {
                    int e = matchFlexible(text, i, t);
                    if (e > 0 && (e == n || !isWordBoundaryChar(text.charAt(e)))) { hit = t; hitEnd = e; break; }
                }
            }
            if (hit == null) { i += Math.max(1, fw.length()); continue; }
            String surface = text.substring(i, hitEnd);
            String repl = exactPlaceholder(surface, terms.get(hit));
            boolean underscoreBefore = i > 0 && text.charAt(i - 1) == '_';
            boolean underscoreAfter = hitEnd < n && text.charAt(hitEnd) == '_';
            if ((underscoreBefore || underscoreAfter) && !repl.equals(surface)) {
                // "acmecorp_sid", "db_acmecorp": l'underscore lega la parola, quindi un
                // segnaposto a meta' non tornerebbe indietro (confine \\w). Si sostituisce
                // la parola intera con una variante della stessa radice: ORG_1_W.
                int ws = i, we = hitEnd;
                while (ws > 0 && isIdentChar(text.charAt(ws - 1))) ws--;
                while (we < n && isIdentChar(text.charAt(we))) we++;
                if (ws < last) { i = hitEnd; continue; }
                String word = text.substring(ws, we);
                if (map.looksLikePlaceholder(word) || LITERAL_PLACEHOLDER.matcher(word).find()) { i = hitEnd; continue; }
                String wph = map.variant(repl, word, "W");
                if (out == null) out = new StringBuilder(n + 32);
                out.append(text, last, ws).append(wph);
                last = we;
                i = we;
                continue;
            }
            if (!repl.equals(surface)) {
                if (out == null) out = new StringBuilder(n + 32);
                out.append(text, last, i).append(repl);
                last = hitEnd;
            }
            i = hitEnd;
        }
        if (out == null) return text;
        out.append(text, last, n);
        return out.toString();
    }

    /**
     * Confine di parola per i termini di contesto: solo lettere e cifre ASCII, cosi'
     * il nome del cliente si trova anche in "acmecorp_sid" (vedi la variante _W).
     */
    /**
     * Confronto senza maiuscole in cui uno spazio del termine vale una sequenza di
     * spazi/tab del testo ("mario  rossi", "Mario\tRossi"). Fine del match o -1.
     */
    private static int matchFlexible(String text, int from, String term) {
        int i = from, j = 0, n = text.length();
        while (j < term.length()) {
            char tc = term.charAt(j);
            if (tc == ' ') {
                int k = i;
                while (k < n && (text.charAt(k) == ' ' || text.charAt(k) == '\t')) k++;
                if (k == i) return -1;
                i = k;
                j++;
                continue;
            }
            if (i >= n) return -1;
            char c = text.charAt(i);
            if (c != tc && Character.toLowerCase(c) != Character.toLowerCase(tc)
                    && Character.toUpperCase(c) != Character.toUpperCase(tc)) return -1;
            i++;
            j++;
        }
        return i;
    }

    private static boolean isWordBoundaryChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }

    private static boolean isIdentChar(char c) {
        return isWordBoundaryChar(c) || c == '_';
    }

    /** Prima parola (lettere/cifre) a partire da from, in minuscolo. */
    private static String firstWord(String s, int from) {
        int j = from;
        while (j < s.length() && Character.isLetterOrDigit(s.charAt(j))) j++;
        return s.substring(from, j).toLowerCase(Locale.ROOT);
    }

    /** Placeholder per una forma precisa: stessa radice, variante _ALT se la grafia differisce. */
    private String exactPlaceholder(String surface, String prefix) {
        String ph = map.placeholder(surface, prefix);
        if (ph == null || ph.equals(surface)) return surface; // escluso dall'utente
        String orig = map.originalOf(ph);
        if (orig != null && !orig.equals(surface)) ph = map.variant(ph, surface, "ALT");
        return ph;
    }

    // --- coppie nome/valore in campi separati (Spring Actuator /env, liste di
    //     impostazioni, header serializzati): il nome sensibile sta in "name", il
    //     segreto in "value" ---
    private static final String NV_NAME = "(?:name|key|property|propertyName|param|parameter|field|header|setting|variable|var|label|id)";
    private static final String NV_VALUE = "(?:value|val|data|content|secret|text)";
    private static final Pattern NV_NAME_FIRST = Pattern.compile(
            "(\"" + NV_NAME + "\"\\s*:\\s*\")([^\"\\\\]{1,200})(\"\\s*,\\s*\"" + NV_VALUE + "\"\\s*:\\s*\")([^\"\\\\]{0,4000}(?:\\\\.[^\"\\\\]{0,4000}){0,20})(\")");
    private static final Pattern NV_VALUE_FIRST = Pattern.compile(
            "(\"" + NV_VALUE + "\"\\s*:\\s*\")([^\"\\\\]{0,4000}(?:\\\\.[^\"\\\\]{0,4000}){0,20})(\"\\s*,\\s*\"" + NV_NAME + "\"\\s*:\\s*\")([^\"\\\\]{1,200})(\")");

    private String maskNamedValues(String text) {
        if (text.indexOf('"') < 0) return text;
        text = regexReplace(text, NV_NAME_FIRST, m -> {
            String v = namedValue(m.group(2), m.group(4));
            return v == null ? m.group() : m.group(1) + m.group(2) + m.group(3) + v + m.group(5);
        });
        return regexReplace(text, NV_VALUE_FIRST, m -> {
            String v = namedValue(m.group(4), m.group(2));
            return v == null ? m.group() : m.group(1) + v + m.group(3) + m.group(4) + m.group(5);
        });
    }

    /** Placeholder per il valore se il nome accanto e' sensibile, altrimenti null. */
    private String namedValue(String name, String value) {
        if (value.isEmpty() || skipValue(value) || map.looksLikePlaceholder(value) || isPreservedKey(name)) return null;
        if (value.chars().allMatch(c -> c == '*')) return null; // gia' mascherato dal server ("******")
        String prefix = sensitiveKeyPrefix(name);
        if (prefix == null && isHostKey(name) && looksLikeInternalHost(value)) prefix = "HOST";
        if (prefix == null) return null;
        String ph = map.placeholder(value, prefix);
        return ph.equals(value) ? null : ph;
    }

    private static final Pattern HTML_COMMENT = Pattern.compile("<!--([\\s\\S]{0,8000}?)-->");
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*([\\s\\S]{0,8000}?)\\*/");
    /** "utente / password", "utente:password", "utente | password" dentro un commento. */
    private static final Pattern COMMENT_PAIR = Pattern.compile(
            "(?<![\\w@.-])([A-Za-z][\\w.@-]{1,40})([ \\t]*[/:|][ \\t]*)([^\\s<>\"'`]{6,64})");

    /** Password lasciate nei commenti (HTML e /* *\/): il valore diventa SECRET_n. */
    private String maskCommentCredentials(String text) {
        if (text.indexOf("<!--") < 0 && text.indexOf("/*") < 0) return text;
        java.util.function.Function<Matcher, String> inComment = cm -> {
            String body = cm.group(1);
            boolean hint = hasCredentialHint(body);
            String nb = regexReplace(body, COMMENT_PAIR, pm -> {
                String user = pm.group(1), secret = pm.group(3);
                if (!hint && !cfg.commonUsers.contains(user.toLowerCase(Locale.ROOT))) return pm.group();
                if (secret.contains("://") || secret.startsWith("/") || map.looksLikePlaceholder(secret)
                        || charClasses(secret) < 3) return pm.group();
                String ph = map.placeholder(secret, "SECRET");
                return ph.equals(secret) ? pm.group() : user + pm.group(2) + ph;
            });
            if (nb.equals(body)) return cm.group();
            String whole = cm.group();
            int bs = cm.start(1) - cm.start();
            return whole.substring(0, bs) + nb + whole.substring(bs + body.length());
        };
        text = regexReplace(text, HTML_COMMENT, inComment::apply);
        text = regexReplace(text, BLOCK_COMMENT, inComment::apply);
        return text;
    }

    private boolean hasCredentialHint(String body) {
        String low = body.toLowerCase(Locale.ROOT);
        for (String h : cfg.credentialHints) if (low.contains(h)) return true;
        return false;
    }

    private static int charClasses(String s) {
        boolean lo = false, up = false, di = false, sy = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLowerCase(c)) lo = true;
            else if (Character.isUpperCase(c)) up = true;
            else if (Character.isDigit(c)) di = true;
            else sy = true;
        }
        return (lo ? 1 : 0) + (up ? 1 : 0) + (di ? 1 : 0) + (sy ? 1 : 0);
    }

    // --- hostname interni riconosciuti dalla chiave ("db_host": "srv-sql-prod01") ---
        private static final Pattern HOSTISH = Pattern.compile(
            "[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\\.[A-Za-z0-9-]{1,63}){0,8}(?::\\d{1,5})?");
    private static final Pattern VERSIONISH = Pattern.compile("v?\\d+(?:\\.\\d+){0,4}(?:-[A-Za-z0-9.]+)?");

    private boolean isHostKey(String key) {
        if (key == null || key.isEmpty() || key.length() > 64) return false;
        String k = key;
        int dot = k.lastIndexOf('.');
        if (dot >= 0 && dot < k.length() - 1) k = k.substring(dot + 1);
        String norm = normKey(k);
        if (cfg.hostKeys.contains(norm)) return true;
        if (norm.endsWith("hostname") || norm.endsWith("servername")) return true;
        if (norm.length() > 4 && norm.endsWith("host") && !norm.endsWith("ghost") && !norm.endsWith("localhost")) return true;
        return norm.length() > 6 && norm.endsWith("server") && !norm.startsWith("webserver") && !norm.endsWith("observer");
    }

    /** Valore con la forma di un nome di macchina (cifre, trattini o punti: "srv-sql-prod01", "db01"). */
    private boolean looksLikeInternalHost(String v) {
        if (v == null || v.length() < 3 || v.length() > 253) return false;
        if (!HOSTISH.matcher(v).matches() || map.looksLikePlaceholder(v)) return false;
        String bare = v.indexOf(':') >= 0 ? v.substring(0, v.indexOf(':')) : v;
        if (isIp(bare)) return true;
        if (VERSIONISH.matcher(bare).matches() || bare.chars().allMatch(Character::isDigit)) return false;
        if (bare.equalsIgnoreCase("localhost")) return false;
        return bare.indexOf('-') >= 0 || bare.indexOf('.') >= 0 || bare.chars().anyMatch(Character::isDigit);
    }

    // --- validazioni dei nuovi pattern di contesto ---
    private boolean plausibleUsername(String s) {
        if (s.length() < 2 || s.length() > 64 || map.looksLikePlaceholder(s)) return false;
        if (cfg.notUsernames.contains(s.toLowerCase(Locale.ROOT))) return false;
        if (s.chars().allMatch(c -> Character.isDigit(c) || c == '-')) return false; // id numerico
        return !UUID.matcher(s).matches();
    }

    /** DOMINIO + backslash + utente: l'utente non deve sembrare una sequenza di escape ("ERROR\nfoo"). */
    private boolean plausibleAdUser(String s) {
        if (!plausibleUsername(s)) return false;
        boolean distinctive = s.indexOf('.') > 0 || s.indexOf('_') > 0 || s.chars().anyMatch(Character::isDigit);
        return distinctive || "ntrbfuxv0".indexOf(Character.toLowerCase(s.charAt(0))) < 0;
    }

    private boolean plausiblePersonName(String s) {
        String first = s.split("[ \\t]+")[0].toLowerCase(Locale.ROOT);
        return !cfg.notNames.contains(first);
    }

    private boolean plausiblePathToken(String s) {
        if (map.looksLikePlaceholder(s)) return false;
        boolean digit = false, letter = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) digit = true;
            else if (Character.isLetter(c)) letter = true;
        }
        return digit && letter;
    }

    // -------------------------------------------------- de-anonimizzazione

    /** Esito della de-anonimizzazione con la diagnostica sui segnaposto toccati dall'LLM. */
    public static final class DeanonResult {
        public final String text;
        /** Segnaposto sostituiti con il valore reale. */
        public final int replaced;
        /** Di cui scritti con l'underscore escapato da markdown ("HOST\_1"). */
        public final int unescaped;
        /** Segnaposto che non esistono nella mappa (inventati o di un'altra sessione): restano cosi'. */
        public final List<String> unknown;
        /** Segnaposto modificati dall'LLM (maiuscole, suffissi): NON sostituiti, da controllare. */
        public final List<String> altered;

        DeanonResult(String text, int replaced, int unescaped, List<String> unknown, List<String> altered) {
            this.text = text;
            this.replaced = replaced;
            this.unescaped = unescaped;
            this.unknown = unknown;
            this.altered = altered;
        }
    }

    public static String deanonymize(String text, Map<String, String> reverse) {
        return deanonymizeReport(text, reverse).text;
    }

    private static final Pattern PH_SHAPE_LOOSE = Pattern.compile(
            "(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9]{0,40}(?:\\\\?_[A-Za-z][A-Za-z0-9]{0,40}){0,8})\\\\?_(\\d{1,9})([A-Za-z0-9_]{0,40})");
    private static final Pattern PH_ROOT = Pattern.compile("^([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*?)_\\d{1,9}(?:_.*)?$");

    private static final Pattern UTF16LE_RUN = Pattern.compile("(?:[\\x01-\\xFF]\\x00){4,}");
    private static final Pattern UTF16BE_RUN = Pattern.compile("(?:\\x00[\\x01-\\xFF]){4,}");

    public static DeanonResult deanonymizeReport(String text, Map<String, String> reverse) {
        if (text != null && text.indexOf('\0') >= 0 && reverse != null && !reverse.isEmpty()) {
            // tratti UTF-16 (body anonimizzato in UTF-16): si decodificano, si ripristinano,
            // si ricodificano uguali
            int[] counts = new int[2];
            List<String> unk = new ArrayList<>(), alt = new ArrayList<>();
            for (int kind = 1; kind <= 2; kind++) {
                final int k = kind;
                text = regexReplace(text, kind == 1 ? UTF16LE_RUN : UTF16BE_RUN, m -> {
                    String dec = decodeUtf16(m.group(), k);
                    if (dec == null) return m.group();
                    DeanonResult r = deanonymizeReport(dec, reverse);
                    counts[0] += r.replaced;
                    counts[1] += r.unescaped;
                    unk.addAll(r.unknown);
                    alt.addAll(r.altered);
                    return r.replaced == 0 ? m.group() : encodeUtf16(r.text, k);
                });
            }
            DeanonResult rest = deanonymizeReport(text, reverse, true);
            unk.addAll(rest.unknown);
            alt.addAll(rest.altered);
            return new DeanonResult(rest.text, rest.replaced + counts[0], rest.unescaped + counts[1], unk, alt);
        }
        return deanonymizeReport(text, reverse, true);
    }

    private static DeanonResult deanonymizeReport(String text, Map<String, String> reverse, boolean plain) {
        List<String> unknown = new ArrayList<>();
        List<String> altered = new ArrayList<>();
        if (text == null || text.isEmpty() || reverse == null || reverse.isEmpty()) {
            return new DeanonResult(text, 0, 0, unknown, altered);
        }
        List<String> toks = new ArrayList<>(reverse.keySet());
        toks.removeIf(t -> t == null || t.isEmpty());
        if (toks.isEmpty()) return new DeanonResult(text, 0, 0, unknown, altered);
        toks.sort((a, b) -> Integer.compare(b.length(), a.length()));
        StringBuilder alt = new StringBuilder();
        for (int i = 0; i < toks.size(); i++) {
            if (i > 0) alt.append('|');
            String t = toks.get(i);
            // gli LLM in markdown scrivono spesso HOST\_1: accettato come HOST_1
            if (t.matches("[A-Z0-9_]+")) alt.append(t.replace("_", "\\\\?_"));
            else alt.append(Pattern.quote(t));
        }
        // confine di parola, ma un placeholder puo' seguire una sequenza %XX ("%22EMAIL_5_URL")
        // confine di parola, ma un placeholder puo' seguire una sequenza %XX ("%22EMAIL_5_URL")
        Pattern p = Pattern.compile("(?:(?<![\\w])|(?<=%(?:25){0,3}[0-9A-Fa-f]{2}))(?:" + alt + ")(?![\\w])");
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        int replaced = 0, unescaped = 0;
        while (m.find()) {
            String tok = m.group();
            String key = tok.indexOf('\\') >= 0 ? tok.replace("\\_", "_") : tok;
            String original = reverse.get(key);
            if (original != null) {
                replaced++;
                if (!key.equals(tok)) unescaped++;
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(original == null ? tok : original));
        }
        m.appendTail(sb);

        // diagnostica: segnaposto che sembrano nostri ma non corrispondono esattamente
        Set<String> roots = new java.util.HashSet<>();
        Set<String> upperKeys = new java.util.HashSet<>();
        for (String k : toks) {
            Matcher r = PH_ROOT.matcher(k);
            if (r.matches()) roots.add(r.group(1));
            upperKeys.add(k.toUpperCase(Locale.ROOT));
        }
        Matcher s = PH_SHAPE_LOOSE.matcher(text);
        while (s.find() && unknown.size() + altered.size() < 40) {
            String found = s.group();
            String clean = found.replace("\\_", "_");
            if (reverse.containsKey(clean)) continue;
            String prefix = s.group(1).replace("\\_", "_");
            String base = prefix + "_" + s.group(2);
            String upBase = base.toUpperCase(Locale.ROOT);
            if (!roots.contains(prefix.toUpperCase(Locale.ROOT))) continue; // non e' un nostro tipo
            boolean isAltered = !clean.equals(clean.toUpperCase(Locale.ROOT)) && upperKeys.contains(clean.toUpperCase(Locale.ROOT))
                    || (!s.group(3).isEmpty() && (reverse.containsKey(base) || upperKeys.contains(upBase)));
            List<String> into = isAltered ? altered : (reverse.containsKey(upBase) ? altered : unknown);
            if (!into.contains(clean)) into.add(clean);
        }
        return new DeanonResult(sb.toString(), replaced, unescaped, unknown, altered);
    }
}
