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
    }

    public SubstitutionMap getMap() { return map; }

    public String anonymizeRequest(String raw) { return anonymizeMessage(raw); }
    public String anonymizeResponse(String raw) { return anonymizeMessage(raw); }

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
        }
    }

    private String anonymizeMessage(String raw) {
        if (raw == null) return "";
        reserveLiterals(raw);
        try {
            return applyForced(anonymizeStructured(raw));
        } catch (Throwable t) {
            try {
                return applyForced(scanSecrets(raw));
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
        String dechunked = chunked ? dechunk(body) : null;
        if (dechunked != null) body = dechunked;
        for (HttpMessage.Header h : msg.headers) {
            String[] nv = anonHeader(h.name, h.value);
            h.name = nv[0];
            h.value = nv[1];
        }
        String anonBody = anonymizeBody(body, fullCt);
        // Content-Length resta quello originale: il messaggio anonimizzato deve
        // tornare identico byte per byte con la de-anonimizzazione.
        if (dechunked != null) anonBody = rechunk(anonBody, msg.newline);
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
                        : map.placeholder(value.trim(), "REDACTED", false);
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
            return m.group(1) + " " + map.placeholder(m.group(2).trim(), prefix);
        }
        return map.placeholder(v, prefix);
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
        return lead + kname + "=" + map.placeholder(v.trim(), prefix);
    }

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

    private String stratAuthChallenge(String value) {
        String redacted = value.replaceAll("\"[^\"]{0,4096}\"", "\"REDACTED\"");
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
                return rewriteJson(body, 0);
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
            return scanSecrets(body);
        } catch (StackOverflowError | RuntimeException e) {
            return scanSecrets(body);
        }
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
            if (prefix != null && !prefix.equals("USERNAME")) return "\"" + map.placeholder(tok, prefix) + "\"";
            if (prefix == null && strictId(memberKey(top), tok)) return "\"" + map.placeholder(tok, "ID") + "\"";
            if (!isIdKey(memberKey(top)) && validCard(tok)) return "\"" + map.placeholder(tok, "CARD") + "\"";
            return tok;
        }
        return prefix != null ? map.placeholder(tok, prefix) : scanSecrets(tok);
    }

    /** Scansiona un valore che puo' contenere a sua volta JSON, URL, query string... */
    private String scanValue(String v, String key, int depth) {
        if (v == null || v.isEmpty()) return v;
        String t = v.trim();
        if (depth < 6 && !t.isEmpty() && (t.charAt(0) == '{' || t.charAt(0) == '[') && looksLikeJsonDoc(t)) {
            return rewriteJson(v, depth + 1);
        }
        return scan(v, isIdKey(key));
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
            if (prefix == null) continue;
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
            String repl;
            Matcher am = AUTH_SCHEME.matcher(raw);
            if (am.matches()) repl = am.group(1) + " " + map.placeholder(am.group(2).trim(), prefix);
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
        for (PatternDef pat : cfg.patterns) {
            if (limited && isLimitedSkip(pat)) continue;
            text = applyOnePattern(text, pat);
        }
        return text;
    }

    private static boolean isGeneric(PatternDef pat) {
        return pat.name.startsWith("generic_") || "hex".equals(pat.validate)
                || "b64".equals(pat.validate) || "b64secret".equals(pat.validate);
    }

    private static boolean isLimitedSkip(PatternDef pat) {
        return isGeneric(pat) || "card".equals(pat.validate) || "luhn".equals(pat.validate)
                || "phone".equals(pat.validate);
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
                    if (ws.isEmpty() && !Character.isWhitespace(scheme.charAt(scheme.length() - 1))) ws = " ";
                    replacement = scheme + ws + map.placeholder(secret, pat.prefix);
                } else {
                    replacement = map.placeholder(whole, pat.prefix);
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
            else if (c != ' ' && c != '-') return false;
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

    // -------------------------------------------------- de-anonimizzazione
    public static String deanonymize(String text, Map<String, String> reverse) {
        if (text == null || text.isEmpty() || reverse == null || reverse.isEmpty()) return text;
        List<String> toks = new ArrayList<>(reverse.keySet());
        toks.removeIf(t -> t == null || t.isEmpty());
        if (toks.isEmpty()) return text;
        toks.sort((a, b) -> Integer.compare(b.length(), a.length()));
        StringBuilder alt = new StringBuilder();
        for (int i = 0; i < toks.size(); i++) {
            if (i > 0) alt.append('|');
            alt.append(Pattern.quote(toks.get(i)));
        }
        // confine di parola, ma un placeholder puo' seguire una sequenza %XX ("%22EMAIL_5_URL")
        Pattern p = Pattern.compile("(?:(?<![\\w])|(?<=%(?:25){0,3}[0-9A-Fa-f]{2}))(?:" + alt + ")(?![\\w])");
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String original = reverse.get(m.group());
            m.appendReplacement(sb, Matcher.quoteReplacement(original == null ? m.group() : original));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
