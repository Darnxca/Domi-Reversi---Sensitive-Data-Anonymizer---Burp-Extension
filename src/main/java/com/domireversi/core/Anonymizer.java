package com.domireversi.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Motore di anonimizzazione. Port di anonymizer.py.
 *
 * Coperto in questa v1: start line, header (selettivi), body JSON (redazione
 * per-chiave + nidificata + regex sulle stringhe), form-urlencoded, scansione
 * regex generica su qualunque body, host noti/URL/domini "nudi", coerenza dei
 * placeholder e de-anonimizzazione.
 *
 * Roadmap (v2): parsing strutturato di multipart, chunked, HTML/XML, GraphQL.
 * Nel frattempo quei body passano dalla scansione regex generica (i segreti con
 * firma regex vengono comunque redatti).
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
            "app","dev","cloud","xyz","online","site","tech","store","ai","me","tv","cc","gg",
            "sh","ly","fm","to","us","uk","de","fr","es","it","ca","au","nl","be","ch","at",
            "se","no","dk","fi","pl","pt","ie","gr","cz","ru","ua","cn","jp","kr","in","br",
            "mx","ar","cl","za","tr","il","sa","ae","eu","asia",
            "local","internal","corp","lan","intra","intranet","home","test","example","invalid","onion");

    private static final Pattern URL_RE = Pattern.compile("https?://[^\\s\"'<>)\\]}]+");
    private static final Pattern BARE_DOMAIN_RE = Pattern.compile(
            "(?<![@\\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,})(?![\\w.-])");
    private static final Pattern IPV4 = Pattern.compile("(?:\\d{1,3}\\.){3}\\d{1,3}");
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "^(Bearer|Basic|Digest|Negotiate|NTLM|Token)\\s+(.+)$", Pattern.CASE_INSENSITIVE);

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

    private String anonymizeMessage(String raw) {
        HttpMessage msg = HttpMessage.parse(raw);
        if (msg.isEmpty) return "";
        try {
            msg.startLine = anonStartLine(msg.startLine);
            String fullCt = msg.get("Content-Type");
            if (fullCt == null) fullCt = msg.contentType();
            String te = msg.get("Transfer-Encoding");
            boolean chunked = te != null && te.toLowerCase().contains("chunked");

            String body = msg.body;
            String dechunked = chunked ? dechunk(body) : null;
            if (dechunked != null) {
                body = dechunked; // ri-assemblato: la redazione per-chiave ora funziona
            }
            for (HttpMessage.Header h : msg.headers) {
                String[] nv = anonHeader(h.name, h.value);
                h.name = nv[0];
                h.value = nv[1];
            }
            String anonBody = anonymizeBody(body, fullCt);
            if (dechunked != null) {
                anonBody = rechunk(anonBody, msg.newline);
            }
            msg.body = anonBody;
            return applyForced(msg.serialize());
        } catch (Exception e) {
            return applyForced(scanSecrets(raw));
        }
    }

    /** Ultima passata: sostituisce le stringhe scelte a mano dall'utente
     *  (selezione + "Anonimizza") con CUSTOM_n, in TUTTE le occorrenze. */
    private String applyForced(String text) {
        if (ov.forceValues.isEmpty() || text == null || text.isEmpty()) return text;
        List<String> vals = new ArrayList<>(ov.forceValues);
        vals.sort((a, b) -> Integer.compare(b.length(), a.length()));
        for (String v : vals) {
            if (!v.isEmpty() && text.contains(v)) {
                text = text.replace(v, map.placeholder(v, "CUSTOM"));
            }
        }
        return text;
    }

    // -------------------------------------------------------------- start line
    private String anonStartLine(String line) {
        if (line == null || line.isEmpty()) return line;
        String[] parts = line.split(" ");
        if (parts.length >= 2 && parts[1].contains("?")
                && !parts[1].toUpperCase(Locale.ROOT).startsWith("HTTP/")) {
            int q = parts[1].indexOf('?');
            String path = parts[1].substring(0, q);
            String query = parts[1].substring(q + 1);
            parts[1] = path + "?" + anonQuery(query);
            line = String.join(" ", parts);
        }
        line = replaceUrlHosts(line);
        return applyPatterns(line);
    }

    // -------------------------------------------------------------------- header
    private String[] anonHeader(String name, String value) {
        String low = name.toLowerCase();
        // override utente: header da NON anonimizzare -> intatto
        if (ov.excludeHeaders.contains(low)) {
            return new String[]{name, value};
        }
        String strategy = cfg.headerStrategy.get(low);
        if ("user_agent".equals(strategy) && !cfg.anonymizeUserAgent) {
            strategy = null;
        }
        if (strategy != null) {
            return new String[]{name, applyHeaderStrategy(strategy, value)};
        }
        // override utente: header extra da anonimizzare (valore -> CUSTOM_n)
        if (ov.extraHeaders.contains(low) && !value.trim().isEmpty()) {
            return new String[]{name, map.placeholder(value.trim(), "CUSTOM")};
        }
        if (name.isEmpty()) {
            return new String[]{name, scanSecrets(value)};
        }
        if (cfg.keepHeaders.contains(low)) {
            return new String[]{name, replaceUrlHosts(replaceKnownHosts(value))};
        }
        return new String[]{name, scanSecrets(value)};
    }

    private String applyHeaderStrategy(String strategy, String value) {
        try {
            switch (strategy) {
                case "host": return anonHostValue(value);
                case "ip": return stratIp(value);
                case "host_scan": return stratHostScan(value);
                case "auth_token": return stratAuthToken(value);
                case "apikey": return placeholderTrim(value, "APIKEY");
                case "token": return placeholderTrim(value, "TOKEN");
                case "cookie": return stratCookie(value);
                case "set_cookie": return stratSetCookie(value);
                case "referer_origin":
                case "location": return applyPatterns(replaceUrlHosts(value));
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
        value = applyPatterns(value);
        value = replaceKnownHosts(value);
        value = replaceUrlHosts(value);
        value = replaceBareDomains(value, false);
        return value;
    }

    private String stratHostScan(String value) {
        value = replaceKnownHosts(value);
        value = replaceUrlHosts(value);
        value = replaceBareDomains(value, false);
        return value;
    }

    private String stratAuthToken(String value) {
        String v = value.trim();
        Matcher m = AUTH_SCHEME.matcher(v);
        if (m.matches()) {
            return m.group(1) + " " + map.placeholder(m.group(2).trim(), "AUTH_TOKEN");
        }
        if (v.isEmpty()) return value;
        return map.placeholder(v, "AUTH_TOKEN");
    }

    private boolean isSessionCookie(String name) {
        String n = name.toLowerCase().replace("-", "").replace("_", "");
        return SESSION_COOKIES.contains(n);
    }

    private String stratCookie(String value) {
        String[] parts = value.split(";", -1);
        List<String> out = new ArrayList<>();
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq >= 0) {
                String k = part.substring(0, eq);
                String v = part.substring(eq + 1);
                String kname = k.trim();
                if (!v.trim().isEmpty()) {
                    String prefix = isSessionCookie(kname) ? "SESSION" : "COOKIE";
                    String lead = k.substring(0, k.length() - stripLeading(k).length());
                    out.add(lead + kname + "=" + map.placeholder(v.trim(), prefix));
                } else {
                    out.add(part);
                }
            } else {
                if (!part.trim().isEmpty()) {
                    String lead = part.substring(0, part.length() - stripLeading(part).length());
                    out.add(lead + map.placeholder(part.trim(), "COOKIE"));
                } else {
                    out.add(part);
                }
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
                String kname = seg.substring(0, eq).trim();
                String v = seg.substring(eq + 1);
                String prefix = isSessionCookie(kname) ? "SESSION" : "COOKIE";
                if (!v.trim().isEmpty()) out.add(kname + "=" + map.placeholder(v.trim(), prefix));
                else out.add(seg);
            } else if (eq >= 0 && seg.substring(0, eq).trim().equalsIgnoreCase("domain")) {
                out.add(seg.substring(0, eq) + "=" + anonHostValue(seg.substring(eq + 1).trim()));
            } else {
                out.add(seg);
            }
        }
        return String.join(";", out);
    }

    private String stratAuthChallenge(String value) {
        String redacted = value.replaceAll("\"[^\"]*\"", "\"REDACTED\"");
        return applyPatterns(redacted);
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
        return h.matches("[0-9A-Fa-f:]+") && countChar(h, ':') >= 2;
    }

    private static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    private String anonHostValue(String value) {
        value = value.trim();
        if (value.isEmpty()) return value;
        String host = value;
        String port = "";
        boolean hasPort = false;
        if (value.startsWith("[")) {
            Matcher m = Pattern.compile("^(\\[[^\\]]+\\])(:\\d+)?$").matcher(value);
            if (m.matches()) {
                host = m.group(1);
                if (m.group(2) != null) { port = m.group(2).substring(1); hasPort = true; }
            }
        } else {
            int c = value.indexOf(':');
            if (c >= 0) { host = value.substring(0, c); port = value.substring(c + 1); hasPort = true; }
        }
        String prefix = isIp(host.replace("[", "").replace("]", "")) ? "IP" : "HOST";
        String ph = map.placeholder(host.toLowerCase(), prefix);
        return hasPort && !port.isEmpty() ? ph + ":" + port : ph;
    }

    private String replaceBareDomains(String text, boolean strict) {
        Matcher m = BARE_DOMAIN_RE.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String fqdn = m.group(1);
            String repl;
            if (strict) {
                String tld = fqdn.substring(fqdn.lastIndexOf('.') + 1).toLowerCase();
                repl = ALLOWED_TLDS.contains(tld) ? anonHostValue(fqdn) : fqdn;
            } else {
                repl = anonHostValue(fqdn);
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(repl));
        }
        m.appendTail(sb);
        return sb.toString();
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
                String prefix = sensitiveKeyPrefix(k);
                if (prefix != null && !dec.isEmpty()) {
                    out.add(k + "=" + map.placeholder(dec, prefix));
                } else {
                    String scanned = applyPatterns(dec);
                    out.add(scanned.equals(dec) ? p : k + "=" + urlEncode(scanned));
                }
            } else {
                out.add(p);
            }
        }
        return String.join("&", out);
    }

    private String replaceUrlHosts(String text) {
        Matcher m = URL_RE.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String url = m.group(0);
            String repl;
            try {
                repl = anonUrl(url);
            } catch (Exception e) {
                repl = url;
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(repl));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String anonUrl(String url) {
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) return url;
        String scheme = url.substring(0, schemeEnd);
        String rest = url.substring(schemeEnd + 3);
        // netloc = fino a / ? #
        int cut = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?' || c == '#') { cut = i; break; }
        }
        String netloc = rest.substring(0, cut);
        String tail = rest.substring(cut);
        String userinfo = "";
        if (netloc.contains("@")) {
            int at = netloc.lastIndexOf('@');
            userinfo = map.placeholder(netloc.substring(0, at), "AUTH_TOKEN") + "@";
            netloc = netloc.substring(at + 1);
        }
        String anonHost = anonHostValue(netloc);
        // query
        String path = tail, query = "", frag = "";
        int hash = path.indexOf('#');
        if (hash >= 0) { frag = path.substring(hash); path = path.substring(0, hash); }
        int qm = path.indexOf('?');
        if (qm >= 0) { query = path.substring(qm + 1); path = path.substring(0, qm); }
        String newTail = path + (qm >= 0 ? "?" + anonQuery(query) : "") + frag;
        return scheme + "://" + userinfo + anonHost + newTail;
    }

    // ---------------------------------------------------------------- body
    public String anonymizeBody(String body, String contentType) {
        if (body == null || body.isEmpty()) return body;
        try {
            String ct = contentType == null ? "" : contentType.toLowerCase();

            // multipart/* (form-data upload, ma anche multipart/mixed annidato)
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

            // application/graphql: il body E' la query GraphQL (non JSON)
            if (ct.contains("graphql") && first != '{' && first != '[') {
                return scanSecrets(anonGraphql(body));
            }

            boolean isJson = ct.contains("json") || first == '{' || first == '[';
            boolean isForm = ct.contains("x-www-form-urlencoded")
                    || (ct.isEmpty() && body.trim().matches("[^\\s=&]+=[^&]*(&[^\\s=&]+=[^&]*)*"));
            boolean isHtmlXml = ct.contains("html") || ct.contains("xml") || first == '<';

            if (isJson) {
                String r = anonJsonBody(body);
                if (r != null) return r;
            }
            if (isForm) {
                String r = anonFormBody(body);
                if (r != null) return r;
            }
            if (isHtmlXml) {
                return anonHtml(body);
            }
            return scanSecrets(body);
        } catch (Exception e) {
            return scanSecrets(body);
        }
    }

    // --- JSON ---
    private String anonJsonBody(String body) {
        try {
            JsonElement root = JsonParser.parseString(body);
            JsonElement out = transformJson(root, null, 0);
            boolean pretty = body.contains("\n");
            Gson gson = pretty ? new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
                               : new GsonBuilder().disableHtmlEscaping().create();
            return gson.toJson(out);
        } catch (Exception e) {
            return null;
        }
    }

    private static final int MAX_JSON_DEPTH = 120;

    private JsonElement transformJson(JsonElement el, String forcedPrefix, int depth) {
        if (depth > MAX_JSON_DEPTH) {
            return new JsonPrimitive(map.placeholder("<deep-structure>", "REDACTED", false));
        }
        if (el.isJsonObject()) {
            JsonObject src = el.getAsJsonObject();
            JsonObject dst = new JsonObject();
            for (Map.Entry<String, JsonElement> e : src.entrySet()) {
                dst.add(e.getKey(), transformValue(e.getKey(), e.getValue(), forcedPrefix, depth + 1));
            }
            return dst;
        }
        if (el.isJsonArray()) {
            JsonArray src = el.getAsJsonArray();
            JsonArray dst = new JsonArray();
            for (JsonElement v : src) dst.add(transformJson(v, forcedPrefix, depth + 1));
            return dst;
        }
        if (el.isJsonPrimitive()) {
            JsonPrimitive p = el.getAsJsonPrimitive();
            if (p.isString()) {
                if (forcedPrefix != null) return new JsonPrimitive(map.placeholder(p.getAsString(), forcedPrefix));
                return new JsonPrimitive(scanSecrets(p.getAsString()));
            }
            if (p.isBoolean()) return el;
            if (p.isNumber()) {
                if (forcedPrefix != null) return new JsonPrimitive(map.placeholder(p.getAsString(), forcedPrefix));
                String scanned = scanNumeric(p.getAsString());
                return scanned == null ? el : new JsonPrimitive(scanned);
            }
        }
        return el; // null
    }

    private JsonElement transformValue(String key, JsonElement value, String inheritedPrefix, int depth) {
        String prefix = sensitiveKeyPrefix(key);
        if (prefix == null) prefix = inheritedPrefix;
        if (prefix != null) {
            if (value.isJsonObject() || value.isJsonArray()) {
                return transformJson(value, prefix, depth);
            }
            if (value.isJsonNull()) return value;
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean()) return value;
            return new JsonPrimitive(map.placeholder(value.getAsString(), prefix));
        }
        // GraphQL: il campo "query" contiene literal inline (password: "...")
        if (inheritedPrefix == null && value.isJsonPrimitive()
                && value.getAsJsonPrimitive().isString() && key.equalsIgnoreCase("query")) {
            String s = value.getAsString();
            if (looksLikeGraphql(s)) {
                return new JsonPrimitive(scanSecrets(anonGraphql(s)));
            }
        }
        return transformJson(value, null, depth);
    }

    /** Solo carta di credito (Luhn) sui numeri, per evitare FP su id/timestamp. */
    private String scanNumeric(String s) {
        for (PatternDef pat : cfg.patterns) {
            if ("luhn".equals(pat.validate)) {
                String scanned = applyOnePattern(s, pat);
                if (!scanned.equals(s)) return scanned;
            }
        }
        return null;
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
                String prefix = sensitiveKeyPrefix(k);
                if (prefix != null && !dec.isEmpty()) {
                    out.add(k + "=" + map.placeholder(dec, prefix));
                } else if (!dec.isEmpty()) {
                    String scanned = scanSecrets(dec);
                    out.add(scanned.equals(dec) ? pair : k + "=" + urlEncode(scanned));
                } else {
                    out.add(pair);
                }
            } else {
                String dec = urlDecode(pair);
                String scanned = scanSecrets(dec);
                out.add(scanned.equals(dec) ? pair : urlEncode(scanned));
            }
        }
        return String.join("&", out);
    }

    // ------------------------------------------------------ sensitive JSON keys
    private String sensitiveKeyPrefix(String key) {
        String norm = key.toLowerCase().replaceAll("[\\s_\\-]", "");
        // override utente: chiave da NON anonimizzare / da anonimizzare in piu'
        if (ov.excludeKeys.contains(norm)) {
            return null;
        }
        if (ov.extraKeys.contains(norm)) {
            return "CUSTOM";
        }
        if (cfg.keyExact.contains(norm)) {
            return cfg.keyPrefixMap.getOrDefault(norm, "SECRET");
        }
        for (String token : cfg.keyContains) {
            if (norm.contains(token)) {
                return cfg.keyPrefixMap.getOrDefault(token, "SECRET");
            }
        }
        return null;
    }

    // ------------------------------------------------------------ scan generico
    public String scanSecrets(String text) {
        if (text == null || text.isEmpty()) return text;
        text = replaceKnownHosts(text);
        text = replaceUrlHosts(text);
        text = applyPatterns(text);
        text = replaceBareDomains(text, true);
        return text;
    }

    private String replaceKnownHosts(String text) {
        List<String[]> hosts = new ArrayList<>(map.knownHosts());
        hosts.sort((a, b) -> Integer.compare(b[0].length(), a[0].length()));
        for (String[] hp : hosts) {
            String host = hp[0];
            if (host == null || host.isEmpty()) continue;
            Pattern p = Pattern.compile("(?<![\\w.-])" + Pattern.quote(host) + "(?![\\w.-])",
                    Pattern.CASE_INSENSITIVE);
            text = p.matcher(text).replaceAll(Matcher.quoteReplacement(hp[1]));
        }
        return text;
    }

    private String applyPatterns(String text) {
        for (PatternDef pat : cfg.patterns) {
            text = applyOnePattern(text, pat);
        }
        return text;
    }

    private String applyOnePattern(String text, PatternDef pat) {
        try {
            Matcher m = pat.regex.matcher(text);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String whole = m.group(0);
                String replacement;
                if ("luhn".equals(pat.validate) && !luhnValid(whole)) {
                    replacement = whole;
                } else if ("phone".equals(pat.validate) && !plausiblePhone(whole)) {
                    replacement = whole;
                } else if (pat.keepGroup != null && m.groupCount() >= pat.keepGroup) {
                    String scheme = m.group(pat.keepGroup);
                    String secret = whole.substring(m.end(pat.keepGroup) - m.start()).stripLeading();
                    replacement = scheme + " " + map.placeholder(secret, pat.prefix);
                } else {
                    replacement = map.placeholder(whole, pat.prefix);
                }
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            m.appendTail(sb);
            return sb.toString();
        } catch (Exception e) {
            return text;
        }
    }

    // -------------------------------------------------------------- validazioni
    public static boolean luhnValid(String number) {
        List<Integer> digits = new ArrayList<>();
        for (char c : number.toCharArray()) if (Character.isDigit(c)) digits.add(c - '0');
        if (digits.size() < 13 || digits.size() > 19) return false;
        int checksum = 0;
        int parity = digits.size() % 2;
        for (int i = 0; i < digits.size(); i++) {
            int d = digits.get(i);
            if (i % 2 == parity) { d *= 2; if (d > 9) d -= 9; }
            checksum += d;
        }
        return checksum % 10 == 0;
    }

    private static boolean plausiblePhone(String s) {
        int n = 0;
        for (char c : s.toCharArray()) if (Character.isDigit(c)) n++;
        return n >= 8 && n <= 15;
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
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(repl.apply(m)));
        }
        m.appendTail(sb);
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
            if (!sizeToken.matches("[0-9A-Fa-f]+")) return null;
            long size;
            try { size = Long.parseLong(sizeToken, 16); } catch (Exception e) { return null; }
            i = j + 1;
            if (size == 0) { sawTerm = true; break; }
            if (i + size > n) return null;
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
        Matcher m = Pattern.compile("(?m)^--([^\\r\\n]+)").matcher(body);
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
            Matcher fn = Pattern.compile("name=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE).matcher(cd.group());
            if (fn.find()) fieldName = fn.group(1);
        }
        String partCt = "";
        Matcher pct = Pattern.compile("content-type:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE).matcher(head);
        if (pct.find()) partCt = pct.group(1).trim();
        String cte = "";
        Matcher mcte = Pattern.compile("content-transfer-encoding:\\s*([^\\r\\n;]+)", Pattern.CASE_INSENSITIVE).matcher(head);
        if (mcte.find()) cte = mcte.group(1).trim().toLowerCase();

        // filename: quoted, RFC 5987 (filename*=), non quotato
        head = regexReplace(head, Pattern.compile("(filename=\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2), "FILENAME") + m.group(3));
        head = regexReplace(head, Pattern.compile("(filename\\*=)([^\\r\\n;]+)", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2).trim(), "FILENAME"));
        head = regexReplace(head, Pattern.compile("(filename=)(?!\")([^;\\r\\n]+)", Pattern.CASE_INSENSITIVE),
                m -> m.group(1) + map.placeholder(m.group(2).trim(), "FILENAME"));

        // scansione dei SOLI header "altri" (non CT/CD, gia' gestiti)
        StringBuilder hb = new StringBuilder();
        String[] hlines = head.split(Pattern.quote(nl), -1);
        for (int i = 0; i < hlines.length; i++) {
            if (i > 0) hb.append(nl);
            String low = hlines[i].toLowerCase();
            if (low.startsWith("content-type:") || low.startsWith("content-disposition:")) hb.append(hlines[i]);
            else hb.append(scanSecrets(hlines[i]));
        }
        head = hb.toString();

        String prefix = fieldName.isEmpty() ? null : sensitiveKeyPrefix(fieldName);
        String newContent;
        if (prefix != null && !content.trim().isEmpty()) {
            newContent = map.placeholder(content.trim(), prefix);
        } else if (cte.equals("base64") || cte.equals("quoted-printable")) {
            newContent = anonEncodedContent(content, cte, partCt);
        } else {
            newContent = partCt.isEmpty() ? scanSecrets(content) : anonymizeBody(content, partCt);
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
            return map.placeholder(content.trim(), "FILE"); // blob binario: redige in blocco
        }
        String anon = anonymizeBody(text, partCt);
        if (anon.equals(text)) return content; // nulla di sensibile: preserva l'encoding
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
        // testo sotto un tag dal nome sensibile: <password>...</password>
        String out = regexReplace(body,
                Pattern.compile("(<([A-Za-z][\\w:-]*)\\b[^>]*>)([^<]*)(</\\2\\s*>)"),
                m -> {
                    String prefix = sensitiveKeyPrefix(m.group(2));
                    String txt = m.group(3);
                    if (prefix != null && !txt.trim().isEmpty()) {
                        return m.group(1) + map.placeholder(txt.trim(), prefix) + m.group(4);
                    }
                    return m.group(0);
                });
        // href/src/action: host negli URL
        out = regexReplace(out,
                Pattern.compile("(?i)\\b(href|src|action)(\\s*=\\s*\")([^\"]*)(\")"),
                m -> m.group(1) + m.group(2) + applyPatterns(replaceUrlHosts(m.group(3))) + m.group(4));
        // value/content/data-*: scansiona i valori (token nascosti, CSRF, ...)
        out = regexReplace(out,
                Pattern.compile("(?i)\\b(value|content|data-[\\w-]+)(\\s*=\\s*\")([^\"]*)(\")"),
                m -> m.group(1) + m.group(2) + scanSecrets(m.group(3)) + m.group(4));
        // nodi testo generali + segreti con firma regex
        return scanSecrets(out);
    }

    // ---------------------------------------------------------------- GraphQL
    private static final Pattern GQL_STR_ARG =
            Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)(\\s*:\\s*)\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern GQL_MARKERS =
            Pattern.compile("\\b(query|mutation|subscription|fragment)\\b");

    private static boolean looksLikeGraphql(String text) {
        if (!text.contains("{")) return false;
        return GQL_MARKERS.matcher(text).find() || (text.contains("(") && text.contains(":"));
    }

    private String anonGraphql(String text) {
        return regexReplace(text, GQL_STR_ARG, m -> {
            String prefix = sensitiveKeyPrefix(m.group(1));
            if (prefix != null) {
                return m.group(1) + m.group(2) + "\"" + map.placeholder(m.group(3), prefix) + "\"";
            }
            return m.group(0);
        });
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
        Pattern p = Pattern.compile("(?<![\\w])(?:" + alt + ")(?![\\w])");
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
