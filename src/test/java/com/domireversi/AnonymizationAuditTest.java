package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.Overrides;
import com.domireversi.core.SubstitutionMap;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Batteria estesa di anonimizzazione: ogni dato sensibile viene provato in ogni
 * posizione del messaggio HTTP, piu' falsi positivi, reversibilita', struttura,
 * robustezza e prestazioni. Gira con: ./gradlew audit
 */
@Tag("audit")
class AnonymizationAuditTest {

    // ------------------------------------------------------------------ helper

    private static final Duration LIMIT = Duration.ofSeconds(5);
    private static final Pattern PLACEHOLDER_LIKE = Pattern.compile("(?i)^[A-Z]+(?:_[A-Z]+)*_\\d+$");

    private static Anonymizer fresh() {
        return new Anonymizer(Config.loadFromResources(), new SubstitutionMap());
    }

    private static String run(Anonymizer an, String raw) {
        return assertTimeoutPreemptively(LIMIT,
                () -> raw.startsWith("HTTP/") ? an.anonymizeResponse(raw) : an.anonymizeRequest(raw),
                "anonimizzazione oltre " + LIMIT.toSeconds() + " s");
    }

    private static String run(String raw) { return run(fresh(), raw); }

    private static String req(String ct, String body) {
        return "POST /api HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: " + ct + "\r\n\r\n" + body;
    }

    private static String resp(String ct, String body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: " + ct + "\r\n\r\n" + body;
    }

    private static String get(String target, String extraHeaders) {
        return "GET " + target + " HTTP/1.1\r\nHost: h.example.com\r\n" + extraHeaders + "\r\n";
    }

    private static String body(String msg) {
        int i = msg.indexOf("\r\n\r\n");
        return i < 0 ? "" : msg.substring(i + 4);
    }

    private static String enc(String v) { return URLEncoder.encode(v, StandardCharsets.UTF_8); }

    /** Tutte le forme in cui il valore potrebbe riapparire in chiaro. */
    private static Set<String> forms(String v) {
        Set<String> f = new LinkedHashSet<>();
        f.add(v);
        f.add(enc(v));
        f.add(v.replace(" ", "%20"));
        f.add(v.replace("@", "%40"));
        f.add(v.replace("/", "\\/"));
        return f;
    }

    private static void assertNoLeak(String out, String v) {
        String lo = out.toLowerCase(Locale.ROOT);
        for (String form : forms(v)) {
            int i = lo.indexOf(form.toLowerCase(Locale.ROOT));
            if (i >= 0) {
                int s = Math.max(0, i - 60), e = Math.min(out.length(), i + form.length() + 60);
                fail("FUGA: '" + form + "' resta in chiaro -> ..." + out.substring(s, e).replace("\r\n", " | ") + "...");
            }
        }
    }

    private static DynamicTest leakTest(String name, String raw, String... secrets) {
        return DynamicTest.dynamicTest(name, () -> {
            String out = run(raw);
            for (String s : secrets) assertNoLeak(out, s);
        });
    }

    private static String chunked(String data) {
        byte[] b = data.getBytes(StandardCharsets.UTF_8);
        return Integer.toHexString(b.length) + "\r\n" + data + "\r\n0\r\n\r\n";
    }

    private static String multipart(String field, String value) {
        return "--BnD\r\nContent-Disposition: form-data; name=\"" + field + "\"\r\n\r\n" + value + "\r\n--BnD--\r\n";
    }

    // ------------------------------------------------------------------ dati

    /** Valori riconoscibili dal contenuto (devono sparire in qualunque posizione). */
    private static final String[][] PATTERN_SECRETS = {
            {"email", "mario.rossi@clientecorp.it"},
            {"email maiuscola", "GIULIA.BIANCHI@CLIENTECORP.IT"},
            {"email con +", "mario+test@mail.clientecorp.it"},
            {"IPv4 pubblico", "93.45.122.8"},
            {"IPv4 privato", "10.20.30.40"},
            {"IPv6", "2001:db8:85a3::8a2e:370:7334"},
            {"IPv6 completo", "2001:0db8:0000:0000:0000:ff00:0042:8329"},
            {"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtcm9zc2kifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
            {"AWS access key", "AK" + "IAIOSFODNN7EXAMPLE"},
            {"AWS secret key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
            {"GitHub token", "gh" + "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"},
            {"GitLab PAT", "gl" + "pat-AbCdEfGhIjKlMnOpQrSt"},
            {"Stripe key", "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"},
            {"Google API key", "AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"},
            {"Slack token", "xo" + "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"},
            {"OpenAI key", "sk-" + "proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"},
            {"Anthropic key", "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-xyz"},
            {"SendGrid key", "S" + "G.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"},
            {"IBAN IT", "IT60X0542811101000000123456"},
            {"IBAN DE", "DE89370400440532013000"},
            {"carta Visa", "4111111111111111"},
            {"carta Mastercard", "5555555555554444"},
            {"carta Amex", "378282246310005"},
            {"Codice Fiscale", "RSSMRA80A01H501U"},
            {"Partita IVA", "IT01234567897"},
            {"telefono +39", "+39 347 123 4567"},
            {"cellulare", "3471234567"},
    };

    /** Posizioni in cui inserire un valore (nessuna chiave sensibile: deve agire il riconoscimento). */
    private static final Map<String, Function<String, String>> PLACES = new LinkedHashMap<>();
    static {
        PLACES.put("body testo", v -> req("text/plain", "nota: " + v + " fine"));
        PLACES.put("inizio body", v -> req("text/plain", v));
        PLACES.put("tra parentesi", v -> req("text/plain", "(" + v + ")"));
        PLACES.put("tra virgolette", v -> req("text/plain", "'" + v + "'"));
        PLACES.put("seguito da punto", v -> req("text/plain", "vedi " + v + "."));
        PLACES.put("JSON chiave neutra", v -> req("application/json", "{\"note\":\"" + v + "\"}"));
        PLACES.put("JSON frase", v -> req("application/json", "{\"msg\":\"scrivere a " + v + " subito\"}"));
        PLACES.put("JSON annidato", v -> req("application/json", "{\"a\":{\"b\":[{\"c\":\"" + v + "\"}]}}"));
        PLACES.put("JSON array", v -> req("application/json", "[\"x\",\"" + v + "\"]"));
        PLACES.put("JSON risposta", v -> resp("application/json", "{\"data\":{\"info\":\"" + v + "\"}}"));
        PLACES.put("JSON chunked", v -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked("{\"info\":\"" + v + "\"}"));
        PLACES.put("JSON con Content-Type text", v -> req("text/plain", "{\"info\":\"" + v + "\"}"));
        PLACES.put("GraphQL variabile", v -> req("application/json", "{\"query\":\"query($n:String){x(n:$n){id}}\",\"variables\":{\"n\":\"" + v + "\"}}"));
        PLACES.put("form neutro", v -> req("application/x-www-form-urlencoded", "note=" + enc(v) + "&x=1"));
        PLACES.put("query string", v -> get("/search?q=" + enc(v) + "&page=1", ""));
        PLACES.put("path", v -> get("/users/" + enc(v) + "/profile", ""));
        PLACES.put("multipart", v -> "POST /u HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: multipart/form-data; boundary=BnD\r\n\r\n" + multipart("note", v));
        PLACES.put("XML elemento", v -> req("application/xml", "<r><note>" + v + "</note></r>"));
        PLACES.put("XML attributo", v -> req("application/xml", "<r note=\"" + v + "\"/>"));
        PLACES.put("XML CDATA", v -> req("application/xml", "<r><![CDATA[" + v + "]]></r>"));
        PLACES.put("HTML testo", v -> resp("text/html", "<html><body><p>" + v + "</p></body></html>"));
        PLACES.put("HTML attributo title", v -> resp("text/html", "<span title=\"" + v + "\">x</span>"));
        PLACES.put("HTML commento", v -> resp("text/html", "<!-- debug " + v + " -->"));
        PLACES.put("JavaScript stringa", v -> resp("application/javascript", "var cfg = \"" + v + "\";"));
        PLACES.put("header neutro", v -> get("/", "X-Debug-Info: " + v + "\r\n"));
        PLACES.put("Referer query", v -> get("/", "Referer: https://h.example.com/p?ref=" + enc(v) + "\r\n"));
        PLACES.put("Location query", v -> "HTTP/1.1 302 Found\r\nLocation: /next?x=" + enc(v) + "\r\n\r\n");
        PLACES.put("messaggio di errore", v -> resp("text/plain", "Exception: user " + v + " not allowed\n\tat com.client.Svc.run(Svc.java:42)"));
    }

    /** Chiavi sensibili: il valore non segue nessun pattern, deve agire il nome della chiave. */
    private static final String[] SECRET_KEYS = {
            "password", "passwd", "pwd", "pass", "secret", "client_secret", "token", "access_token",
            "refresh_token", "id_token", "api_key", "apikey", "apiKey", "x-api-key", "auth", "authorization",
            "session", "sessionid", "session_id", "sid", "csrf", "_csrf", "csrf_token", "xsrf_token",
            "otp", "pin", "private_key", "signature", "sig", "passphrase", "credentials",
            "secret_key", "auth_token", "jwt", "bearer", "cookie", "session_token", "csrfmiddlewaretoken",
            "card_number", "cvv"
    };

    /** Segreti solo in query string / form / URL (nel JSON o nell'HTML sono quasi sempre innocui). */
    private static final String[] QUERY_ONLY_KEYS = {"code", "ticket", "key", "SAMLResponse"};

    private static final Map<String, java.util.function.BiFunction<String, String, String>> KEY_PLACES = new LinkedHashMap<>();
    static {
        KEY_PLACES.put("JSON", (k, v) -> req("application/json", "{\"" + k + "\":\"" + v + "\"}"));
        KEY_PLACES.put("JSON annidato", (k, v) -> req("application/json", "{\"data\":{\"cfg\":[{\"" + k + "\":\"" + v + "\"}]}}"));
        KEY_PLACES.put("JSON risposta", (k, v) -> resp("application/json", "{\"" + k + "\":\"" + v + "\"}"));
        KEY_PLACES.put("JSON chunked", (k, v) -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked("{\"" + k + "\":\"" + v + "\"}"));
        KEY_PLACES.put("JSON in stringa", (k, v) -> req("application/json", "{\"payload\":\"{\\\"" + k + "\\\":\\\"" + v + "\\\"}\"}"));
        KEY_PLACES.put("JSON malformato", (k, v) -> req("application/json", "{\"" + k + "\":\"" + v + "\", \"x\":"));
        KEY_PLACES.put("form", (k, v) -> req("application/x-www-form-urlencoded", "user=a&" + k + "=" + v));
        KEY_PLACES.put("query string", (k, v) -> get("/cb?" + k + "=" + v + "&page=2", ""));
        KEY_PLACES.put("Location", (k, v) -> "HTTP/1.1 302 Found\r\nLocation: https://h.example.com/cb?" + k + "=" + v + "\r\n\r\n");
        KEY_PLACES.put("URL dentro JSON", (k, v) -> req("application/json", "{\"next\":\"https://h.example.com/f?" + k + "=" + v + "\"}"));
        KEY_PLACES.put("multipart", (k, v) -> "POST /u HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: multipart/form-data; boundary=BnD\r\n\r\n" + multipart(k, v));
        KEY_PLACES.put("XML elemento", (k, v) -> req("application/xml", "<r><" + k + ">" + v + "</" + k + "></r>"));
        KEY_PLACES.put("XML attributo", (k, v) -> req("application/xml", "<r " + k + "=\"" + v + "\"/>"));
        KEY_PLACES.put("HTML input hidden", (k, v) -> resp("text/html", "<form><input type=\"hidden\" name=\"" + k + "\" value=\"" + v + "\"></form>"));
        KEY_PLACES.put("HTML meta", (k, v) -> resp("text/html", "<meta name=\"" + k + "\" content=\"" + v + "\">"));
        KEY_PLACES.put("JavaScript var", (k, v) -> resp("application/javascript", "var " + k.replace("-", "_") + " = \"" + v + "\";"));
        KEY_PLACES.put("JS oggetto", (k, v) -> resp("text/html", "<script>window.cfg={\"" + k + "\":\"" + v + "\"}</script>"));
        KEY_PLACES.put("GraphQL inline", (k, v) -> req("application/json", "{\"query\":\"mutation{login(" + k.replace("-", "_") + ":\\\"" + v + "\\\"){ok}}\"}"));
        KEY_PLACES.put("testo chiave=valore", (k, v) -> req("text/plain", k + "=" + v + "\n"));
        KEY_PLACES.put("testo chiave: valore", (k, v) -> req("text/plain", k + ": " + v + "\n"));
        KEY_PLACES.put("YAML", (k, v) -> req("application/x-yaml", "app:\n  " + k + ": " + v + "\n"));
        KEY_PLACES.put("NDJSON", (k, v) -> req("application/x-ndjson", "{\"a\":1}\n{\"" + k + "\":\"" + v + "\"}\n"));
        KEY_PLACES.put("cookie", (k, v) -> get("/", "Cookie: theme=dark; " + k + "=" + v + "\r\n"));
    }

    // ------------------------------------------------------------------ 1. pattern x posizione

    @TestFactory
    Stream<DynamicNode> datiRiconosciutiInOgniPosizione() {
        return Arrays.stream(PATTERN_SECRETS).map(s -> DynamicContainer.dynamicContainer(s[0],
                PLACES.entrySet().stream().map(p -> leakTest(s[0] + " / " + p.getKey(), p.getValue().apply(s[1]), s[1]))));
    }

    // ------------------------------------------------------------------ 2. chiave sensibile x posizione

    @TestFactory
    Stream<DynamicNode> chiaviSensibiliInOgniFormato() {
        return KEY_PLACES.entrySet().stream().map(p -> DynamicContainer.dynamicContainer(p.getKey(),
                Arrays.stream(SECRET_KEYS).map(k -> {
                    String v = "Zq7v" + Math.abs(k.hashCode() % 9973) + "Xw";
                    return leakTest(p.getKey() + " / " + k, p.getValue().apply(k, v), v);
                })));
    }

    @TestFactory
    Stream<DynamicNode> chiaviSoloInUrl() {
        String[] places = {"form", "query string", "Location", "URL dentro JSON", "multipart"};
        return Arrays.stream(places).map(pl -> DynamicContainer.dynamicContainer(pl,
                Arrays.stream(QUERY_ONLY_KEYS).map(k -> {
                    String v = "Qk9" + Math.abs(k.hashCode() % 9973) + "Zz";
                    return leakTest(pl + " / " + k, KEY_PLACES.get(pl).apply(k, v), v);
                })));
    }

    // ------------------------------------------------------------------ 3. PII per nome campo

    @TestFactory
    Stream<DynamicNode> datiPersonaliPerNomeCampo() {
        String[][] pii = {
                {"firstName", "Giulia"}, {"lastName", "Bianchi"}, {"name", "Giulia Bianchi"},
                {"fullName", "Giulia Bianchi"}, {"nome", "Mario"}, {"cognome", "Rossi"},
                {"username", "gbianchi85"}, {"user", "gbianchi85"}, {"login", "gbianchi85"},
                {"address", "Via Roma 12"}, {"indirizzo", "Via Roma 12"}, {"street", "Via Roma 12"},
                {"birthdate", "1985-08-01"}, {"dob", "1985-08-01"}, {"data_nascita", "1985-08-01"},
                {"phone", "0612345678"}, {"telefono", "0612345678"}, {"mobile", "3479998888"},
                {"email", "privato@dominio-cliente.it"}, {"cf", "BNCGLI85M41H501Z"},
                {"codice_fiscale", "BNCGLI85M41H501Z"}, {"iban", "IT60X0542811101000000123456"},
                {"card_number", "4012888888881881"}, {"cvv", "737"}, {"cvc", "737"},
                {"card_expiry", "12/28"}, {"ssn", "123-45-6789"}, {"tax_id", "IT01234567897"},
                {"ip", "81.2.69.160"}, {"client_ip", "81.2.69.160"},
        };
        return Stream.of("JSON", "form", "XML").map(fmt -> DynamicContainer.dynamicContainer(fmt,
                Arrays.stream(pii).map(p -> {
                    String raw = switch (fmt) {
                        case "JSON" -> req("application/json", "{\"profile\":{\"" + p[0] + "\":\"" + p[1] + "\"}}");
                        case "form" -> req("application/x-www-form-urlencoded", p[0] + "=" + enc(p[1]));
                        default -> req("application/xml", "<profile><" + p[0] + ">" + p[1] + "</" + p[0] + "></profile>");
                    };
                    return leakTest(fmt + " / " + p[0], raw, p[1]);
                })));
    }

    // ------------------------------------------------------------------ 4. header

    @TestFactory
    Stream<DynamicNode> headerSensibili() {
        String[][] h = {
                {"Host", "api.clientecorp.it", "api.clientecorp.it"},
                {"Host con porta", "Host: api.clientecorp.it:8443", "api.clientecorp.it"},
                {"Authorization Bearer", "Authorization: Bearer tok_A1b2C3d4E5f6G7h8", "tok_A1b2C3d4E5f6G7h8"},
                {"Authorization Basic", "Authorization: Basic YWRtaW46U3VwZXJTZWdyZXRh", "YWRtaW46U3VwZXJTZWdyZXRh"},
                {"Authorization bearer minuscolo", "authorization: bearer lowerTok998877aa", "lowerTok998877aa"},
                {"Authorization Digest", "Authorization: Digest username=\"mrossi\", response=\"6629fae49393a05397450978507c4ef1\"", "6629fae49393a05397450978507c4ef1"},
                {"Authorization NTLM", "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==", "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="},
                {"Authorization AWS SigV4", "Authorization: AWS4-HMAC-SHA256 Credential=AK" + "IAIOSFODNN7EXAMPLE/20261107/eu-west-1/s3/aws4_request, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024", "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"},
                {"Authorization schema custom", "Authorization: Token tkn_9f8e7d6c5b4a", "tkn_9f8e7d6c5b4a"},
                {"Proxy-Authorization", "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="},
                {"Cookie", "Cookie: JSESSIONID=8F3A9C2B71D04E5F", "8F3A9C2B71D04E5F"},
                {"Cookie multipli", "Cookie: a=CookieValA1234\r\nCookie: b=CookieValB5678", "CookieValB5678"},
                {"Cookie tra virgolette", "Cookie: token=\"QuotedCookie77\"", "QuotedCookie77"},
                {"X-Api-Key", "X-Api-Key: 9f8e7d6c5b4a3210fedcba9876543210", "9f8e7d6c5b4a3210fedcba9876543210"},
                {"Api-Key", "Api-Key: plainApiKey12345", "plainApiKey12345"},
                {"X-Auth-Token", "X-Auth-Token: authTok55667788", "authTok55667788"},
                {"X-Access-Token", "X-Access-Token: accTok55667788", "accTok55667788"},
                {"X-CSRF-Token", "X-CSRF-Token: csrfTok55667788", "csrfTok55667788"},
                {"X-XSRF-TOKEN", "X-XSRF-TOKEN: xsrfTok55667788", "xsrfTok55667788"},
                {"X-Session-Id", "X-Session-Id: sess_ABCDEF123456", "sess_ABCDEF123456"},
                {"X-Amz-Security-Token", "X-Amz-Security-Token: FwoGZXIvYXdzEJrSessionToken", "FwoGZXIvYXdzEJrSessionToken"},
                {"X-Goog-Api-Key", "X-Goog-Api-Key: AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", "AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"},
                {"Ocp-Apim-Subscription-Key", "Ocp-Apim-Subscription-Key: 0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
                {"X-Forwarded-For", "X-Forwarded-For: 93.45.122.8, 10.0.0.1", "93.45.122.8"},
                {"X-Forwarded-Host", "X-Forwarded-Host: backend01.clientecorp.local", "backend01.clientecorp.local"},
                {"X-Real-IP", "X-Real-IP: 81.2.69.160", "81.2.69.160"},
                {"CF-Connecting-IP", "CF-Connecting-IP: 151.38.1.9", "151.38.1.9"},
                {"True-Client-IP", "True-Client-IP: 151.38.1.10", "151.38.1.10"},
                {"Forwarded", "Forwarded: for=198.51.100.17;host=internal.clientecorp.it", "internal.clientecorp.it"},
                {"Via", "Via: 1.1 proxy-int.clientecorp.it", "proxy-int.clientecorp.it"},
                {"Origin", "Origin: https://app.clientecorp.it", "app.clientecorp.it"},
                {"Referer", "Referer: https://app.clientecorp.it/x", "app.clientecorp.it"},
                {"X-Original-URL", "X-Original-URL: https://admin.clientecorp.it/panel", "admin.clientecorp.it"},
        };
        Stream<DynamicNode> reqs = Arrays.stream(h).map(x -> {
            String line = x[1].contains(":") ? x[1] : "Host: " + x[1];
            String raw = x[0].startsWith("Host")
                    ? "GET / HTTP/1.1\r\n" + line + "\r\n\r\n"
                    : "GET / HTTP/1.1\r\nHost: h.example.com\r\n" + line + "\r\n\r\n";
            return leakTest("richiesta / " + x[0], raw, x[2]);
        });
        String[][] r = {
                {"Set-Cookie", "Set-Cookie: sid=NEWSESS99887766; Path=/; HttpOnly", "NEWSESS99887766"},
                {"Set-Cookie Domain", "Set-Cookie: a=1; Domain=.clientecorp.it", "clientecorp.it"},
                {"Location", "Location: https://sso.clientecorp.it/login", "sso.clientecorp.it"},
                {"Server", "Server: Apache/2.4.41 (Ubuntu)", "2.4.41"},
                {"X-Powered-By", "X-Powered-By: PHP/7.4.3", "7.4.3"},
                {"X-AspNet-Version", "X-AspNet-Version: 4.0.30319", "4.0.30319"},
                {"WWW-Authenticate", "WWW-Authenticate: Basic realm=\"intranet.clientecorp.it\"", "intranet.clientecorp.it"},
                {"Access-Control-Allow-Origin", "Access-Control-Allow-Origin: https://portal.clientecorp.it", "portal.clientecorp.it"},
                {"Content-Security-Policy", "Content-Security-Policy: default-src 'self' https://cdn.clientecorp.it", "cdn.clientecorp.it"},
                {"Link", "Link: <https://api.clientecorp.it/p=2>; rel=\"next\"", "api.clientecorp.it"},
        };
        Stream<DynamicNode> resps = Arrays.stream(r).map(x ->
                leakTest("risposta / " + x[0], "HTTP/1.1 200 OK\r\n" + x[1] + "\r\n\r\n", x[2]));
        return Stream.of(DynamicContainer.dynamicContainer("richiesta", reqs),
                DynamicContainer.dynamicContainer("risposta", resps));
    }

    // ------------------------------------------------------------------ 5. stringhe di connessione e chiavi multilinea

    @TestFactory
    Stream<DynamicNode> segretiComplessi() {
        String[][] c = {
                {"postgres URI", "postgres://dbadmin:PgS3cret9@db.clientecorp.it:5432/prod", "PgS3cret9|db.clientecorp.it|dbadmin"},
                {"mysql URI", "mysql://root:MyS3cret8@10.1.2.3:3306/app", "MyS3cret8|10.1.2.3"},
                {"mongodb+srv URI", "mongodb+srv://app:M0ngoPwd@cluster0.ab1cd.mongodb.net/test", "M0ngoPwd"},
                {"redis URI", "redis://:R3disPass@10.1.2.3:6379", "R3disPass"},
                {"amqp URI", "amqp://guest:AmqpPwd77@mq.clientecorp.it:5672", "AmqpPwd77|mq.clientecorp.it"},
                {"ftp URI", "ftp://ftpuser:FtpPwd66@files.clientecorp.it/", "FtpPwd66|files.clientecorp.it"},
                {"https user:pass", "https://admin:P4ssw0rd@intranet.clientecorp.it/x", "P4ssw0rd|intranet.clientecorp.it"},
                {"JDBC", "jdbc:mysql://db.clientecorp.it:3306/app?user=root&password=MyJdbc1x", "MyJdbc1x|db.clientecorp.it"},
                {"Azure storage", "DefaultEndpointsProtocol=https;AccountName=clientstore;AccountKey=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4==;EndpointSuffix=core.windows.net", "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"},
                {"SQL Server", "Server=sql.clientecorp.it;Database=App;User Id=sa;Password=SqlPwd!55;", "SqlPwd!55|sql.clientecorp.it"},
                {"RSA private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretkeymaterialRSA\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEAsecretkeymaterialRSA"},
                {"PKCS8 private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc\n-----END PRIVATE KEY-----", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc"},
                {"OPENSSH private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"},
                {"EC private key", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oc\n-----END EC PRIVATE KEY-----", "MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oc"},
                {"PGP private key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF0secretPGPmaterial\n-----END PGP PRIVATE KEY BLOCK-----", "lQOYBF0secretPGPmaterial"},
                {"npm token", "//registry.npmjs.org/:_authToken=np" + "m_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "np" + "m_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"},
                {"Twilio SID", "A" + "C0123456789abcdef0123456789abcdef", "A" + "C0123456789abcdef0123456789abcdef"},
                {"Telegram bot token", "123456789:AA" + "HdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "AA" + "HdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"},
                {"Slack webhook", "https://hooks." + "slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX"},
                {"Discord webhook", "https://discord.com/api/" + "webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz", "AbCdEfGhIjKlMnOpQrStUvWxYz"},
                {"MAC address", "00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5E"},
                {"IBAN con spazi", "IT60 X054 2811 1010 0000 0123 456", "IT60 X054 2811 1010 0000 0123 456"},
                {"carta con spazi", "4111 1111 1111 1111", "4111 1111 1111 1111"},
                {"carta con trattini", "4111-1111-1111-1111", "4111-1111-1111-1111"},
                {"CF minuscolo", "rssmra80a01h501u", "rssmra80a01h501u"},
                {"telefono con trattini", "347-123-4567", "347-123-4567"},
                {"telefono UK", "+44 20 7946 0958", "7946 0958"},
                {"IPv4 con porta", "172.16.5.4:8080", "172.16.5.4"},
                {"IPv6 tra parentesi", "http://[2001:db8::1]:8080/", "2001:db8::1"},
                {"IPv6 link-local", "fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a"},
                {"IPv4-mapped IPv6", "::ffff:192.0.2.128", "192.0.2.128"},
                {"email percent-encoded", "mario%40clientecorp.it", "mario%40clientecorp.it"},
                {"email entity HTML", "mario&#64;clientecorp.it", "mario&#64;clientecorp.it"},
                {"email \\u0040", "mario\\u0040clientecorp.it", "mario\\u0040clientecorp.it"},
                {"dominio interno nudo", "server db01.corp.clientecorp.it down", "db01.corp.clientecorp.it"},
                {"dominio .local", "host fileserver.clientecorp.local", "fileserver.clientecorp.local"},
                {"hostname Windows UNC", "\\\\FS01.clientecorp.it\\share", "FS01.clientecorp.it"},
        };
        return Stream.of("testo", "JSON").map(fmt -> DynamicContainer.dynamicContainer(fmt,
                Arrays.stream(c).map(x -> {
                    String val = x[1];
                    String raw = fmt.equals("testo")
                            ? req("text/plain", "cfg: " + val + "\n")
                            : req("application/json", "{\"cfg\":\"" + val.replace("\\", "\\\\").replace("\n", "\\n") + "\"}");
                    return leakTest(fmt + " / " + x[0], raw, x[2].split("\\|"));
                })));
    }

    // ------------------------------------------------------------------ 6. falsi positivi

    @TestFactory
    Stream<DynamicNode> falsiPositivi() {
        String[][] fp = {
                {"JSON configurazione", "application/json", "{\"theme\":\"dark\",\"lang\":\"it\",\"pageSize\":50,\"enabled\":true,\"ratio\":0.75}"},
                {"data ISO", "application/json", "{\"created\":\"2026-11-07T10:20:30Z\",\"updated\":\"2026-11-08\"}"},
                {"versione semver", "application/json", "{\"version\":\"4.17.21\",\"node\":\"20.11.1\"}"},
                {"UUID", "application/json", "{\"orderId\":\"550e8400-e29b-41d4-a716-446655440000\"}"},
                {"ID numerici", "application/json", "{\"id\":12345678,\"ts\":1730985600000,\"price\":19.99}"},
                {"ID 16 cifre Luhn-valido", "application/json", "{\"tweet_id\":\"1234567812345670\"}"},
                {"hash git", "application/json", "{\"commit\":\"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\"}"},
                {"hash SHA-256 file", "application/json", "{\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"},
                {"codice errore", "application/json", "{\"error\":\"not_found\",\"code\":404,\"message\":\"Risorsa non trovata\"}"},
                {"valori null e boolean", "application/json", "{\"token\":null,\"password\":false,\"count\":0}"},
                {"JSON vuoto", "application/json", "{}"},
                {"pagina HTML", "text/html", "<!doctype html><html><head><title>Home</title><link rel=\"stylesheet\" href=\"/css/app.css\"></head><body class=\"main\"><h1>Benvenuto</h1><a href=\"/about\">Chi siamo</a></body></html>"},
                {"file statici", "text/html", "<script src=\"/static/app.min.js\"></script><img src=\"/img/logo.png\" alt=\"logo\">"},
                {"immagine data: base64", "text/html", "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\">"},
                {"CSS", "text/css", "body{color:#1a2b3c;margin:0 auto}@media screen and (max-width:600px){.nav{display:none}}"},
                {"JavaScript", "application/javascript", "function a(b){return b.map(function(c){return c*2}).filter(Boolean)}"},
                {"testo italiano", "text/plain", "Il pagamento di 25,00 euro e' stato effettuato il 7 novembre alle 10.30."},
                {"testo inglese", "text/plain", "The quick brown fox jumps over the lazy dog. Version 2 is out now."},
                {"pacchetto npm", "application/json", "{\"dependencies\":{\"@types/node\":\"^20.0.0\",\"lodash\":\"4.17.21\"}}"},
                {"handle social", "text/plain", "Seguici su @clientofficial"},
                {"numeri brevi", "text/plain", "Ordine 4521, quantita' 3, totale 129"},
                {"orari e percentuali", "text/plain", "Apertura 08:30-19:00, sconto 15%, rating 4.5/5"},
                {"coordinate", "application/json", "{\"lat\":45.4642,\"lng\":9.1900}"},
                {"localhost", "text/plain", "in ascolto su localhost:8080"},
                {"nomi dei campi sensibili senza valore", "text/plain", "Inserisci la tua password e il token nel modulo."},
                {"enum stato", "application/json", "{\"status\":\"active\",\"role\":\"admin\",\"type\":\"premium\"}"},
                {"user agent nel body", "text/plain", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.6099.109 Safari/537.36"},
                {"codice HTML in <code>", "text/html", "<p>Esempio:</p><code>npm install lodash</code><pre><code>let x = 1;</code></pre>"},
                {"form HTML senza valori", "text/html", "<form method=\"post\" action=\"/login\"><input type=\"text\" name=\"username\"><input type=\"password\" name=\"password\" autocomplete=\"current-password\"><button type=\"submit\">Accedi</button></form>"},
                {"label e placeholder", "text/html", "<label for=\"pwd\">Password</label><input id=\"pwd\" name=\"pwd\" placeholder=\"La tua password\">"},
                {"script SRI integrity", "text/html", "<script src=\"/js/app.js\" integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\" crossorigin=\"anonymous\"></script>"},
                {"JSON con metadati del token", "application/json", "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"session_timeout\":900,\"password_policy\":\"strong\"}"},
                {"JSON formattato su piu' righe", "application/json", "{\n  \"status\": \"ok\",\n  \"items\": [\n    1,\n    2\n  ],\n  \"note\": \"tutto bene\"\n}"},
                {"JSON con escape unicode", "application/json", "{\"citta\":\"Citt\\u00e0\",\"path\":\"a\\/b\"}"},
                {"JSON con spazi attorno ai due punti", "application/json", "{ \"a\" : 1 , \"b\" : [ true , null ] }"},
                {"codice JavaScript", "application/javascript", "const config = { retries: 3, timeout: 5000, mode: 'cors' };\nfunction login(user) { return fetch('/api/login', { method: 'POST' }); }"},
                {"YAML innocuo", "application/x-yaml", "server:\n  port: 8080\n  threads: 4\nlogging:\n  level: info\n"},
                {"CSV innocuo", "text/csv", "prodotto,quantita,prezzo\nscarpe,2,49.90\nmaglia,1,19.00\n"},
                {"log applicativo", "text/plain", "2026-11-07 10:20:30 INFO Avvio completato in 532 ms (versione 3.4.1)"},
                {"messaggio con 'code' e 'key'", "application/json", "{\"code\":\"ORDER_NOT_FOUND\",\"key\":\"ui.title\",\"ticket\":\"none\"}"},
                {"prezzi e quantita' grandi", "text/plain", "Totale: 1.234.567,89 EUR per 10 000 pezzi, anno 2019-2024"},
                {"numero d'ordine lungo", "application/json", "{\"order_number\":\"20261107123456\"}"},
                {"timestamp nel testo", "text/plain", "generato il 1730985600 (epoch) e 1730985600000 ms"},
                {"JavaScript con membri tipo dominio", "application/javascript", "window.App = {}; user.name = data.info; res.app.use(x); this.me = e.store;"},
                {"JavaScript assegnazioni tra riferimenti", "application/javascript", "e.token=t.session;r.password=n.value;headers.Authorization=\"Bearer \"+t;"},
                {"namespace SOAP/XML standard", "text/xml", "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soap:Body/></soap:Envelope>"},
                {"nomi di file con estensioni", "text/plain", "allegati: report.pdf, app.min.js, style.css, foto.jpeg, backup.tar.gz, setup.exe"},
        };
        Stream<DynamicNode> bodies = Arrays.stream(fp).map(x -> DynamicTest.dynamicTest(x[0], () -> {
            String out = body(run(req(x[1], x[2])));
            assertEquals(x[2], out, "contenuto innocuo modificato");
        }));
        String[] headers = {
                "Accept: application/json, text/plain, */*",
                "Accept-Language: it-IT,it;q=0.9,en-US;q=0.8",
                "Accept-Encoding: gzip, deflate, br",
                "Cache-Control: no-cache",
                "Connection: keep-alive",
                "Content-Type: application/json; charset=utf-8",
                "Sec-Fetch-Mode: cors",
                "Sec-Ch-Ua-Platform: \"Windows\"",
                "Upgrade-Insecure-Requests: 1",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36",
                "Pragma: no-cache",
                "DNT: 1",
                "X-Requested-With: XMLHttpRequest",
        };
        Stream<DynamicNode> hdr = Arrays.stream(headers).map(hl -> DynamicTest.dynamicTest("header " + hl.substring(0, hl.indexOf(':')), () -> {
            String out = run(get("/", hl + "\r\n"));
            assertTrue(out.contains(hl), "header innocuo modificato: " + hl + "\n" + out);
        }));
        String[] lines = {
                "GET /api/v1/orders/42 HTTP/1.1",
                "GET /search?q=scarpe&sort=price&page=3 HTTP/1.1",
                "DELETE /api/items/7 HTTP/1.1",
                "OPTIONS * HTTP/1.1",
        };
        Stream<DynamicNode> rl = Arrays.stream(lines).map(l -> DynamicTest.dynamicTest("request line " + l, () -> {
            String out = run(l + "\r\nHost: h.example.com\r\n\r\n");
            assertTrue(out.startsWith(l + "\r\n"), "request line modificata:\n" + out);
        }));
        return Stream.of(DynamicContainer.dynamicContainer("body", bodies),
                DynamicContainer.dynamicContainer("header", hdr),
                DynamicContainer.dynamicContainer("request line", rl));
    }

    // ------------------------------------------------------------------ 7. reversibilita'

    @TestFactory
    Stream<DynamicNode> roundTrip() {
        String[] places = {"body testo", "JSON chiave neutra", "JSON risposta", "XML elemento", "HTML testo", "header neutro"};
        Stream<DynamicNode> gen = Arrays.stream(places).map(pl -> DynamicContainer.dynamicContainer(pl,
                Arrays.stream(PATTERN_SECRETS).map(s -> DynamicTest.dynamicTest(pl + " / " + s[0], () -> {
                    String raw = PLACES.get(pl).apply(s[1]);
                    Anonymizer an = fresh();
                    String out = run(an, raw);
                    String back = Anonymizer.deanonymize(out, an.getMap().reverseMap());
                    assertEquals(raw, back, "de-anonimizzazione non restituisce l'originale");
                }))));
        String[][] real = {
                {"login JSON", req("application/json", "{\"email\":\"rt@clientecorp.it\",\"password\":\"RtPwd1x\",\"iban\":\"IT60X0542811101000000123456\"}")},
                {"URL in HTML", resp("text/html", "<a href=\"https://shop.clientecorp.it/p?id=1\">negozio</a>")},
                {"URL in JSON", resp("application/json", "{\"next\":\"https://api.clientecorp.it/v2/items?page=2\"}")},
                {"host in header e body", "GET /x HTTP/1.1\r\nHost: api.clientecorp.it\r\nReferer: https://api.clientecorp.it/a\r\nContent-Type: text/plain\r\n\r\nvedi https://api.clientecorp.it/b"},
                {"redirect", "HTTP/1.1 302 Found\r\nLocation: https://sso.clientecorp.it/login?next=%2Fhome\r\n\r\n"},
                {"cookie e bearer", get("/", "Authorization: Bearer RoundTok123456\r\nCookie: sid=RT_SESSION_99; theme=dark\r\n")},
        };
        Stream<DynamicNode> rs = Arrays.stream(real).map(x -> DynamicTest.dynamicTest(x[0], () -> {
            Anonymizer an = fresh();
            String out = run(an, x[1]);
            String back = Anonymizer.deanonymize(out, an.getMap().reverseMap());
            assertEquals(x[1], back, "de-anonimizzazione non restituisce l'originale");
        }));
        return Stream.of(DynamicContainer.dynamicContainer("generati", gen),
                DynamicContainer.dynamicContainer("realistici", rs));
    }

    // ------------------------------------------------------------------ 8. invarianti su tutti i casi

    @TestFactory
    Stream<DynamicNode> invarianti() {
        List<DynamicNode> out = new ArrayList<>();
        for (Map.Entry<String, Function<String, String>> p : PLACES.entrySet()) {
            String raw = p.getValue().apply("mario.rossi@clientecorp.it 93.45.122.8 https://api.clientecorp.it/x");
            out.add(DynamicTest.dynamicTest("mappa senza segnaposto ri-anonimizzati / " + p.getKey(), () -> {
                Anonymizer an = fresh();
                run(an, raw);
                for (SubstitutionMap.Entry e : an.getMap().entries())
                    assertFalse(PLACEHOLDER_LIKE.matcher(e.original).matches(),
                            "un segnaposto e' stato anonimizzato di nuovo: " + e.placeholder + " <- " + e.original);
            }));
            out.add(DynamicTest.dynamicTest("idempotenza / " + p.getKey(), () -> {
                String once = run(raw);
                String twice = run(once);
                assertEquals(once, twice, "ri-anonimizzare l'output lo modifica");
            }));
            out.add(DynamicTest.dynamicTest("struttura preservata / " + p.getKey(), () -> {
                String o = run(raw);
                String[] a = raw.split("\r\n", -1), b = o.split("\r\n", -1);
                assertEquals(a[0].split(" ")[0], b[0].split(" ")[0], "metodo o versione cambiati");
                int ha = raw.indexOf("\r\n\r\n"), hb = o.indexOf("\r\n\r\n");
                assertEquals(ha >= 0, hb >= 0, "riga vuota tra header e body persa");
                List<String> na = new ArrayList<>(), nb = new ArrayList<>();
                for (String l : raw.substring(0, Math.max(ha, 0)).split("\r\n")) if (l.contains(":")) na.add(l.substring(0, l.indexOf(':')));
                for (String l : o.substring(0, Math.max(hb, 0)).split("\r\n")) if (l.contains(":")) nb.add(l.substring(0, l.indexOf(':')));
                assertEquals(na, nb, "nomi degli header cambiati");
            }));
        }
        String[] jsons = {
                "{\"a\":1,\"b\":[1,2,{\"c\":\"x@clientecorp.it\"}],\"password\":\"p\",\"n\":null,\"t\":true}",
                "[{\"email\":\"a@clientecorp.it\"},{\"email\":\"b@clientecorp.it\"}]",
                "{\"s\":\"virgolette \\\" e backslash \\\\ e unicode \\u00e8\",\"token\":\"t\\\"x\"}",
                "{\"deep\":{\"a\":{\"b\":{\"c\":{\"d\":{\"password\":\"x\"}}}}}}",
        };
        for (String j : jsons) {
            out.add(DynamicTest.dynamicTest("JSON valido resta valido / " + j.substring(0, Math.min(40, j.length())), () -> {
                String o = body(run(req("application/json", j)));
                assertDoesNotThrow(() -> JsonParser.parseString(o), "JSON non piu' valido: " + o);
            }));
        }
        out.add(DynamicTest.dynamicTest("campi null non spariscono", () -> {
            String o = body(run(req("application/json", "{\"token\":null,\"a\":1}")));
            assertTrue(o.contains("\"token\""), "il campo null e' stato rimosso: " + o);
        }));
        out.add(DynamicTest.dynamicTest("ordine dei campi JSON preservato", () -> {
            String o = body(run(req("application/json", "{\"z\":1,\"a\":2,\"m\":3}")));
            assertTrue(o.indexOf("\"z\"") < o.indexOf("\"a\"") && o.indexOf("\"a\"") < o.indexOf("\"m\""), o);
        }));
        return out.stream();
    }

    // ------------------------------------------------------------------ 9. coerenza

    @TestFactory
    Stream<DynamicNode> coerenza() {
        List<DynamicNode> out = new ArrayList<>();
        for (String[] s : PATTERN_SECRETS) {
            out.add(DynamicTest.dynamicTest("stesso valore in richiesta e risposta -> un segnaposto / " + s[0], () -> {
                Anonymizer an = fresh();
                String a = run(an, req("text/plain", "uno " + s[1] + " fine"));
                String b = run(an, resp("application/json", "{\"note\":\"" + s[1] + "\"}"));
                long n = an.getMap().entries().stream().filter(e -> e.original.equalsIgnoreCase(s[1])).count();
                assertEquals(1, n, "valore mappato " + n + " volte");
                String ph = an.getMap().entries().stream().filter(e -> e.original.equalsIgnoreCase(s[1])).findFirst().get().placeholder;
                assertTrue(a.contains(ph) && b.contains(ph), "segnaposto diversi tra richiesta e risposta");
            }));
        }
        String[][] cases = {
                {"email maiuscole/minuscole", "Mario@Clientecorp.it", "mario@clientecorp.it"},
                {"host maiuscole/minuscole", "API.Clientecorp.IT", "api.clientecorp.it"},
                {"IBAN maiuscole/minuscole", "IT60X0542811101000000123456", "it60x0542811101000000123456"},
        };
        for (String[] c : cases) {
            out.add(DynamicTest.dynamicTest(c[0] + " -> stesso segnaposto", () -> {
                Anonymizer an = fresh();
                String o = body(run(an, req("text/plain", c[1] + " e " + c[2])));
                String[] parts = o.split(" e ");
                assertEquals(parts[0], parts[1], "segnaposto diversi: " + o);
            }));
        }
        out.add(DynamicTest.dynamicTest("molti valori: nessuna collisione tra segnaposto", () -> {
            Anonymizer an = fresh();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 150; i++) sb.append("u").append(i).append("@clientecorp.it ");
            run(an, req("text/plain", sb.toString()));
            Map<String, String> rev = an.getMap().reverseMap();
            assertEquals("u0@clientecorp.it u9@clientecorp.it u99@clientecorp.it u149@clientecorp.it",
                    Anonymizer.deanonymize("EMAIL_1 EMAIL_10 EMAIL_100 EMAIL_150", rev));
        }));
        return out.stream();
    }

    // ------------------------------------------------------------------ 10. de-anonimizzazione

    @TestFactory
    Stream<DynamicNode> deanonimizzazione() {
        Anonymizer an = fresh();
        run(an, "POST /api HTTP/1.1\r\nHost: api.clientecorp.it\r\nContent-Type: text/plain\r\n\r\na@clientecorp.it 93.45.122.8");
        Map<String, String> rev = an.getMap().reverseMap();
        String[][] c = {
                {"confini di parola", "EMAIL_1a XEMAIL_1 EMAIL_1_x", "EMAIL_1a XEMAIL_1 EMAIL_1_x"},
                {"punteggiatura", "(EMAIL_1), \"IP_1\".", "(a@clientecorp.it), \"93.45.122.8\"."},
                {"markdown", "`HOST_1` e **IP_1**", "`api.clientecorp.it` e **93.45.122.8**"},
                {"dentro URL", "https://HOST_1/admin", "https://api.clientecorp.it/admin"},
                {"segnaposto sconosciuto", "EMAIL_99 resta", "EMAIL_99 resta"},
                {"testo vuoto", "", ""},
                {"segnaposto minuscolo (LLM)", "email_1", "email_1"},
        };
        return Arrays.stream(c).map(x -> DynamicTest.dynamicTest(x[0], () ->
                assertEquals(x[2], Anonymizer.deanonymize(x[1], rev))));
    }

    // ------------------------------------------------------------------ 11. controlli utente

    @TestFactory
    Stream<DynamicNode> controlliUtente() {
        return Stream.of(
                DynamicTest.dynamicTest("valore escluso resta in chiaro", () -> {
                    Anonymizer an = new Anonymizer(Config.loadFromResources(), new SubstitutionMap(Set.of("keep@clientecorp.it")));
                    String o = run(an, req("text/plain", "keep@clientecorp.it hide@clientecorp.it"));
                    assertTrue(o.contains("keep@clientecorp.it"));
                    assertNoLeak(o, "hide@clientecorp.it");
                }),
                DynamicTest.dynamicTest("selezione manuale copre ogni occorrenza", () -> {
                    Anonymizer an = new Anonymizer(Config.loadFromResources(), new SubstitutionMap(), Overrides.empty().withForced(List.of("ProgettoAquila")));
                    String o = run(an, "GET /p/ProgettoAquila HTTP/1.1\r\nHost: h.example.com\r\nX-Project: ProgettoAquila\r\nContent-Type: application/json\r\n\r\n{\"n\":\"ProgettoAquila\"}");
                    assertFalse(o.contains("ProgettoAquila"), o);
                }),
                DynamicTest.dynamicTest("selezione manuale ignora maiuscole", () -> {
                    Anonymizer an = new Anonymizer(Config.loadFromResources(), new SubstitutionMap(), Overrides.empty().withForced(List.of("ProgettoAquila")));
                    assertNoLeak(run(an, req("text/plain", "progettoaquila PROGETTOAQUILA")), "progettoaquila");
                }),
                DynamicTest.dynamicTest("selezione manuale con caratteri speciali regex", () -> {
                    Anonymizer an = new Anonymizer(Config.loadFromResources(), new SubstitutionMap(), Overrides.empty().withForced(List.of("a.b*c(d)[e]$")));
                    assertNoLeak(run(an, req("text/plain", "x a.b*c(d)[e]$ y")), "a.b*c(d)[e]$");
                })
        );
    }

    // ------------------------------------------------------------------ 12. robustezza

    @TestFactory
    Stream<DynamicNode> inputPatologici() {
        String[][] evil = {
                {"200k lettere", "a".repeat(200_000)},
                {"a@ ripetuto", "a@".repeat(50_000)},
                {"a. ripetuto (4k caratteri)", "a.".repeat(2_000) + "@"},
                {"a. ripetuto (100k caratteri)", "a.".repeat(50_000) + "@"},
                {"cifre", "1".repeat(200_000)},
                {"cifre e spazi", "1 ".repeat(100_000)},
                {"1.1. ripetuto", "1.1.".repeat(10_000)},
                {"PEM senza fine", "-----BEGIN PRIVATE KEY-----" + "A".repeat(200_000)},
                {"JWT gigante", "eyJ" + "a".repeat(200_000) + "."},
                {"email gigante", "x".repeat(100_000) + "@" + "y.".repeat(10_000) + "it"},
                {"percentuali", "%".repeat(100_000)},
                {"graffe aperte", "{".repeat(100_000)},
                {"virgolette", "\"".repeat(100_000)},
                {"tag aperti", "<".repeat(100_000)},
                {"URL con dominio lungo", "https://" + "a.".repeat(10_000) + "com"},
                {"due punti", "::".repeat(100_000)},
                {"+39 ripetuto", "+39 ".repeat(50_000)},
                {"JSON profondo 10k", "[".repeat(10_000) + "]".repeat(10_000)},
                {"riga lunghissima header", "x".repeat(500_000)},
                {"byte nulli", "\u0000".repeat(10_000)},
                {"surrogate spaiati", "\uD800\uDC00\uD800x".repeat(10_000)},
                {"emoji", "\uD83D\uDE00".repeat(50_000)},
                {"percent UTF-8 non valido", "%E2%82".repeat(2_000) + " x%40clientecorp.it"},
                {"percent annidato profondo", "%25".repeat(5_000) + "40"},
                {"entita' HTML ripetute", "&#64;&amp;".repeat(20_000)},
                {"candidati base64 di ogni lunghezza", "ab12CDefgh3J ab12CDefgh3JK ab12CDefgh3JKL ab12CDefgh3JKLm ab12CDefgh3JKLmn= x"},
        };
        String[] cts = {"text/plain", "application/json", "application/x-www-form-urlencoded", "text/html", "application/xml"};
        return Arrays.stream(cts).map(ct -> DynamicContainer.dynamicContainer(ct,
                Arrays.stream(evil).map(e -> DynamicTest.dynamicTest(ct + " / " + e[0], () -> {
                    String raw = e[0].startsWith("riga lunghissima")
                            ? "GET / HTTP/1.1\r\nHost: h.example.com\r\nX-Long: " + e[1] + "\r\n\r\n"
                            : req(ct, e[1]);
                    assertDoesNotThrow(() -> run(raw));
                }))));
    }

    @TestFactory
    Stream<DynamicNode> fuzz() {
        String[] parts = {"GET / HTTP/1.1\r\n", "HTTP/1.1 200 OK\r\n", "Host: ", "a.clientecorp.it", "\r\n", "Cookie: ", "=", ";",
                "Content-Type: ", "application/json", "application/x-www-form-urlencoded", "text/html", "application/xml",
                "multipart/form-data; boundary=b", "--b", "Content-Disposition: form-data; name=\"x\"", "{", "}", "\"", ":", ",", "[", "]",
                "Transfer-Encoding: chunked\r\n", "0\r\n\r\n", "5\r\n", "ffffffff\r\n", "%", "%zz", "%E2%82", "&", "@", "\u00e8",
                "\uD83D\uDE00", "\uD800", "\u0000", "Authorization: Bearer ", "Basic ", "<x>", "</x>", "<!--", "<![CDATA[", "eyJ",
                ".", "4111111111111111", "IT60X", "\n", "\r\n\r\n", "password", "query", "mutation{", "\\", "\\u00", "-----BEGIN PRIVATE KEY-----"};
        return Stream.of(1L, 2L, 3L, 4L, 5L).map(seed -> DynamicTest.dynamicTest("fuzz seed " + seed + " (2000 messaggi)", () ->
                assertTimeoutPreemptively(Duration.ofSeconds(90), () -> fuzzSeed(seed, parts), "fuzz bloccato")));
    }

    private static void fuzzSeed(long seed, String[] parts) {
        {
            Random rnd = new Random(seed);
            for (int n = 0; n < 2000; n++) {
                StringBuilder sb = new StringBuilder();
                int len = 1 + rnd.nextInt(80);
                for (int k = 0; k < len; k++) sb.append(parts[rnd.nextInt(parts.length)]);
                String raw = sb.toString();
                try {
                    Anonymizer an = fresh();
                    an.anonymizeRequest(raw);
                    an.anonymizeResponse(raw);
                    Anonymizer.deanonymize(raw, an.getMap().reverseMap());
                } catch (Throwable t) {
                    fail("crash (" + t + ") sull'input: " + raw.replace("\r\n", "\\r\\n"));
                }
            }
        }
    }

    // ------------------------------------------------------------------ 13. prestazioni

    private static long timeMs(String raw) {
        long t0 = System.nanoTime();
        run(raw);
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static String jsonList(int n, String fieldTemplate) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < n; i++) {
            if (i > 0) b.append(',');
            b.append(fieldTemplate.replace("#", String.valueOf(i))
                    .replace("%A", String.valueOf(i / 256 % 256)).replace("%B", String.valueOf(i % 256)));
        }
        return b.append(']').toString();
    }

    @TestFactory
    Stream<DynamicNode> prestazioni() {
        String[][] kinds = {
                {"email diverse", "{\"email\":\"u#@clientecorp.it\"}"},
                {"IP diversi", "{\"ip\":\"10.0.%A.%B\"}"},
                {"host diversi", "{\"url\":\"https://s#.clientecorp.it/x\"}"},
                {"token diversi", "{\"token\":\"tok#abcdef\"}"},
        };
        List<DynamicNode> out = new ArrayList<>();
        for (String[] k : kinds) {
            out.add(DynamicTest.dynamicTest(k[0] + ": 3000 valori in meno di 3 s", () -> {
                run(req("application/json", jsonList(200, k[1]))); // warm-up
                long ms = timeMs(req("application/json", jsonList(3000, k[1])));
                assertTrue(ms < 3000, "troppo lento: " + ms + " ms");
            }));
            out.add(DynamicTest.dynamicTest(k[0] + ": crescita lineare (4x valori -> max 8x tempo)", () -> {
                run(req("application/json", jsonList(200, k[1])));
                long a = Math.max(20, timeMs(req("application/json", jsonList(500, k[1]))));
                long b = timeMs(req("application/json", jsonList(2000, k[1])));
                assertTrue(b < a * 8, "crescita non lineare: 500 valori " + a + " ms, 2000 valori " + b + " ms");
            }));
        }
        out.add(DynamicTest.dynamicTest("body testo 1 MB in meno di 3 s", () -> {
            long ms = timeMs(req("text/plain", "lorem ipsum dolor sit amet, contatto x@clientecorp.it ".repeat(20_000)));
            assertTrue(ms < 3000, "troppo lento: " + ms + " ms");
        }));
        out.add(DynamicTest.dynamicTest("pagina HTML 1 MB in meno di 3 s", () -> {
            long ms = timeMs(resp("text/html", "<div class=\"item\"><a href=\"/p/1\">Prodotto</a><span>19,99</span></div>".repeat(15_000)));
            assertTrue(ms < 3000, "troppo lento: " + ms + " ms");
        }));
        return out.stream();
    }
}
