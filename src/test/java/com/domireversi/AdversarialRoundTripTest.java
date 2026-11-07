package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.SubstitutionMap;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test avversariale di pseudonimizzazione reversibile su request + response
 * della stessa sessione. Input letto byte per byte da src/test/resources/adversarial
 * senza alcuna modifica. Genera build/reports/adversarial/report.md.
 */
class AdversarialRoundTripTest {

    private static String reqRaw, respRaw, reqOut, respOut, reqBack, respBack;
    private static SubstitutionMap map;
    private static long elapsedMs;
    private static final Map<String, String> results = new LinkedHashMap<>();
    private static final List<String> details = new ArrayList<>();

    /** Valori sensibili presenti nei messaggi (devono sparire dall'output). */
    private static final String[] SENSITIVE = {
            "mario@example.com", "mario+test@example.com", "luca@example.com", "192.168.1.100", "10.0.0.5",
            "abc123XYZ", "refresh_987654321", "sk_live_EXAMPLE_SECRET_123456", "P@ssw0rd!EMAIL_1",
            "Mario Rossi", "+39 333 1234567", "+39 333 7654321", "Via Roma 123", "Milano", "other_secret_987",
            "api.example.com", "mario%40example.com", "mario%2540example.com", "mario&#64;example.com",
            "bWFyaW9AZXhhbXBsZS5jb20=", "6d6172696f406578616d706c652e636f6d",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYXJpbyIsImVtYWlsIjoibWFyaW9AZXhhbXBsZS5jb20ifQ.signature"};

    private static String resource(String path) throws Exception {
        try (InputStream in = AdversarialRoundTripTest.class.getResourceAsStream(path)) {
            return new String(Objects.requireNonNull(in, path).readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @BeforeAll
    static void run() throws Exception {
        reqRaw = resource("/adversarial/request.http");
        respRaw = resource("/adversarial/response.http");
        long t0 = System.nanoTime();
        map = new SubstitutionMap();
        Anonymizer an = new Anonymizer(Config.loadFromResources(), map);
        an.reserveLiterals(reqRaw, respRaw); // sessione: entrambi i messaggi prima di generare
        reqOut = an.anonymizeRequest(reqRaw);
        respOut = an.anonymizeResponse(respRaw);
        Map<String, String> rev = map.reverseMap();
        reqBack = Anonymizer.deanonymize(reqOut, rev);
        respBack = Anonymizer.deanonymize(respOut, rev);
        elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    }

    private static void record(String id, String name, boolean ok, String why) {
        results.put(id + ". " + name, ok ? "PASS" : "FAIL");
        if (!ok) details.add(id + ": " + why);
    }

    private static String rootOf(String ph) {
        Matcher m = Pattern.compile("^([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\\d+)").matcher(ph);
        return m.find() ? m.group(1) : ph;
    }

    private static int count(String s, String sub) {
        int n = 0, i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) { n++; i += sub.length(); }
        return n;
    }

    private static int countToken(String s, String tok) {
        Matcher m = Pattern.compile("(?<![A-Za-z0-9_])" + Pattern.quote(tok) + "(?![A-Za-z0-9_])").matcher(s);
        int n = 0;
        while (m.find()) n++;
        return n;
    }

    private static String firstDiff(String a, String b) {
        int i = 0;
        while (i < a.length() && i < b.length() && a.charAt(i) == b.charAt(i)) i++;
        if (i == a.length() && i == b.length()) return "nessuna";
        return "offset " + i + ": atteso «" + a.substring(i, Math.min(a.length(), i + 40)).replace("\n", "\\n")
                + "» trovato «" + b.substring(i, Math.min(b.length(), i + 40)).replace("\n", "\\n") + "»";
    }

    @Test
    void adversarialSession() throws Exception {
        Map<String, String> rev = map.reverseMap();
        List<SubstitutionMap.Entry> entries = map.entries();

        // 1. stesso dato -> stesso placeholder in request e response
        boolean ok1 = true;
        StringBuilder w1 = new StringBuilder();
        for (String v : new String[]{"mario@example.com", "192.168.1.100", "abc123XYZ", "Mario Rossi",
                "+39 333 1234567", "luca@example.com", "refresh_987654321", "+39 333 7654321"}) {
            List<String> phs = new ArrayList<>();
            for (SubstitutionMap.Entry e : entries) if (e.original.equals(v)) phs.add(e.placeholder);
            if (phs.size() != 1) { ok1 = false; w1.append(v).append(" -> ").append(phs).append("; "); continue; }
            String ph = phs.get(0);
            if (reqRaw.contains(v) && countToken(reqOut, ph) == 0) { ok1 = false; w1.append(ph).append(" assente nella request; "); }
            if (respRaw.contains(v) && countToken(respOut, ph) == 0) { ok1 = false; w1.append(ph).append(" assente nella response; "); }
        }
        record("1", "Stesso dato, stesso placeholder in request e response", ok1, w1.toString());

        // 2. letterali EMAIL_1 / TOKEN_1 / HOST_1 non confusi con placeholder generati
        boolean ok2 = true;
        for (String lit : new String[]{"EMAIL_1", "EMAIL_2", "EMAIL_10", "TOKEN_1", "HOST_1"}) {
            if (rev.containsKey(lit) || map.isEmitted(lit)) { ok2 = false; details.add("2: generato placeholder uguale al letterale " + lit); }
            int inOrig = countToken(reqRaw, lit) + countToken(respRaw, lit);
            // le occorrenze dentro un valore mascherato per intero (es. la password "P@ssw0rd!EMAIL_1") spariscono legittimamente
            for (SubstitutionMap.Entry e : entries) {
                if (e.original.equals(lit)) continue;
                int inside = countToken(e.original, lit);
                if (inside > 0) inOrig -= inside * (count(reqRaw, e.original) + count(respRaw, e.original));
            }
            int inOut = countToken(reqOut, lit) + countToken(respOut, lit);
            if (inOrig != inOut) { ok2 = false; details.add("2: occorrenze di " + lit + " originale=" + inOrig + " output=" + inOut); }
        }
        record("2", "Letterali EMAIL_1/TOKEN_1/HOST_1 non confusi con placeholder", ok2, "");

        // 3. nessuna sostituzione parziale
        boolean ok3 = reqOut.contains("\"prefix_EMAIL_1_suffix\"") && reqOut.contains("\"NOT_EMAIL_1\"")
                && reqOut.contains("\"EMAIL_10\"") && reqBack.contains("\"prefix_EMAIL_1_suffix\"");
        record("3", "EMAIL_1 / EMAIL_10 / prefix_EMAIL_1_suffix / NOT_EMAIL_1 senza sostituzioni parziali", ok3, "stringhe alterate");

        // 4. ripetizioni coerenti: ogni originale ha un solo placeholder radice
        Map<String, Set<String>> roots = new HashMap<>();
        for (SubstitutionMap.Entry e : entries) {
            if (e.placeholder.equals("REDACTED")) continue;
            String root = rootOf(e.placeholder);
            String rootOrig = map.originalOf(root);
            roots.computeIfAbsent(rootOrig == null ? e.original : rootOrig, k -> new HashSet<>()).add(root);
        }
        boolean ok4 = roots.values().stream().allMatch(s -> s.size() == 1);
        record("4", "Valori ripetuti coerenti", ok4, roots.toString());

        // 5-6. nessuna collisione: un placeholder -> un solo originale, originali diversi -> placeholder diversi
        Map<String, Set<String>> phToOrig = new HashMap<>();
        for (SubstitutionMap.Entry e : entries) phToOrig.computeIfAbsent(e.placeholder, k -> new HashSet<>()).add(e.original);
        long collisions = phToOrig.entrySet().stream()
                .filter(e -> !e.getKey().equals("REDACTED") && e.getValue().size() > 1).count();
        record("5", "Valori differenti non collidono", collisions == 0, phToOrig.toString());
        Map<String, Set<String>> typesPerPh = new HashMap<>();
        for (SubstitutionMap.Entry e : entries) typesPerPh.computeIfAbsent(e.placeholder, k -> new HashSet<>()).add(e.type);
        boolean ok6 = typesPerPh.values().stream().allMatch(s -> s.size() == 1);
        record("6", "Nessuna collisione tra categorie diverse", ok6, typesPerPh.toString());

        // 7. codifiche: nessuna fuga e rappresentazione originale ricostruita
        boolean ok7 = true;
        for (String enc : new String[]{"mario%40example.com", "mario%2540example.com", "mario&#64;example.com",
                "bWFyaW9AZXhhbXBsZS5jb20=", "6d6172696f406578616d706c652e636f6d", "luca%2540example.com"}) {
            if (reqOut.contains(enc) || respOut.contains(enc)) { ok7 = false; details.add("7: forma codificata in chiaro: " + enc); }
            if (count(reqRaw, enc) + count(respRaw, enc) != count(reqBack, enc) + count(respBack, enc)) {
                ok7 = false; details.add("7: rappresentazione non ricostruita: " + enc);
            }
        }
        record("7", "Stringhe codificate gestite senza perdere la rappresentazione", ok7, "");

        // 8. Unicode conservato esattamente
        boolean ok8 = reqOut.contains("X-Unicode: àèìòù-你好-مرحبا-😀-é")
                && reqOut.contains("\"unicode\": \"👨‍👩‍👧‍👦 é é ñ 中文 العربية\"");
        record("8", "Unicode conservato esattamente", ok8, "unicode alterato");

        // 9. header duplicati
        record("9", "Header duplicati mantenuti", count(reqOut, "\nX-Collision:") == 2 && count(respOut, "\nSet-Cookie:") == 2, "duplicati persi");

        // 10. cookie e Set-Cookie
        boolean ok10 = reqOut.contains("Cookie: session=") && !reqOut.matches("(?s).*Cookie: session=abc123XYZ.*")
                && reqOut.contains("; preference=EMAIL_1") && respOut.contains("; HttpOnly; Secure; SameSite=Lax")
                && respOut.contains("; Path=/; Secure") && !respOut.contains("user_email=mario@example.com");
        record("10", "Cookie e Set-Cookie elaborati correttamente", ok10, "cookie alterati");

        // 11. vuoti, null, spazi
        boolean ok11 = reqOut.contains("\nX-Empty:\n") && reqOut.contains("\nX-Whitespace:    \n")
                && reqOut.contains("\"empty\": \"\"") && reqOut.contains("\"null\": null") && reqOut.contains("\"spaces\": \"   \"");
        record("11", "Campi vuoti, null e spazi non alterati", ok11, "vuoti/spazi alterati");

        // 12. caratteri speciali / regex / HTML / JS
        boolean ok12 = reqOut.contains("\"special\": \"<script>alert('") && reqOut.contains("')</script>\"")
                && reqOut.contains("\"regex\": \"a+b*c? [") && reqOut.contains("] (TOKEN_1) {EMAIL_1}\"");
        record("12", "Caratteri speciali, regex, HTML e JavaScript senza sostituzioni errate", ok12, "struttura alterata");

        // 13. sovrapposizioni: nessuna fuga e ricostruzione esatta
        boolean ok13 = !reqOut.contains("mario@example.com") && reqBack.contains("\"overlap\": \"mario@example.com.mario@example.com\"")
                && reqBack.contains("\"similar\": \"mario@example.co mario@example.comx x.mario@example.com\"");
        record("13", "Nessun problema di sovrapposizione tra valori", ok13, "sovrapposizione errata");

        // 14. decodifica solo con la mappa della sessione corrente
        SubstitutionMap other = new SubstitutionMap();
        Anonymizer oa = new Anonymizer(Config.loadFromResources(), other);
        oa.anonymizeRequest("POST /x HTTP/1.1\r\nHost: altro.it\r\nContent-Type: application/json\r\n\r\n{\"email\":\"zeta@altro.it\",\"token\":\"ZZ99yy88\"}");
        boolean ok14 = !Anonymizer.deanonymize(reqOut, other.reverseMap()).equals(reqRaw);
        record("14", "Decodifica solo con il mapping della sessione corrente", ok14, "un altro mapping ricostruisce la request");

        // 15-16. ricostruzione byte per byte
        byte[] a = reqRaw.getBytes(StandardCharsets.UTF_8), b = reqBack.getBytes(StandardCharsets.UTF_8);
        record("15", "Request originale ricostruita esattamente (byte)", Arrays.equals(a, b), firstDiff(reqRaw, reqBack));
        byte[] c = respRaw.getBytes(StandardCharsets.UTF_8), d = respBack.getBytes(StandardCharsets.UTF_8);
        record("16", "Response originale ricostruita esattamente (byte)", Arrays.equals(c, d), firstDiff(respRaw, respBack));

        // extra: nessuna fuga di dati sensibili
        List<String> leaks = new ArrayList<>();
        for (String s : SENSITIVE) if (reqOut.contains(s) || respOut.contains(s)) leaks.add(s);
        record("X1", "Nessun dato sensibile in chiaro nell'output", leaks.isEmpty(), "fughe: " + leaks);

        // extra: ogni placeholder nell'output ha un'associazione registrata
        Set<String> unknown = new TreeSet<>();
        Matcher tm = Pattern.compile("(?<![A-Za-z0-9_])[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?![A-Za-z0-9_])").matcher(reqOut + "\n" + respOut);
        Set<String> literals = new HashSet<>(List.of("EMAIL_1", "EMAIL_2", "EMAIL_10", "TOKEN_1", "HOST_1", "NOT_EMAIL_1"));
        while (tm.find()) {
            String t = tm.group();
            if (!rev.containsKey(t) && !literals.contains(t) && !t.equals("REDACTED")) unknown.add(t);
        }
        record("X2", "Ogni placeholder dell'output e' registrato nel mapping", unknown.isEmpty(), "sconosciuti: " + unknown);

        writeReport(leaks, collisions);
        assertTrue(details.isEmpty(), "Requisiti falliti:\n" + String.join("\n", details));
    }

    @Test
    void fiftyIsolatedSessions() throws Exception {
        ExecutorService ex = Executors.newFixedThreadPool(8);
        List<Future<String>> fs = new ArrayList<>();
        for (int s = 0; s < 50; s++) {
            final int id = s;
            fs.add(ex.submit(() -> {
                String uniq = "utente" + id + "@sessione" + id + ".it";
                String tok = "tokSess" + id + "Xy9";
                String req = "POST /s?e=" + uniq.replace("@", "%40") + "&same=mario%40example.com&lit=EMAIL_1 HTTP/1.1\n"
                        + "Host: api" + id + ".example.com\nCookie: session=" + tok + "; theme=dark\n"
                        + "X-Forwarded-For: 10.1." + id + ".7, 10.1." + id + ".7\nContent-Type: application/json\n\n"
                        + "{\"email\":\"" + uniq + "\",\"same\":\"mario@example.com\",\"token\":\"" + tok + "\","
                        + "\"literal\":\"TOKEN_1\",\"enc\":\"" + uniq.replace("@", "%40") + "\",\"ip\":\"10.1." + id + ".7\"}";
                String resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"echo\":\"" + uniq + "\",\"token\":\"" + tok
                        + "\",\"literal\":\"EMAIL_1\"}";
                SubstitutionMap m = new SubstitutionMap();
                Anonymizer an = new Anonymizer(Config.loadFromResources(), m);
                an.reserveLiterals(req, resp);
                String o1 = an.anonymizeRequest(req), o2 = an.anonymizeResponse(resp);
                if (o1.contains(uniq) || o1.contains(tok) || o2.contains(uniq)) return "fuga nella sessione " + id;
                if (!Anonymizer.deanonymize(o1, m.reverseMap()).equals(req)) return "request " + id + " non ricostruita";
                if (!Anonymizer.deanonymize(o2, m.reverseMap()).equals(resp)) return "response " + id + " non ricostruita";
                return id + "|" + o1 + "\u0000" + req + "\u0000" + serialize(m.reverseMap());
            }));
        }
        List<String[]> sessions = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        for (Future<String> f : fs) {
            String r = f.get(60, TimeUnit.SECONDS);
            if (!r.contains("\u0000")) errors.add(r); else sessions.add(r.split("\u0000", -1));
        }
        ex.shutdown();
        int crossOk = 0;
        for (int i = 0; i < sessions.size(); i++) {
            String out = sessions.get(i)[0].substring(sessions.get(i)[0].indexOf('|') + 1);
            String orig = sessions.get(i)[1];
            Map<String, String> otherMap = deserialize(sessions.get((i + 1) % sessions.size())[2]);
            if (!Anonymizer.deanonymize(out, otherMap).equals(orig)) crossOk++;
            else errors.add("la sessione " + i + " e' decodificabile col mapping di un'altra");
        }
        Files.createDirectories(Path.of("build/reports/adversarial"));
        Files.writeString(Path.of("build/reports/adversarial/isolation.txt"),
                "Sessioni: 50\nRound-trip esatti: " + sessions.size() + "\nDecodifiche incrociate respinte: " + crossOk
                        + "\nErrori: " + errors + "\n");
        assertTrue(errors.isEmpty(), String.join("\n", errors));
        assertEquals(50, sessions.size());
    }

    private static String serialize(Map<String, String> m) {
        StringBuilder sb = new StringBuilder();
        m.forEach((k, v) -> sb.append(k).append('\u0001').append(v).append('\u0002'));
        return sb.toString();
    }

    private static Map<String, String> deserialize(String s) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String p : s.split("\u0002")) {
            if (p.isEmpty()) continue;
            String[] kv = p.split("\u0001", -1);
            m.put(kv[0], kv[1]);
        }
        return m;
    }

    private static String mask(String v) {
        String one = v.replace("\n", "\\n");
        if (one.length() <= 4) return "*".repeat(one.length());
        return one.substring(0, 2) + "*".repeat(Math.min(8, one.length() - 4)) + one.substring(one.length() - 2)
                + " (" + one.length() + " car.)";
    }

    private static void writeReport(List<String> leaks, long collisions) throws Exception {
        Map<String, String> rev = map.reverseMap();
        int substitutions = 0, repeated = 0;
        for (String ph : rev.keySet()) {
            int n = countToken(reqOut, ph) + countToken(respOut, ph);
            substitutions += n;
            if (n > 1) repeated++;
        }
        StringBuilder r = new StringBuilder();
        r.append("# Report test avversariale\n\n");
        r.append("| Metrica | Valore |\n|---|---|\n");
        r.append("| Valori sensibili individuati (voci del mapping) | ").append(map.size()).append(" |\n");
        r.append("| Sostituzioni effettuate | ").append(substitutions).append(" |\n");
        r.append("| Placeholder ripetuti | ").append(repeated).append(" |\n");
        r.append("| Collisioni | ").append(collisions).append(" |\n");
        r.append("| Errori | ").append(details.size()).append(" |\n");
        r.append("| Fughe | ").append(leaks.size()).append(" |\n");
        r.append("| Tempo di elaborazione | ").append(elapsedMs).append(" ms |\n\n");
        r.append("## Requisiti\n\n| Requisito | Esito |\n|---|---|\n");
        results.forEach((k, v) -> r.append("| ").append(k).append(" | ").append(v).append(" |\n"));
        if (!details.isEmpty()) r.append("\n## Dettagli dei fallimenti\n\n").append(String.join("\n", details)).append("\n");
        r.append("\n## Mapping (originali mascherati)\n\n| Placeholder | Tipo | Originale |\n|---|---|---|\n");
        for (SubstitutionMap.Entry e : map.entries())
            r.append("| ").append(e.placeholder).append(" | ").append(e.type).append(" | `").append(mask(e.original)).append("` |\n");
        r.append("\n## Request pseudonimizzata\n\n```http\n").append(reqOut).append("\n```\n");
        r.append("\n## Response pseudonimizzata\n\n```http\n").append(respOut).append("\n```\n");
        r.append("\n## Confronto\n\n- Request: ").append(firstDiff(reqRaw, reqBack))
                .append("\n- Response: ").append(firstDiff(respRaw, respBack)).append("\n");
        Files.createDirectories(Path.of("build/reports/adversarial"));
        Files.writeString(Path.of("build/reports/adversarial/report.md"), r.toString());
        Files.writeString(Path.of("build/reports/adversarial/request.anon.http"), reqOut);
        Files.writeString(Path.of("build/reports/adversarial/response.anon.http"), respOut);
        Files.writeString(Path.of("build/reports/adversarial/request.decoded.http"), reqBack);
        Files.writeString(Path.of("build/reports/adversarial/response.decoded.http"), respBack);
    }
}
