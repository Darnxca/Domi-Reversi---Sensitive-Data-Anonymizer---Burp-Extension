package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.Overrides;
import com.domireversi.core.SubstitutionMap;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Catalogo dei casi limite guidato da dati: src/test/resources/edgecases/*.json.
 *
 * Per aggiungere un caso basta aggiungere una voce a un file (o un file nuovo):
 *
 * <pre>
 * {
 *   "id": "org-nel-path",                 // univoco nel file
 *   "description": "Nome del cliente nel path",
 *   "severity": "critical|high|medium|low",
 *   "request":  "GET /acme-corp/x HTTP/1.1\nHost: app.acme-corp.it\n\n",   // facoltativo
 *   "response": "HTTP/1.1 200 OK\n\n...",                                   // facoltativo
 *   "org_terms": ["Acme"],                // facoltativo: campo "Cliente" della UI
 *   "level": "strict",                    // facoltativo: livello Rigoroso
 *   "must_hide": ["acme-corp"],           // non deve comparire (maiuscole ignorate)
 *   "must_keep": ["/x"],                  // deve restare identico (falsi positivi)
 *   "known_gap": "motivo",                // facoltativo: limite noto e documentato
 *   "exact_roundtrip": false              // facoltativo: torna come testo, non come byte (gzip, binari decodificati)
 * }
 * </pre>
 *
 * Ogni caso verifica anche che non ci siano eccezioni e che la de-anonimizzazione
 * ricostruisca request e response byte per byte. Un caso "known_gap" che fallisce
 * non rompe la build ma finisce nel report; se invece inizia a passare la build
 * fallisce, cosi' il catalogo resta onesto (si toglie il known_gap).
 *
 * I casi di de-anonimizzazione hanno "map", "llm_text", "expect" ed
 * eventualmente "expect_unknown" / "expect_altered".
 *
 * Report: build/reports/edgecases/report.md
 */
class EdgeCaseCatalogTest {

    private static final List<String[]> REPORT = new ArrayList<>();

    @TestFactory
    Stream<DynamicNode> catalog() throws IOException, URISyntaxException {
        URL dir = EdgeCaseCatalogTest.class.getResource("/edgecases");
        if (dir == null) fail("cartella edgecases/ non trovata nelle risorse di test");
        List<Path> files;
        try (Stream<Path> s = Files.list(Paths.get(dir.toURI()))) {
            files = s.filter(p -> p.toString().endsWith(".json")).sorted().collect(Collectors.toList());
        }
        List<DynamicNode> nodes = new ArrayList<>();
        for (Path f : files) {
            JsonObject doc = JsonParser.parseString(Files.readString(f, StandardCharsets.UTF_8)).getAsJsonObject();
            String category = str(doc, "category", f.getFileName().toString());
            List<DynamicNode> tests = new ArrayList<>();
            for (JsonElement el : doc.getAsJsonArray("cases")) {
                JsonObject c = el.getAsJsonObject();
                String id = str(c, "id", "?");
                tests.add(DynamicTest.dynamicTest(id + " — " + str(c, "description", ""), () -> run(category, c)));
            }
            nodes.add(DynamicContainer.dynamicContainer(category, tests));
        }
        nodes.add(DynamicTest.dynamicTest("report", EdgeCaseCatalogTest::writeReport));
        return nodes.stream();
    }

    private static void run(String category, JsonObject c) {
        String id = str(c, "id", "?");
        String sev = str(c, "severity", "medium");
        String gap = str(c, "known_gap", null);
        List<String> problems = c.has("llm_text") ? checkDeanon(c) : checkAnon(c);
        if (gap == null) {
            REPORT.add(new String[]{category, id, sev, problems.isEmpty() ? "ok" : "FALLITO", String.join("; ", problems)});
            if (!problems.isEmpty()) fail("[" + sev + "] " + id + ": " + String.join("\n  ", problems));
        } else {
            REPORT.add(new String[]{category, id, sev, problems.isEmpty() ? "RISOLTO?" : "limite noto", gap});
            assertTrue(!problems.isEmpty(), id + " ora passa: togli \"known_gap\" dal catalogo");
        }
    }

    private static List<String> checkAnon(JsonObject c) {
        List<String> problems = new ArrayList<>();
        Config cfg = Config.loadFromResources();
        if (c.has("level")) cfg.level = str(c, "level", Config.LEVEL_STANDARD);
        Overrides ov = Overrides.empty().withOrgTerms(list(c, "org_terms"));
        SubstitutionMap map = new SubstitutionMap(ov.excludeValues);
        Anonymizer a = new Anonymizer(cfg, map, ov);
        String req = str(c, "request", "");
        String resp = str(c, "response", "");
        String outReq, outResp;
        try {
            a.reserveLiterals(req, resp); // come la UI: request + response = una sessione
            outReq = req.isEmpty() ? "" : a.anonymizeRequest(req);
            outResp = resp.isEmpty() ? "" : a.anonymizeResponse(resp);
        } catch (Throwable t) {
            problems.add("eccezione: " + t);
            return problems;
        }
        String all = outReq + "\n" + outResp;
        String low = all.toLowerCase(Locale.ROOT);
        for (String h : list(c, "must_hide")) {
            if (low.contains(h.toLowerCase(Locale.ROOT))) problems.add("in chiaro: \"" + h + "\"");
        }
        for (String k : list(c, "must_keep")) {
            if (!all.contains(k)) problems.add("alterato (falso positivo): \"" + k + "\"");
        }
        Map<String, String> rev = map.reverseMap();
        boolean exact = !c.has("exact_roundtrip") || c.get("exact_roundtrip").getAsBoolean();
        if (exact && !req.isEmpty() && !Anonymizer.deanonymize(outReq, rev).equals(req)) problems.add("request non ricostruita esattamente");
        if (exact && !resp.isEmpty() && !Anonymizer.deanonymize(outResp, rev).equals(resp)) problems.add("response non ricostruita esattamente");
        if (!problems.isEmpty()) problems.add("output: " + abbrev(all));
        return problems;
    }

    private static List<String> checkDeanon(JsonObject c) {
        List<String> problems = new ArrayList<>();
        Map<String, String> rev = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> e : c.getAsJsonObject("map").entrySet()) rev.put(e.getKey(), e.getValue().getAsString());
        Anonymizer.DeanonResult r = Anonymizer.deanonymizeReport(str(c, "llm_text", ""), rev);
        if (!r.text.equals(str(c, "expect", ""))) problems.add("testo: \"" + r.text + "\"");
        if (!sorted(r.unknown).equals(sorted(list(c, "expect_unknown")))) problems.add("sconosciuti: " + r.unknown);
        if (!sorted(r.altered).equals(sorted(list(c, "expect_altered")))) problems.add("modificati: " + r.altered);
        return problems;
    }

    private static void writeReport() throws IOException {
        StringBuilder sb = new StringBuilder("# Catalogo dei casi limite\n\n");
        Map<String, int[]> byCat = new LinkedHashMap<>();
        for (String[] r : REPORT) {
            int[] n = byCat.computeIfAbsent(r[0], k -> new int[3]);
            if (r[3].equals("ok")) n[0]++; else if (r[3].equals("limite noto")) n[1]++; else n[2]++;
        }
        sb.append("| Categoria | ok | limiti noti | da sistemare |\n|---|---|---|---|\n");
        for (Map.Entry<String, int[]> e : byCat.entrySet()) {
            sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()[0]).append(" | ")
              .append(e.getValue()[1]).append(" | ").append(e.getValue()[2]).append(" |\n");
        }
        sb.append("\n| Categoria | Caso | Gravita' | Esito | Note |\n|---|---|---|---|---|\n");
        for (String[] r : REPORT) {
            sb.append("| ").append(r[0]).append(" | ").append(r[1]).append(" | ").append(r[2]).append(" | ")
              .append(r[3]).append(" | ").append(r[4].replace("|", "\\|").replace("\n", " ")).append(" |\n");
        }
        Path out = Paths.get("build", "reports", "edgecases", "report.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
        assertEquals(REPORT.size(), REPORT.size());
    }

    // ------------------------------------------------------------------ util
    private static String str(JsonObject o, String k, String def) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : def;
    }

    private static List<String> list(JsonObject o, String k) {
        List<String> out = new ArrayList<>();
        if (o.has(k) && o.get(k).isJsonArray()) {
            JsonArray a = o.getAsJsonArray(k);
            for (JsonElement e : a) out.add(e.getAsString());
        }
        return out;
    }

    private static List<String> sorted(List<String> l) {
        List<String> s = new ArrayList<>(l);
        s.sort(null);
        return s;
    }

    private static String abbrev(String s) {
        String one = s.replace("\r", "").replace("\n", "⏎");
        return one.length() > 600 ? one.substring(0, 600) + "…" : one;
    }
}
