package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.SubstitutionMap;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Le regex delle passate di contesto girano sull'intero messaggio: niente
 * ricorsione per carattere (StackOverflowError su valori lunghi) e tempi lineari.
 * Regressione: un valore lungo sotto "data"/"value" faceva fallire l'intera
 * anonimizzazione (fail-closed, ma inutilizzabile).
 */
class RegexSafetyTest {

    private static String repeat(String s, int n) {
        StringBuilder b = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) b.append(s);
        return b.toString();
    }

    @Test
    void valoriLunghiSottoChiaviNomeValore() {
        for (String key : new String[]{"data", "value", "content", "name", "key", "text"}) {
            String big = repeat("a.b@", 300_000);
            String req = "POST /api HTTP/1.1\r\nHost: app.acme-corp.it\r\nContent-Type: application/json\r\n\r\n"
                    + "{\"" + key + "\":\"" + big + "\",\"name\":\"password\"}";
            SubstitutionMap map = new SubstitutionMap();
            Anonymizer a = new Anonymizer(Config.loadFromResources(), map);
            String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> a.anonymizeRequest(req));
            boolean sensitiveKey = key.equals("name") || key.equals("key"); // "name" e' un nome di persona
            if (!sensitiveKey) assertTrue(out.contains(big), key + ": il contenuto innocuo deve restare");
            assertTrue(!out.startsWith("[Domi Reversi]"), key + ": l'anonimizzazione non deve arrendersi");
            assertEquals(req, Anonymizer.deanonymize(out, map.reverseMap()), key + ": ricostruzione esatta");
        }
    }

    @Test
    void diagnosticaSuTestiLunghi() {
        String llm = repeat("A_B_C_D_E_F_G_H_I_J_K_", 50_000) + " HOST_1 " + repeat("x", 100_000);
        Anonymizer.DeanonResult r = assertTimeoutPreemptively(Duration.ofSeconds(10),
                () -> Anonymizer.deanonymizeReport(llm, Map.of("HOST_1", "app.acme-corp.it")));
        assertEquals(1, r.replaced);
    }

    @Test
    void letteraliLunghiNelTraffico() {
        String req = "GET / HTTP/1.1\r\nHost: h.example\r\nX-Note: " + repeat("A\\_B", 100_000) + "_1\r\n\r\n";
        SubstitutionMap map = new SubstitutionMap();
        Anonymizer a = new Anonymizer(Config.loadFromResources(), map);
        String out = assertTimeoutPreemptively(Duration.ofSeconds(20), () -> a.anonymizeRequest(req));
        assertEquals(req, Anonymizer.deanonymize(out, map.reverseMap()));
    }
}
