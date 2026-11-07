package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.SubstitutionMap;
import org.junit.jupiter.api.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Coerenza, URL annidati, separazione, dati non sensibili, contesto e livelli
 * di anonimizzazione per gli identificativi.
 */
class ContextAndLevelsTest {

    private static Anonymizer fresh(SubstitutionMap m, String level) {
        Config c = Config.loadFromResources();
        c.level = level;
        return new Anonymizer(c, m);
    }

    private static String body(String msg) {
        int i = msg.indexOf("\r\n\r\n");
        return i < 0 ? "" : msg.substring(i + 4);
    }

    private static String json(String body) {
        return "POST /api HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: application/json\r\n\r\n" + body;
    }

    @Test
    void coerenzaStessaEmailOvunque() {
        SubstitutionMap m = new SubstitutionMap();
        Anonymizer an = fresh(m, Config.LEVEL_STANDARD);
        String raw = "POST /u?notify=mario.rossi%40clientecorp.it HTTP/1.1\r\nHost: h.example.com\r\n"
                + "X-User-Email: mario.rossi@clientecorp.it\r\nCookie: email=mario.rossi@clientecorp.it\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"email\":\"mario.rossi@clientecorp.it\",\"cc\":[\"mario.rossi@clientecorp.it\"],\"msg\":\"scrivi a mario.rossi@clientecorp.it\"}";
        String out = an.anonymizeRequest(raw);
        String resp = an.anonymizeResponse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nciao mario.rossi@clientecorp.it");
        assertFalse(out.contains("mario.rossi@clientecorp.it") || resp.contains("mario.rossi@clientecorp.it"));
        String ph = m.entries().stream().filter(e -> e.original.equals("mario.rossi@clientecorp.it")).findFirst().orElseThrow().placeholder;
        Matcher mm = Pattern.compile("(?<![A-Za-z0-9_])" + ph + "(?![A-Za-z0-9])").matcher(out + resp);
        int n = 0;
        while (mm.find()) n++;
        assertEquals(7, n, "ogni occorrenza (query, header, cookie, 3 nel JSON, response) deve avere la stessa radice");
        assertTrue(out.contains("notify=" + ph + "_URL"), "la forma codificata condivide la radice " + ph);
        assertEquals(raw, Anonymizer.deanonymize(out, m.reverseMap()));
    }

    @Test
    void urlAnnidatiConParametriSensibili() {
        SubstitutionMap m = new SubstitutionMap();
        String raw = "GET /login?redirect=https%3A%2F%2Fapp.clientecorp.it%2Fcb%3Ftoken%3DTk9988zzQ%26next%3D"
                + "https%253A%252F%252Fsso.clientecorp.it%252Fx%253Femail%253Dg%2540clientecorp.it HTTP/1.1\r\n"
                + "Host: h.example.com\r\n\r\n";
        String out = fresh(m, Config.LEVEL_STANDARD).anonymizeRequest(raw);
        for (String s : new String[]{"Tk9988zzQ", "clientecorp.it", "g%2540", "g@"}) assertFalse(out.contains(s), s + "\n" + out);
        assertTrue(out.startsWith("GET /login?redirect=https%3A%2F%2F"), "struttura dell'URL conservata");
        assertEquals(raw, Anonymizer.deanonymize(out, m.reverseMap()));

        SubstitutionMap m2 = new SubstitutionMap();
        String raw2 = json("{\"next\":\"https://app.clientecorp.it/cb?redirect=https%3A%2F%2Fsso.clientecorp.it%2F%3Fsession%3DSs77xx\"}");
        String out2 = fresh(m2, Config.LEVEL_STANDARD).anonymizeRequest(raw2);
        assertFalse(out2.contains("Ss77xx") || out2.contains("clientecorp"), out2);
        assertEquals(raw2, Anonymizer.deanonymize(out2, m2.reverseMap()));
    }

    @Test
    void segretiConFormaDiPlaceholderVengonoComunqueAnonimizzati() {
        SubstitutionMap m = new SubstitutionMap();
        String raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=VAL_A_1234\r\nSet-Cookie: b=VAL_B_5678\r\nContent-Type: application/json\r\n\r\n"
                + "{\"token\":\"APP_KEY_998877\",\"note\":\"EMAIL_1 resta letterale\"}";
        String out = fresh(m, Config.LEVEL_STANDARD).anonymizeResponse(raw);
        for (String s : new String[]{"VAL_A_1234", "VAL_B_5678", "APP_KEY_998877"}) assertFalse(out.contains(s), s + "\n" + out);
        assertTrue(out.contains("EMAIL_1 resta letterale"));
        assertEquals(raw, Anonymizer.deanonymize(out, m.reverseMap()));
    }

    @Test
    void separazioneValoriDiversi() {
        SubstitutionMap m = new SubstitutionMap();
        String raw = json("{\"from\":\"anna@clientecorp.it\",\"to\":\"anna@clientecorp.com\",\"cc\":\"anna.b@clientecorp.it\",\"bcc\":\"anna@clientecorp.it\"}");
        String out = fresh(m, Config.LEVEL_STANDARD).anonymizeRequest(raw);
        assertEquals("{\"from\":\"EMAIL_1\",\"to\":\"EMAIL_2\",\"cc\":\"EMAIL_3\",\"bcc\":\"EMAIL_1\"}", body(out));
        assertEquals("da anna@clientecorp.it a anna@clientecorp.com",
                Anonymizer.deanonymize("da EMAIL_1 a EMAIL_2", m.reverseMap()));
    }

    @Test
    void datiNonSensibiliInvariati() {
        String b = "{\"amount\":\"1234.56\",\"currency\":\"EUR\",\"price\":19.99,\"total\":\"€ 1.234,56\",\"language\":\"it\","
                + "\"theme\":\"dark\",\"notifications\":true,\"timezone\":\"Europe/Rome\",\"vat_rate\":22,\"quantity\":3,"
                + "\"discount\":\"10%\",\"newsletter\":false,\"page_size\":50}";
        assertEquals(b, body(fresh(new SubstitutionMap(), Config.LEVEL_STANDARD).anonymizeRequest(json(b))));
        String q = "GET /shop?currency=EUR&amount=99.90&sort=price&lang=it HTTP/1.1\r\nHost: h.example.com\r\nCookie: theme=dark; lang=it\r\n\r\n";
        String out = fresh(new SubstitutionMap(), Config.LEVEL_STANDARD).anonymizeRequest(q);
        assertTrue(out.startsWith("GET /shop?currency=EUR&amount=99.90&sort=price&lang=it HTTP/1.1"));
        assertTrue(out.contains("Cookie: theme=dark; lang=it"));
    }

    @Test
    void contestoGeograficoNonSensibile() {
        String b = "{\"country\":\"IT\",\"country_code\":\"IT\",\"locale\":\"it-IT\",\"region\":\"Lombardia\",\"nationality\":\"IT\",\"continent\":\"EU\"}";
        assertEquals(b, body(fresh(new SubstitutionMap(), Config.LEVEL_STANDARD).anonymizeRequest(json(b))));
        String t = "POST /x HTTP/1.1\r\nHost: h.example.com\r\nContent-Type: text/plain\r\n\r\ncountry: IT\nlocale: it-IT\n";
        assertTrue(fresh(new SubstitutionMap(), Config.LEVEL_STANDARD).anonymizeRequest(t).endsWith("country: IT\nlocale: it-IT\n"));
    }

    private static final String IDS = "POST /tx HTTP/1.1\r\nHost: h.example.com\r\n"
            + "X-Correlation-Id: 4bf92f3577b34da6a3ce929d0e0e4736\r\nX-Request-Id: req-7f3a9c2b71d04e5f\r\n"
            + "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nContent-Type: application/json\r\n\r\n"
            + "{\"transaction\":{\"id\":\"TXN-2026-000123\",\"ref\":\"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\"},"
            + "\"user_ref\":\"USR-0000123\",\"correlation_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\",\"orderId\":\"4111111111111111\","
            + "\"email\":\"cliente@clientecorp.it\",\"android\":\"14\",\"lang_pref\":\"it\"}";

    @Test
    void livelloStandardConservaGliIdentificativi() {
        SubstitutionMap m = new SubstitutionMap();
        String out = fresh(m, Config.LEVEL_STANDARD).anonymizeRequest(IDS);
        for (String keep : new String[]{"X-Correlation-Id: 4bf92f3577b34da6a3ce929d0e0e4736", "X-Request-Id: req-7f3a9c2b71d04e5f",
                "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "\"id\":\"TXN-2026-000123\"",
                "\"ref\":\"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\"", "\"user_ref\":\"USR-0000123\"",
                "\"correlation_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\"", "\"orderId\":\"4111111111111111\"",
                "\"android\":\"14\"", "\"lang_pref\":\"it\""}) {
            assertTrue(out.contains(keep), "identificativo alterato: " + keep + "\n" + out);
        }
        assertFalse(out.contains("cliente@clientecorp.it"), "i dati personali restano anonimizzati");
        assertEquals(IDS, Anonymizer.deanonymize(out, m.reverseMap()));
    }

    @Test
    void livelloRigorosoAnonimizzaGliIdMaNonQuelliDiTracing() {
        SubstitutionMap m = new SubstitutionMap();
        String out = fresh(m, Config.LEVEL_STRICT).anonymizeRequest(IDS);
        for (String gone : new String[]{"TXN-2026-000123", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "USR-0000123", "4111111111111111"}) {
            assertFalse(out.contains(gone), "con livello rigoroso deve sparire: " + gone + "\n" + out);
        }
        assertTrue(out.contains("\"id\":\"ID_"), out);
        // preserve_keys: tracing sempre leggibile
        assertTrue(out.contains("X-Correlation-Id: 4bf92f3577b34da6a3ce929d0e0e4736"));
        assertTrue(out.contains("\"correlation_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
        assertTrue(out.contains("traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"));
        // non sono identificativi: restano
        assertTrue(out.contains("\"android\":\"14\"") && out.contains("\"lang_pref\":\"it\""));
        assertEquals(IDS, Anonymizer.deanonymize(out, m.reverseMap()));
    }

    @Test
    void stessoIdStessoPlaceholderNelLivelloRigoroso() {
        SubstitutionMap m = new SubstitutionMap();
        Anonymizer an = fresh(m, Config.LEVEL_STRICT);
        String a = an.anonymizeRequest(json("{\"order_id\":\"ORD-77\"}"));
        String b = an.anonymizeResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orderId\":\"ORD-77\"}");
        assertTrue(body(a).contains("ID_1") && body(b).contains("ID_1"));
    }
}
