package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.SubstitutionMap;
import com.domireversi.core.Transcript;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Trascritti costruiti dal menu di Burp: riconosciuti, anonimizzati per blocco, reversibili. */
class TranscriptTest {

    @Test
    void webSocketCoerenteConLHandshake() {
        String upgrade = "GET /ws HTTP/1.1\r\nHost: app.acme-corp.it\r\nUpgrade: websocket\r\n\r\n";
        String t = Transcript.webSocket("wss://app.acme-corp.it/ws", List.of(
                new Transcript.Frame(true, "{\"type\":\"auth\",\"email\":\"m.rossi@acme-corp.it\"}"),
                new Transcript.Frame(false, "42[\"welcome\",{\"user\":\"m.rossi@acme-corp.it\"}]"),
                new Transcript.Frame(true, "ping")));
        assertTrue(Anonymizer.isTranscript(t));
        SubstitutionMap map = new SubstitutionMap();
        Anonymizer a = new Anonymizer(Config.loadFromResources(), map);
        a.reserveLiterals(upgrade, t);
        String up = a.anonymizeRequest(upgrade);
        String out = a.anonymizeResponse(t);
        assertFalse(out.contains("m.rossi"), out);
        assertFalse(out.contains("acme-corp"), out);
        assertTrue(up.contains("HOST_1") && out.contains("HOST_1"), "stesso host nell'handshake e nel trascritto");
        assertTrue(out.contains("client → server") && out.contains("server → client"), out);
        assertTrue(out.contains("42[\"welcome\""), "prefisso Socket.IO intatto: " + out);
        assertEquals(1, out.split("EMAIL_1", -1).length - 2, "stessa email, stesso segnaposto: " + out);
        assertEquals(t, Anonymizer.deanonymize(out, map.reverseMap()));
    }

    @Test
    void issueDelloScanner() {
        String t = Transcript.issue("Cross-site scripting (reflected)", "HIGH", "CERTAIN",
                "https://portal.acme-corp.it/search",
                "<p>Payload <b>&lt;script&gt;</b> reflected for user g.bianchi@acme-corp.it</p>",
                "<p>Background</p>", "<p>Encode output.</p>");
        SubstitutionMap map = new SubstitutionMap();
        Anonymizer a = new Anonymizer(Config.loadFromResources(), map);
        String out = a.anonymizeResponse(t);
        assertFalse(out.contains("g.bianchi"), out);
        assertFalse(out.contains("portal.acme-corp.it"), out);
        assertTrue(out.contains("Cross-site scripting (reflected) · high / certain"), out);
        assertEquals(t, Anonymizer.deanonymize(out, map.reverseMap()));
    }
}
