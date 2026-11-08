package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.MapFile;
import com.domireversi.core.SubstitutionMap;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/** Export / import della mappa per de-anonimizzare in un altro momento. */
class MapFileTest {

    @Test
    void mappaEsportataEReimportata() {
        SubstitutionMap map = new SubstitutionMap();
        Anonymizer a = new Anonymizer(Config.loadFromResources(), map);
        String req = "GET /x HTTP/1.1\r\nHost: app.acme-corp.it\r\nCookie: session=k8J2mQ9xLp4Z\r\n\r\n";
        String out = a.anonymizeRequest(req);
        Map<String, String> back = MapFile.importReverse(MapFile.export(map));
        assertEquals(map.reverseMap(), back);
        assertEquals(req, Anonymizer.deanonymize(out, back));
    }

    @Test
    void mappaNonValidaRifiutata() {
        for (String bad : new String[]{
                "non json", "{}", "{\"entries\":[]}",
                "{\"entries\":[{\"placeholder\":\"\",\"original\":\"x\"}]}",
                "{\"entries\":[{\"placeholder\":\"a\",\"original\":\"x\"}]}",
                "{\"entries\":[{\"placeholder\":\"HOST_1\",\"original\":\"a\"},{\"placeholder\":\"HOST_1\",\"original\":\"b\"}]}"}) {
            try {
                MapFile.importReverse(bad);
                fail("doveva essere rifiutata: " + bad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
    }
}
