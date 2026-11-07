package com.domireversi;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.SubstitutionMap;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * La sintassi GraphQL (keyword, operazioni, variabili, tipi, campi, argomenti,
 * alias, direttive, frammenti) deve restare identica: si anonimizzano solo i
 * valori (variabili JSON e stringhe letterali) e il round-trip deve essere esatto.
 */
class GraphqlPreservationTest {

    static final String UPDATE_PROFILE =
            "mutation UpdateUserProfile($userId: ID!, $email: String!, $firstName: String!, $lastName: String!) {\n"
            + "  updateUser(id: $userId, input: {\n"
            + "    email: $email,\n"
            + "    firstName: $firstName,\n"
            + "    lastName: $lastName\n"
            + "  }) {\n"
            + "    id email firstName lastName\n"
            + "  }\n"
            + "}";

    private static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    private static String request(String query, String variablesJson) {
        String body = "{\"operationName\":\"UpdateUserProfile\",\"query\":" + jsonString(query)
                + (variablesJson == null ? "" : ",\"variables\":" + variablesJson) + "}";
        return "POST /graphql HTTP/1.1\r\nHost: api.clientecorp.it\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtcm9zc2kifQ.c2lnbmF0dXJl\r\n"
                + "X-User-Email: mario.rossi@clientecorp.it\r\n"
                + "Cookie: session=SESS8842abcXYZ; email=mario.rossi@clientecorp.it\r\n"
                + "Content-Type: application/json\r\n\r\n" + body;
    }

    private static String bodyOf(String msg) {
        return msg.substring(msg.indexOf("\r\n\r\n") + 4);
    }

    /** Sequenza dei token sintattici GraphQL (stringhe e commenti esclusi). */
    static List<String> syntaxTokens(String doc) {
        List<String> out = new ArrayList<>();
        int i = 0, n = doc.length();
        while (i < n) {
            char c = doc.charAt(i);
            if (c == '#') { while (i < n && doc.charAt(i) != '\n') i++; continue; }
            if (doc.startsWith("\"\"\"", i)) {
                int j = doc.indexOf("\"\"\"", i + 3);
                i = j < 0 ? n : j + 3;
                out.add("<blockstring>");
                continue;
            }
            if (c == '"') {
                int j = i + 1;
                while (j < n && doc.charAt(j) != '"' && doc.charAt(j) != '\n') j += doc.charAt(j) == '\\' ? 2 : 1;
                i = Math.min(n, j + 1);
                out.add("<string>");
                continue;
            }
            if (Character.isWhitespace(c) || c == ',') { i++; continue; }
            if (Character.isLetter(c) || c == '_' || c == '$' || c == '@') {
                int j = i + 1;
                while (j < n && (Character.isLetterOrDigit(doc.charAt(j)) || doc.charAt(j) == '_')) j++;
                out.add(doc.substring(i, j));
                i = j;
                continue;
            }
            out.add(String.valueOf(c));
            i++;
        }
        return out;
    }

    private static void assertGraphqlPreserved(String original, String anonymized) {
        assertEquals(syntaxTokens(original), syntaxTokens(anonymized), "sintassi GraphQL modificata");
    }

    @Test
    void updateUserProfileMutation() {
        String vars = "{\"userId\":\"usr_8842\",\"email\":\"mario.rossi@clientecorp.it\",\"firstName\":\"Mario\",\"lastName\":\"Rossi\"}";
        String raw = request(UPDATE_PROFILE, vars);

        // prima: la scansione generica sul testo libero (vecchio comportamento) altera la sintassi
        Anonymizer legacy = new Anonymizer(Config.loadFromResources(), new SubstitutionMap());
        String before = legacy.scanSecrets(UPDATE_PROFILE);
        System.out.println("=== PRIMA (scansione generica sulla query) ===\n" + before);

        SubstitutionMap map = new SubstitutionMap();
        Anonymizer an = new Anonymizer(Config.loadFromResources(), map);
        String out = an.anonymizeRequest(raw);
        JsonObject body = JsonParser.parseString(bodyOf(out)).getAsJsonObject();
        String query = body.get("query").getAsString();
        System.out.println("=== DOPO (query nella request anonimizzata) ===\n" + query);
        System.out.println("=== DOPO (variabili) ===\n" + body.get("variables"));

        assertEquals(UPDATE_PROFILE, query, "la query GraphQL deve restare identica");
        assertTrue(query.contains("$email: String!") && query.contains("$userId: ID!"));
        assertTrue(query.contains("email: $email,") && query.contains("firstName: $firstName,")
                && query.contains("lastName: $lastName"));

        JsonObject v = body.getAsJsonObject("variables");
        assertTrue(v.get("email").getAsString().startsWith("EMAIL_"));
        assertTrue(v.get("firstName").getAsString().startsWith("NAME_"));
        assertTrue(v.get("lastName").getAsString().startsWith("NAME_"));
        assertEquals("usr_8842", v.get("userId").getAsString(), "gli identificativi restano leggibili (livello standard)");

        // coerenza tra header, cookie e variabili
        String emailPh = v.get("email").getAsString();
        assertTrue(out.contains("X-User-Email: " + emailPh + "\r\n"));
        assertTrue(out.contains("email=" + emailPh));
        assertFalse(out.contains("mario.rossi@clientecorp.it"));

        assertEquals(raw, Anonymizer.deanonymize(out, map.reverseMap()), "round-trip non esatto");
    }

    private static final String[][] CASES = {
            {"query semplice", "query GetUser($id: ID!) { user(id: $id) { id name email } }"},
            {"mutation con letterali sensibili", "mutation { login(email: \"mario@clientecorp.it\", password: \"Hunter2!\") { token } }"},
            {"subscription", "subscription OnMessage($room: ID!) { messageAdded(roomId: $room) { id text author { email } } }"},
            {"alias", "query { me: user(id: \"42\") { mail: email nome: firstName } }"},
            {"direttive", "query Q($withEmail: Boolean!) { user { id email @include(if: $withEmail) phone @skip(if: true) } }"},
            {"frammenti", "query { user { ...UserFields } } fragment UserFields on User { id email firstName }"},
            {"frammento inline", "query { node(id: \"1\") { ... on User { email } } }"},
            {"annidata", "query { org { teams { members { user { email address { street city } } } } } }"},
            {"null, array e oggetti", "mutation { update(input: {email: null, tags: [\"a\", \"b\"], phones: [\"+39 347 123 4567\"], meta: {note: \"x\"}}) { ok } }"},
            {"caratteri speciali ed escape", "mutation { note(text: \"riga1\\nriga2 \\\"quoted\\\" \\u00e8 mario@clientecorp.it\") { id } }"},
            {"block string", "mutation { setBio(bio: \"\"\"\n  Scrivimi a mario@clientecorp.it\n  \"\"\") { id } }"},
            {"commento", "# contatto: mario@clientecorp.it\nquery { me { id } }"},
            {"variabile con default sensibile", "query Q($email: String = \"mario@clientecorp.it\") { user(email: $email) { id } }"},
            {"input con chiave password", "mutation { register(input: {username: \"mrossi\", password: \"S3gr3t0!\", email: \"m@clientecorp.it\"}) { id } }"},
            {"malformata: stringa non chiusa", "mutation { login(password: \"Hunter2!) { token } }"},
            {"malformata: parentesi mancanti", "query { user(email: \"mario@clientecorp.it\" { id"},
    };

    @TestFactory
    Stream<DynamicTest> syntaxPreservedAndRoundTrip() {
        return Stream.of(CASES).flatMap(c -> Stream.of(
                DynamicTest.dynamicTest("JSON / " + c[0], () -> check(c[1], true)),
                DynamicTest.dynamicTest("application/graphql / " + c[0], () -> check(c[1], false))));
    }

    private static void check(String query, boolean json) {
        String raw = json
                ? request(query, "{\"email\":\"mario@clientecorp.it\",\"password\":\"Pwd!998\",\"tags\":[\"x\",null],\"id\":\"7\"}")
                : "POST /graphql HTTP/1.1\r\nHost: api.clientecorp.it\r\nContent-Type: application/graphql\r\n\r\n" + query;
        SubstitutionMap map = new SubstitutionMap();
        Anonymizer an = new Anonymizer(Config.loadFromResources(), map);
        String out = an.anonymizeRequest(raw);
        String q = json ? JsonParser.parseString(bodyOf(out)).getAsJsonObject().get("query").getAsString() : bodyOf(out);
        assertGraphqlPreserved(query, q);
        for (String secret : new String[]{"mario@clientecorp.it", "Hunter2!", "S3gr3t0!", "+39 347 123 4567", "Pwd!998", "m@clientecorp.it"}) {
            assertFalse(out.contains(secret), "dato sensibile in chiaro: " + secret + "\n" + out);
        }
        assertEquals(raw, Anonymizer.deanonymize(out, map.reverseMap()), "round-trip non esatto");
    }
}
