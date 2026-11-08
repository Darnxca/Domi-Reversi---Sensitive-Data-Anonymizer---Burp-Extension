package com.domireversi.core;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Esporta / importa la mappa segnaposto -> valore come JSON, per de-anonimizzare
 * una risposta dell'LLM anche in un altro giorno o su un'altra macchina (un
 * incarico dura settimane). Il file lo scrive solo l'utente, quando lo chiede:
 * contiene i dati reali, va custodito come il resto delle evidenze del test.
 *
 * L'import e' difensivo (come in rizzo-pii): un file con chiavi vuote o non a
 * forma di segnaposto renderebbe la sostituzione quasi universale e
 * corromperebbe l'intero testo, quindi viene rifiutato per intero.
 */
public final class MapFile {

    public static final int VERSION = 1;
    private static final Pattern PLACEHOLDER = Pattern.compile("[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\\d{1,9}(?:_[A-Z0-9]+)*");

    private MapFile() {
    }

    public static String export(SubstitutionMap map) {
        JsonObject root = new JsonObject();
        root.addProperty("format", "domi-reversi-map");
        root.addProperty("version", VERSION);
        root.addProperty("warning", "Contiene i valori REALI: non condividere e non incollare nell'LLM.");
        JsonArray entries = new JsonArray();
        Map<String, String> rev = map.reverseMap();
        for (SubstitutionMap.Entry e : map.entries()) {
            if (!rev.containsKey(e.placeholder)) continue; // ambigui: non reversibili
            JsonObject o = new JsonObject();
            o.addProperty("placeholder", e.placeholder);
            o.addProperty("original", e.original);
            o.addProperty("type", e.type);
            entries.add(o);
        }
        root.add("entries", entries);
        JsonArray org = new JsonArray();
        for (String t : map.orgTerms()) org.add(t);
        root.add("org_terms", org);
        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(root);
    }

    /** Voci {placeholder, originale, tipo} per riprendere una sessione (vedi SubstitutionMap.seed). */
    public static java.util.List<String[]> importEntries(String json) {
        Map<String, String> rev = importReverse(json); // stesse verifiche
        Map<String, String> types = new java.util.HashMap<>();
        for (JsonElement el : JsonParser.parseString(json).getAsJsonObject().getAsJsonArray("entries")) {
            JsonObject o = el.getAsJsonObject();
            if (o.has("type") && o.get("type").isJsonPrimitive()) types.put(o.get("placeholder").getAsString(), o.get("type").getAsString());
        }
        java.util.List<String[]> out = new java.util.ArrayList<>();
        for (Map.Entry<String, String> e : rev.entrySet()) out.add(new String[]{e.getKey(), e.getValue(), types.get(e.getKey())});
        return out;
    }

    /** Mappa placeholder -> originale; IllegalArgumentException se il file non e' valido. */
    public static Map<String, String> importReverse(String json) {
        JsonObject root;
        try {
            root = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("non e' un file JSON valido");
        }
        if (!root.has("entries") || !root.get("entries").isJsonArray()) {
            throw new IllegalArgumentException("manca l'elenco \"entries\"");
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (JsonElement el : root.getAsJsonArray("entries")) {
            if (!el.isJsonObject()) throw new IllegalArgumentException("voce non valida");
            JsonObject o = el.getAsJsonObject();
            if (!o.has("placeholder") || !o.has("original")
                    || !o.get("placeholder").isJsonPrimitive() || !o.get("original").isJsonPrimitive()) {
                throw new IllegalArgumentException("voce senza placeholder/original");
            }
            String ph = o.get("placeholder").getAsString();
            if (!PLACEHOLDER.matcher(ph).matches()) throw new IllegalArgumentException("segnaposto non valido: " + ph);
            String prev = out.putIfAbsent(ph, o.get("original").getAsString());
            if (prev != null && !prev.equals(o.get("original").getAsString())) {
                throw new IllegalArgumentException("segnaposto duplicato con valori diversi: " + ph);
            }
        }
        if (out.isEmpty()) throw new IllegalArgumentException("la mappa e' vuota");
        return out;
    }
}
