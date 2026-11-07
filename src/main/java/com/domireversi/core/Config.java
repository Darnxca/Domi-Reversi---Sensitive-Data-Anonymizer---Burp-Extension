package com.domireversi.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Carica sensitive_headers.json e sensitive_patterns.json (bundlati come
 * risorse nel jar). Nessun errore fatale: se manca/e' corrotto si usa il
 * minimo indispensabile.
 */
public final class Config {

    public final Map<String, String> headerStrategy = new HashMap<>(); // nome-lower -> strategia
    public final Set<String> keepHeaders = new HashSet<>();
    public boolean anonymizeUserAgent = false;

    public final List<PatternDef> patterns = new ArrayList<>();
    public final Set<String> keyExact = new HashSet<>();
    public final List<String> keyContains = new ArrayList<>();
    public final Map<String, String> keyPrefixMap = new HashMap<>();

    /** Livello: "standard" (gli identificativi restano leggibili) o "strict" (anche gli ID -> ID_n). */
    public static final String LEVEL_STANDARD = "standard";
    public static final String LEVEL_STRICT = "strict";
    public volatile String level = LEVEL_STANDARD;
    /** Chiavi/header mai anonimizzati, a qualunque livello (normalizzati: minuscolo, senza _ - . spazi). */
    public final Set<String> preserveKeys = new HashSet<>();

    public boolean strictIds() { return LEVEL_STRICT.equalsIgnoreCase(level); }

    public static String normKey(String key) {
        StringBuilder sb = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c == '_' || c == '-' || c == '.' || Character.isWhitespace(c)) continue;
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    /** Carica dalla classpath (risorse nel jar). */
    public static Config loadFromResources() {
        String headers = readResource("/sensitive_headers.json");
        String patterns = readResource("/sensitive_patterns.json");
        return load(headers, patterns);
    }

    public static Config load(String headersJson, String patternsJson) {
        Config c = new Config();
        c.parseHeaders(headersJson);
        c.parsePatterns(patternsJson);
        return c;
    }

    private static String readResource(String path) {
        try (InputStream in = Config.class.getResourceAsStream(path)) {
            if (in == null) return null;
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private void parseHeaders(String json) {
        if (json == null) return;
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonObject strategies = root.has("strategies") ? root.getAsJsonObject("strategies") : new JsonObject();
            for (Map.Entry<String, JsonElement> e : strategies.entrySet()) {
                String strat = e.getKey();
                if (!e.getValue().isJsonArray()) continue;
                for (JsonElement n : e.getValue().getAsJsonArray()) {
                    headerStrategy.put(n.getAsString().toLowerCase(), strat);
                }
            }
            if (root.has("keep") && root.get("keep").isJsonArray()) {
                for (JsonElement n : root.getAsJsonArray("keep")) {
                    keepHeaders.add(n.getAsString().toLowerCase());
                }
            }
            if (root.has("options") && root.get("options").isJsonObject()) {
                JsonObject opt = root.getAsJsonObject("options");
                if (opt.has("anonymize_user_agent")) {
                    anonymizeUserAgent = opt.get("anonymize_user_agent").getAsBoolean();
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void parsePatterns(String json) {
        if (json == null) return;
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (root.has("patterns") && root.get("patterns").isJsonArray()) {
                for (JsonElement el : root.getAsJsonArray("patterns")) {
                    JsonObject p = el.getAsJsonObject();
                    try {
                        int flags = compileFlags(p.has("flags") ? p.get("flags").getAsString() : "");
                        Pattern rx = Pattern.compile(p.get("regex").getAsString(), flags);
                        Integer keepGroup = p.has("keep_group") ? p.get("keep_group").getAsInt() : null;
                        String validate = p.has("validate") ? p.get("validate").getAsString() : null;
                        patterns.add(new PatternDef(
                                p.has("name") ? p.get("name").getAsString() : "?",
                                p.has("prefix") ? p.get("prefix").getAsString() : "SECRET",
                                rx, validate, keepGroup));
                    } catch (Exception badPattern) {
                        // pattern non valido: saltato
                    }
                }
            }
            if (root.has("sensitive_json_keys") && root.get("sensitive_json_keys").isJsonObject()) {
                JsonObject keys = root.getAsJsonObject("sensitive_json_keys");
                if (keys.has("exact") && keys.get("exact").isJsonArray()) {
                    for (JsonElement k : keys.getAsJsonArray("exact")) keyExact.add(k.getAsString().toLowerCase());
                }
                if (keys.has("contains") && keys.get("contains").isJsonArray()) {
                    for (JsonElement k : keys.getAsJsonArray("contains")) keyContains.add(k.getAsString().toLowerCase());
                }
            }
            if (root.has("options") && root.get("options").isJsonObject()) {
                JsonObject opt = root.getAsJsonObject("options");
                if (opt.has("level")) level = opt.get("level").getAsString().trim().toLowerCase();
                if (opt.has("preserve_keys") && opt.get("preserve_keys").isJsonArray()) {
                    for (JsonElement k : opt.getAsJsonArray("preserve_keys")) preserveKeys.add(normKey(k.getAsString()));
                }
            }
            if (root.has("key_prefix_map") && root.get("key_prefix_map").isJsonObject()) {
                for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("key_prefix_map").entrySet()) {
                    keyPrefixMap.put(e.getKey().toLowerCase(), e.getValue().getAsString());
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static int compileFlags(String flags) {
        int out = 0;
        if (flags == null) return out;
        for (char ch : flags.toLowerCase().toCharArray()) {
            if (ch == 'i') out |= Pattern.CASE_INSENSITIVE;
            else if (ch == 'm') out |= Pattern.MULTILINE;
            else if (ch == 's') out |= Pattern.DOTALL;
        }
        return out;
    }
}
