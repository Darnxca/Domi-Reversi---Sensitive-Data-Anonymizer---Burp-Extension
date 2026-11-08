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

    // ---- regole di contesto (sezione "context" di sensitive_patterns.json) ----
    // Liste che decidono COSA e' sensibile per il contesto in cui compare: si
    // estendono dal JSON, anche con un file utente, senza ricompilare.
    /** Etichette di dominio che non identificano un cliente (CDN, SaaS, parole generiche). */
    public final Set<String> orgStop = new HashSet<>();
    /** Suffissi pubblici a due livelli (co.uk, com.br...). */
    public final Set<String> twoLevelSuffixes = new HashSet<>();
    /** Chiavi il cui valore e' un nome di macchina (normalizzate). */
    public final Set<String> hostKeys = new HashSet<>();
    /** Segmenti che seguono /users/, C:\\Users\\ ma non sono persone. */
    public final Set<String> notUsernames = new HashSet<>();
    /** Parole dopo un saluto ("Gentile Cliente") che non sono nomi. */
    public final Set<String> notNames = new HashSet<>();
    /** Utenze tipiche: "admin / X" in un commento e' una credenziale anche senza parole chiave. */
    public final Set<String> commonUsers = new HashSet<>();
    /** Parole che in un commento indicano credenziali (sottostringhe, minuscolo). */
    public final List<String> credentialHints = new ArrayList<>();
    /** XML-RPC: metodo (o prefisso con '.') -> {posizione username, posizione password}, 1-based. */
    public final java.util.Map<String, int[]> xmlrpcCredentials = new java.util.HashMap<>();
    /** vCard / iCalendar: proprieta' (maiuscolo) -> prefisso del segnaposto. */
    public final java.util.Map<String, String> vcardProperties = new java.util.HashMap<>();
    /** Claim JWT che identificano una persona (normalizzati). */
    public final Set<String> jwtIdentityClaims = new HashSet<>();
    /** Valori pubblici e non identificativi mai sostituiti (loopback, metadata cloud, domini d'esempio). */
    public final Set<String> keepValues = new HashSet<>();
    /** Sintassi d'attacco: un valore che la contiene e' un payload del tester e resta leggibile. */
    public final List<Pattern> attackMarkers = new ArrayList<>();
    /** Lunghezza minima di un nome di cliente ricavato da un dominio senza trattini o cifre. */
    public int orgMinLength = 6;

    /** File utente caricati in aggiunta a quelli inclusi (per mostrarlo nella UI). */
    public final List<String> loadedOverrides = new ArrayList<>();

    /** Cartella dei file utente: -Ddomireversi.config.dir oppure ~/.domi-reversi */
    public static java.nio.file.Path userConfigDir() {
        String p = System.getProperty("domireversi.config.dir");
        if (p == null || p.isBlank()) p = System.getProperty("user.home", "") + java.io.File.separator + ".domi-reversi";
        return java.nio.file.Paths.get(p);
    }

    /**
     * Configurazione inclusa + file utente facoltativi con lo stesso formato
     * (sensitive_patterns.json, sensitive_headers.json nella cartella utente).
     * I file utente si SOMMANO a quelli inclusi: pattern, chiavi e liste di
     * contesto in piu', strategie di header e opzioni che sostituiscono le
     * esistenti. Solo lettura: l'estensione non scrive nulla su disco.
     */
    public static Config loadWithUserOverrides() {
        Config c = loadFromResources();
        java.nio.file.Path dir = userConfigDir();
        for (String f : new String[]{"sensitive_headers.json", "sensitive_patterns.json"}) {
            java.nio.file.Path p = dir.resolve(f);
            try {
                if (!java.nio.file.Files.isRegularFile(p)) continue;
                String json = java.nio.file.Files.readString(p, StandardCharsets.UTF_8);
                if (f.startsWith("sensitive_headers")) c.parseHeaders(json); else c.parsePatterns(json);
                c.loadedOverrides.add(p.toString());
            } catch (Exception ignored) {
                // file utente illeggibile: si resta sulla configurazione inclusa
            }
        }
        return c;
    }

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
            if (root.has("context") && root.get("context").isJsonObject()) {
                JsonObject ctx = root.getAsJsonObject("context");
                addAll(ctx, "org_stop", orgStop, false);
                addAll(ctx, "two_level_suffixes", twoLevelSuffixes, false);
                addAll(ctx, "host_keys", hostKeys, true);
                addAll(ctx, "not_usernames", notUsernames, false);
                addAll(ctx, "not_names", notNames, false);
                addAll(ctx, "common_users", commonUsers, false);
                Set<String> hints = new HashSet<>();
                addAll(ctx, "credential_hints", hints, false);
                for (String h : hints) if (!credentialHints.contains(h)) credentialHints.add(h);
                addAll(ctx, "keep_values", keepValues, false);
                if (ctx.has("xmlrpc_credentials") && ctx.get("xmlrpc_credentials").isJsonObject()) {
                    for (java.util.Map.Entry<String, JsonElement> e : ctx.getAsJsonObject("xmlrpc_credentials").entrySet()) {
                        if (!e.getValue().isJsonArray() || e.getValue().getAsJsonArray().size() != 2) continue;
                        xmlrpcCredentials.put(e.getKey(), new int[]{e.getValue().getAsJsonArray().get(0).getAsInt(),
                                e.getValue().getAsJsonArray().get(1).getAsInt()});
                    }
                }
                if (ctx.has("vcard_properties") && ctx.get("vcard_properties").isJsonObject()) {
                    for (java.util.Map.Entry<String, JsonElement> e : ctx.getAsJsonObject("vcard_properties").entrySet()) {
                        vcardProperties.put(e.getKey().toUpperCase(java.util.Locale.ROOT), e.getValue().getAsString());
                    }
                }
                addAll(ctx, "jwt_identity_claims", jwtIdentityClaims, true);
                if (ctx.has("attack_markers") && ctx.get("attack_markers").isJsonArray()) {
                    for (JsonElement m : ctx.getAsJsonArray("attack_markers")) {
                        try {
                            attackMarkers.add(Pattern.compile(m.getAsString(), Pattern.CASE_INSENSITIVE));
                        } catch (Exception badRegex) {
                            // marcatore non valido: saltato
                        }
                    }
                }
                if (ctx.has("org_min_length")) orgMinLength = Math.max(3, ctx.get("org_min_length").getAsInt());
            }
            if (root.has("key_prefix_map") && root.get("key_prefix_map").isJsonObject()) {
                for (Map.Entry<String, JsonElement> e : root.getAsJsonObject("key_prefix_map").entrySet()) {
                    keyPrefixMap.put(e.getKey().toLowerCase(), e.getValue().getAsString());
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static void addAll(JsonObject obj, String name, Set<String> into, boolean normalize) {
        if (!obj.has(name) || !obj.get(name).isJsonArray()) return;
        for (JsonElement e : obj.getAsJsonArray(name)) {
            String s = e.getAsString().trim();
            if (s.isEmpty()) continue;
            into.add(normalize ? normKey(s) : s.toLowerCase(java.util.Locale.ROOT));
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
