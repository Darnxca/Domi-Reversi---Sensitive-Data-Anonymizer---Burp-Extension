package com.domireversi.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mappa di sostituzione coerente: lo stesso valore originale riceve SEMPRE lo
 * stesso placeholder, indipendentemente dal prefisso richiesto (vince il primo
 * tipo con cui e' stato incontrato). I numeri sono progressivi per prefisso.
 *
 * Valori che differiscono solo per maiuscole/spazi (email, host, IBAN, carte...)
 * condividono lo stesso placeholder. Un testo che e' gia' un placeholder non
 * viene mai anonimizzato una seconda volta.
 */
public final class SubstitutionMap {

    /** Voce della mappa (originale -> placeholder, con tipo). */
    public static final class Entry {
        public final String original;
        public final String placeholder;
        public final String type;

        public Entry(String original, String placeholder, String type) {
            this.original = original;
            this.placeholder = placeholder;
            this.type = type;
        }
    }

    /** Prefissi prodotti dal motore e dalla configurazione di default. */
    private static final Set<String> KNOWN_PREFIXES = Set.of(
            "HOST", "IP", "EMAIL", "TOKEN", "AUTH_TOKEN", "SESSION", "COOKIE", "APIKEY", "SECRET",
            "JWT", "CARD", "CARD_EXP", "IBAN", "CF", "PIVA", "PHONE", "PRIVATE_KEY", "USERNAME",
            "NAME", "ADDRESS", "DOB", "SSN", "OTP", "PIN", "CVV", "CUSTOM", "FILENAME", "FILE",
            "USER_AGENT", "MAC", "PASSWORD", "URL", "ID");

    private static final Pattern PLACEHOLDER_SHAPE =
            Pattern.compile("([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_\\d{1,9}");

    private final Map<String, String> byValue = new HashMap<>();
    private final Map<String, Integer> counters = new HashMap<>();
    private final List<Entry> entries = new ArrayList<>();
    private final Set<String> exclude;
    private final Set<String> excludeLower = new HashSet<>();
    private final Set<String> placeholders = new HashSet<>();
    private final Map<String, String> hostIndex = new HashMap<>();
    /** placeholder -> originale (prima occorrenza) e radice delle varianti. */
    private final Map<String, String> phToOriginal = new HashMap<>();
    private final Map<String, String> variantRoot = new HashMap<>();
    /** Testi gia' presenti nei messaggi con forma di placeholder: mai generati. */
    private final Set<String> reserved = new HashSet<>();
    private int version = 0;

    public SubstitutionMap() {
        this(null);
    }

    /** exclude: valori che l'utente NON vuole anonimizzare (restano invariati). */
    public SubstitutionMap(Set<String> excludeValues) {
        this.exclude = excludeValues != null ? new HashSet<>(excludeValues) : new HashSet<>();
        for (String v : this.exclude) if (v != null) excludeLower.add(v.toLowerCase(Locale.ROOT));
    }

    /** Ritorna il placeholder per {@code original}, creandone uno nuovo se serve. */
    public String placeholder(String original, String prefix, boolean numbered) {
        if (original == null) {
            return null;
        }
        if (isExcluded(original)) {
            return original; // override utente: non anonimizzare
        }
        if (looksLikePlaceholder(original)) {
            return original; // gia' anonimizzato: non ri-mappare
        }
        String existing = byValue.get(original);
        if (existing != null) {
            return existing;
        }
        String canonKey = canonicalKey(prefix, original);
        if (canonKey != null) {
            existing = byValue.get(canonKey);
            if (existing != null) {
                byValue.put(original, existing);
                return existing;
            }
        }
        String ph;
        if (numbered) {
            int n = counters.getOrDefault(prefix, 0);
            do {
                n++;
                ph = prefix + "_" + n;
            } while (reserved.contains(ph)); // non collidere con testo letterale "EMAIL_1"
            counters.put(prefix, n);
        } else {
            ph = prefix; // es. "REDACTED" non numerato
        }
        byValue.put(original, ph);
        if (canonKey != null) byValue.put(canonKey, ph);
        entries.add(new Entry(original, ph, prefix));
        placeholders.add(ph);
        phToOriginal.putIfAbsent(ph, original);
        version++;
        if (prefix.equals("HOST") || prefix.equals("IP")) {
            hostIndex.putIfAbsent(original.toLowerCase(Locale.ROOT), ph);
        }
        return ph;
    }

    public String placeholder(String original, String prefix) {
        return placeholder(original, prefix, true);
    }

    /** Riserva un testo letterale con forma di placeholder: non verra' mai generato. */
    public void reserve(String literal) {
        if (literal == null || literal.isEmpty() || placeholders.contains(literal)) return;
        // solo testi con un prefisso che il motore usa davvero: un segreto come
        // "VAL_A_1234" ha la stessa forma ma deve comunque essere anonimizzato
        Matcher m = PLACEHOLDER_SHAPE.matcher(literal);
        if (m.matches() && KNOWN_PREFIXES.contains(m.group(1))) reserved.add(literal);
    }

    /** True se il token e' stato emesso da questa mappa (placeholder o variante). */
    public boolean isEmitted(String token) {
        return token != null && placeholders.contains(token);
    }

    /** Originale (rappresentazione esatta) associato a un placeholder emesso. */
    public String originalOf(String placeholder) {
        return phToOriginal.get(placeholder);
    }

    /** Cresce a ogni nuova voce: per invalidare cache costruite sulla mappa. */
    public int version() {
        return version;
    }

    /**
     * Variante esatta di un placeholder per una rappresentazione diversa dello
     * stesso valore (es. "mario%40x.it" per EMAIL_1 -> EMAIL_1_URL). Lo stesso
     * dato resta riconoscibile (stessa radice) e la de-anonimizzazione
     * ricostruisce esattamente la forma originale.
     */
    public String variant(String token, String raw, String kind) {
        if (token == null || raw == null || raw.equals(phToOriginal.get(token))) return token;
        String key = "\u0001" + token + "\u0001" + raw;
        String existing = byValue.get(key);
        if (existing != null) return existing;
        String root = variantRoot.getOrDefault(token, token);
        String base = root + "_" + kind;
        if (!token.equals(root) && token.startsWith(base)) {
            // variante di una variante dello stesso tipo: EMAIL_1_URL -> EMAIL_1_URL2
            String rest = token.substring(base.length());
            int depth = rest.isEmpty() ? 1 : parseIntOr(rest, 1);
            base = root + "_" + kind + (depth + 1);
        }
        String name = base;
        int i = 2;
        while ((placeholders.contains(name) && !raw.equals(phToOriginal.get(name))) || reserved.contains(name)) {
            name = base + "_" + i++;
        }
        if (!placeholders.contains(name)) {
            String type = typeOf(root);
            entries.add(new Entry(raw, name, type));
            placeholders.add(name);
            phToOriginal.put(name, raw);
            variantRoot.put(name, root);
            version++;
        }
        byValue.put(key, name);
        return name;
    }

    private String typeOf(String placeholder) {
        for (Entry e : entries) if (e.placeholder.equals(placeholder)) return e.type;
        return "VARIANT";
    }

    private static int parseIntOr(String s, int def) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
    }

    public boolean isExcluded(String value) {
        if (value == null || exclude.isEmpty()) return false;
        return exclude.contains(value) || excludeLower.contains(value.toLowerCase(Locale.ROOT));
    }

    /**
     * True se il testo e' gia' un placeholder: uno emesso da questa mappa
     * (qualunque maiuscola) oppure con la forma PREFISSO_n di un prefisso noto.
     */
    public boolean looksLikePlaceholder(String s) {
        if (s == null || s.isEmpty() || s.length() > 40) return false;
        if (s.equals("REDACTED")) return true;
        if (placeholders.contains(s) || reserved.contains(s)) return true;
        String up = s.toUpperCase(Locale.ROOT);
        if (placeholders.contains(up)) return true;
        if (!s.equals(up)) return false;
        Matcher m = PLACEHOLDER_SHAPE.matcher(s);
        return m.matches() && (KNOWN_PREFIXES.contains(m.group(1)) || counters.containsKey(m.group(1)));
    }

    /** Chiave canonica per i tipi in cui maiuscole/spazi non cambiano il valore. */
    private static String canonicalKey(String prefix, String v) {
        String c;
        switch (prefix) {
            case "EMAIL":
            case "HOST":
            case "IP":
            case "CUSTOM":
            case "MAC":
                c = v.toLowerCase(Locale.ROOT);
                break;
            case "IBAN":
            case "CARD":
            case "CF":
            case "PIVA":
                c = v.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
                break;
            case "PHONE":
                c = v.replaceAll("[^0-9+]", "");
                break;
            default:
                return null;
        }
        return "\u0000" + prefix + "\u0000" + c;
    }

    public List<Entry> entries() {
        return new ArrayList<>(entries);
    }

    /** Voci aggiunte a partire dall'indice indicato (per scansioni incrementali). */
    public List<Entry> entriesFrom(int start) {
        if (start >= entries.size()) return List.of();
        return new ArrayList<>(entries.subList(Math.max(0, start), entries.size()));
    }

    public int size() {
        return entries.size();
    }

    /** Coppie (host_originale, placeholder) per i prefissi host-like. */
    public List<String[]> knownHosts() {
        List<String[]> out = new ArrayList<>();
        for (Entry e : entries) {
            if (e.type.equals("HOST") || e.type.equals("IP")) {
                out.add(new String[]{e.original, e.placeholder});
            }
        }
        return out;
    }

    /** Indice host/IP noti: originale in minuscolo -> placeholder. Sola lettura. */
    public Map<String, String> hostIndex() {
        return Collections.unmodifiableMap(hostIndex);
    }

    /**
     * Mappa placeholder -> originale per la de-anonimizzazione. Esclude i
     * placeholder ambigui (piu' originali sullo stesso placeholder, es.
     * "REDACTED"), non reversibili in modo univoco.
     */
    public Map<String, String> reverseMap() {
        Map<String, Integer> counts = new HashMap<>();
        for (Entry e : entries) {
            counts.merge(e.placeholder, 1, Integer::sum);
        }
        Map<String, String> rev = new LinkedHashMap<>();
        for (Entry e : entries) {
            if (counts.get(e.placeholder) == 1) {
                rev.put(e.placeholder, e.original);
            }
        }
        return rev;
    }
}
