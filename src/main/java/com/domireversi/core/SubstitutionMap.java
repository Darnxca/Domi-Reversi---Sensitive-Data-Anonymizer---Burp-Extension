package com.domireversi.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Mappa di sostituzione coerente: lo stesso valore originale riceve SEMPRE lo
 * stesso placeholder, indipendentemente dal prefisso richiesto (vince il primo
 * tipo con cui e' stato incontrato). I numeri sono progressivi per prefisso.
 *
 * Port fedele di SubstitutionMap (anonymizer.py).
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

    private final Map<String, String> byValue = new HashMap<>();
    private final Map<String, Integer> counters = new HashMap<>();
    private final List<Entry> entries = new ArrayList<>();
    private final Set<String> exclude;

    public SubstitutionMap() {
        this.exclude = new HashSet<>();
    }

    /** exclude: valori che l'utente NON vuole anonimizzare (restano invariati). */
    public SubstitutionMap(Set<String> excludeValues) {
        this.exclude = excludeValues != null ? new HashSet<>(excludeValues) : new HashSet<>();
    }

    /** Ritorna il placeholder per {@code original}, creandone uno nuovo se serve. */
    public String placeholder(String original, String prefix, boolean numbered) {
        if (original == null) {
            return null;
        }
        if (exclude.contains(original)) {
            return original; // override utente: non anonimizzare
        }
        String existing = byValue.get(original);
        if (existing != null) {
            return existing;
        }
        String ph;
        if (numbered) {
            int n = counters.getOrDefault(prefix, 0) + 1;
            counters.put(prefix, n);
            ph = prefix + "_" + n;
        } else {
            ph = prefix; // es. "REDACTED" non numerato
        }
        byValue.put(original, ph);
        entries.add(new Entry(original, ph, prefix));
        return ph;
    }

    public String placeholder(String original, String prefix) {
        return placeholder(original, prefix, true);
    }

    public List<Entry> entries() {
        return new ArrayList<>(entries);
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
