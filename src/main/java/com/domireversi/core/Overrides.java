package com.domireversi.core;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Override utente ("seconda opzione"): personalizza cosa anonimizzare.
 *
 *  extraHeaders   -> header il cui VALORE va anonimizzato in piu' (-> CUSTOM_n)
 *  excludeHeaders -> header da NON anonimizzare (lasciati intatti)
 *  extraKeys      -> chiavi JSON/form/query da anonimizzare in piu'
 *  excludeKeys    -> chiavi da NON anonimizzare per nome
 *  excludeValues  -> valori esatti da NON anonimizzare mai
 */
public final class Overrides {

    public final Set<String> extraHeaders = new HashSet<>();
    public final Set<String> excludeHeaders = new HashSet<>();
    public final Set<String> extraKeys = new HashSet<>();
    public final Set<String> excludeKeys = new HashSet<>();
    public final Set<String> excludeValues = new HashSet<>();
    // valori esatti scelti a mano dall'utente da anonimizzare (-> CUSTOM_n)
    public final Set<String> forceValues = new HashSet<>();
    // nome del cliente e termini riservati (progetto, codici interni) -> ORG_n ovunque
    public final Set<String> orgTerms = new java.util.LinkedHashSet<>();

    public Overrides withOrgTerms(Collection<String> terms) {
        if (terms != null) {
            for (String t : terms) if (t != null && t.trim().length() >= 3) orgTerms.add(t.trim());
        }
        return this;
    }

    public static Overrides empty() {
        return new Overrides();
    }

    public Overrides withForced(Collection<String> values) {
        if (values != null) {
            for (String v : values) if (v != null && !v.isEmpty()) forceValues.add(v);
        }
        return this;
    }

    public Overrides withHeaders(Collection<String> extra, Collection<String> exclude) {
        addLower(extraHeaders, extra);
        addLower(excludeHeaders, exclude);
        return this;
    }

    public Overrides withKeys(Collection<String> extra, Collection<String> exclude) {
        addNorm(extraKeys, extra);
        addNorm(excludeKeys, exclude);
        return this;
    }

    public Overrides withValues(Collection<String> values) {
        if (values != null) {
            for (String v : values) if (v != null && !v.isEmpty()) excludeValues.add(v);
        }
        return this;
    }

    static String normKey(String key) {
        return key.toLowerCase().replaceAll("[\\s_\\-]", "");
    }

    private static void addLower(Set<String> set, Collection<String> src) {
        if (src == null) return;
        for (String s : src) {
            if (s != null && !s.trim().isEmpty()) set.add(s.toLowerCase().trim());
        }
    }

    private static void addNorm(Set<String> set, Collection<String> src) {
        if (src == null) return;
        for (String s : src) {
            if (s != null && !s.trim().isEmpty()) set.add(normKey(s));
        }
    }
}
