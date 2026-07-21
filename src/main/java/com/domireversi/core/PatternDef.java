package com.domireversi.core;

import java.util.regex.Pattern;

/** Un pattern regex per dati sensibili (port delle voci di sensitive_patterns.json). */
public final class PatternDef {
    public final String name;
    public final String prefix;
    public final Pattern regex;
    public final String validate;   // "luhn" | "phone" | null
    public final Integer keepGroup; // gruppo da preservare (es. schema Bearer), o null

    public PatternDef(String name, String prefix, Pattern regex, String validate, Integer keepGroup) {
        this.name = name;
        this.prefix = prefix;
        this.regex = regex;
        this.validate = validate;
        this.keepGroup = keepGroup;
    }
}
