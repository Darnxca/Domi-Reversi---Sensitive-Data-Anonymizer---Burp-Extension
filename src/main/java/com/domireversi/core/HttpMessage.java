package com.domireversi.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rappresentazione strutturata e parsing robusto di un messaggio HTTP grezzo.
 * Non solleva mai eccezioni verso il chiamante (fallback graceful). Port di
 * parser.py.
 */
public final class HttpMessage {

    /** Header come coppia nome/valore (ordine e duplicati preservati). */
    public static final class Header {
        public String name;
        public String value;
        public Header(String name, String value) { this.name = name; this.value = value; }
    }

    public String kind = "unknown";          // "request" | "response" | "unknown"
    public String startLine = "";
    public final List<Header> headers = new ArrayList<>();
    public String body = "";
    public String newline = "\r\n";
    public boolean hadBodySeparator = false;
    public boolean isEmpty = true;

    private static final Pattern STATUS_LINE =
            Pattern.compile("^\\s*HTTP/\\d(?:\\.\\d)?\\s+\\d{3}\\b", Pattern.CASE_INSENSITIVE);
    private static final String METHODS =
            "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|"
            + "MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT|SEARCH";
    private static final Pattern REQUEST_LINE =
            Pattern.compile("^\\s*(" + METHODS + ")\\s+\\S+(?:\\s+HTTP/\\d(?:\\.\\d)?)?\\s*$",
                            Pattern.CASE_INSENSITIVE);
    private static final Pattern HEADER_NAME =
            Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");
    private static final Pattern BODY_SEP = Pattern.compile("\\r\\n\\r\\n|\\n\\n|\\r\\r");

    public String get(String name) {
        String low = name.toLowerCase();
        for (Header h : headers) {
            if (h.name.toLowerCase().equals(low)) return h.value;
        }
        return null;
    }

    public List<String> getAll(String name) {
        String low = name.toLowerCase();
        List<String> out = new ArrayList<>();
        for (Header h : headers) {
            if (h.name.toLowerCase().equals(low)) out.add(h.value);
        }
        return out;
    }

    /** Content-Type di base (senza parametri), minuscolo. */
    public String contentType() {
        String ct = get("Content-Type");
        if (ct == null) return "";
        int sc = ct.indexOf(';');
        return (sc >= 0 ? ct.substring(0, sc) : ct).trim().toLowerCase();
    }

    // ------------------------------------------------------------------ parse
    public static HttpMessage parse(String text) {
        HttpMessage msg = new HttpMessage();
        if (text == null || text.trim().isEmpty()) {
            return msg; // isEmpty = true
        }
        try {
            msg.newline = detectNewline(text);
            String[] hb = splitHeadBody(text);
            String head = hb[0];
            msg.body = hb[1];
            msg.hadBodySeparator = hb[2] != null;

            List<String> lines = new ArrayList<>();
            for (String l : head.split("\\r\\n|\\n|\\r", -1)) lines.add(l);
            while (!lines.isEmpty() && lines.get(0).trim().isEmpty()) lines.remove(0);

            msg.isEmpty = false;
            if (lines.isEmpty()) {
                msg.kind = "unknown";
                return msg;
            }
            String first = lines.get(0);
            String k = classify(first);
            List<String> headerLines;
            if (k.equals("unknown")) {
                if (looksLikeHeader(first)) {
                    msg.startLine = "";
                    headerLines = lines;
                } else {
                    msg.startLine = first;
                    headerLines = lines.subList(1, lines.size());
                }
            } else {
                msg.kind = k;
                msg.startLine = first;
                headerLines = lines.subList(1, lines.size());
            }
            parseHeaders(msg, headerLines);
            return msg;
        } catch (Exception e) {
            HttpMessage fb = new HttpMessage();
            fb.isEmpty = false;
            fb.body = text;
            return fb;
        }
    }

    private static String detectNewline(String t) {
        if (t.contains("\r\n")) return "\r\n";
        if (t.contains("\n")) return "\n";
        if (t.contains("\r")) return "\r";
        return "\r\n";
    }

    /** {head, body, sep-or-null}. */
    private static String[] splitHeadBody(String text) {
        Matcher m = BODY_SEP.matcher(text);
        if (m.find()) {
            return new String[]{text.substring(0, m.start()), text.substring(m.end()), "x"};
        }
        return new String[]{text, "", null};
    }

    private static String classify(String line) {
        if (line.trim().isEmpty()) return "unknown";
        if (STATUS_LINE.matcher(line).find()) return "response";
        if (REQUEST_LINE.matcher(line).find()) return "request";
        return "unknown";
    }

    private static boolean looksLikeHeader(String line) {
        int c = line.indexOf(':');
        if (c < 0) return false;
        String name = line.substring(0, c).trim();
        return !name.isEmpty() && HEADER_NAME.matcher(name).matches();
    }

    private static void parseHeaders(HttpMessage msg, List<String> lines) {
        for (String line : lines) {
            if (line.isEmpty()) continue;
            char c0 = line.charAt(0);
            if ((c0 == ' ' || c0 == '\t') && !msg.headers.isEmpty()) {
                Header last = msg.headers.get(msg.headers.size() - 1);
                last.value = last.value + " " + line.trim();
                continue;
            }
            int c = line.indexOf(':');
            if (c < 0) {
                msg.headers.add(new Header("", line));
                continue;
            }
            msg.headers.add(new Header(line.substring(0, c).trim(), line.substring(c + 1).trim()));
        }
    }

    // -------------------------------------------------------------- serialize
    public String serialize() {
        if (isEmpty) return "";
        String nl = (newline == null || newline.isEmpty()) ? "\r\n" : newline;
        StringBuilder sb = new StringBuilder();
        List<String> parts = new ArrayList<>();
        if (startLine != null && !startLine.isEmpty()) parts.add(startLine);
        for (Header h : headers) {
            if (h.name.isEmpty()) parts.add(h.value);
            else parts.add(h.name + ": " + h.value);
        }
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) sb.append(nl);
            sb.append(parts.get(i));
        }
        if (hadBodySeparator || (body != null && !body.isEmpty())) {
            sb.append(nl).append(nl).append(body == null ? "" : body);
        }
        return sb.toString();
    }
}
