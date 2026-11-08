package com.domireversi.core;

import java.util.List;
import java.util.Locale;

/**
 * Costruisce i trascritti di contenuti che passano da Burp ma non sono una
 * coppia request/response (WebSocket, issue dello Scanner), nel formato che
 * {@link Anonymizer#anonymizeTranscript(String)} riconosce: una prima riga
 * "### Domi Reversi ..." e blocchi separati da righe "### ...".
 * Indipendente da Burp, quindi testabile.
 */
public final class Transcript {

    private Transcript() {
    }

    /** Un messaggio WebSocket: verso (true = dal client) e contenuto testuale. */
    public static final class Frame {
        public final boolean fromClient;
        public final String payload;

        public Frame(boolean fromClient, String payload) {
            this.fromClient = fromClient;
            this.payload = payload == null ? "" : payload;
        }
    }

    public static String webSocket(String url, List<Frame> frames) {
        StringBuilder sb = new StringBuilder(Anonymizer.TRANSCRIPT_HEAD).append(" · WebSocket");
        if (url != null && !url.isBlank()) sb.append(" · ").append(url.trim());
        sb.append('\n');
        int i = 1;
        for (Frame f : frames) {
            sb.append("### #").append(i++).append(f.fromClient ? " client → server" : " server → client").append('\n');
            sb.append(f.payload);
            if (!f.payload.endsWith("\n")) sb.append('\n');
        }
        return sb.toString();
    }

    /** Una issue dello Scanner: nome, gravita', URL, dettaglio e rimedio (HTML di Burp). */
    public static String issue(String name, String severity, String confidence, String url,
                               String detail, String background, String remediation) {
        StringBuilder sb = new StringBuilder(Anonymizer.TRANSCRIPT_HEAD).append(" · Burp issue\n");
        sb.append("### ").append(nz(name)).append(" · ").append(nz(severity).toLowerCase(Locale.ROOT))
          .append(" / ").append(nz(confidence).toLowerCase(Locale.ROOT)).append('\n');
        if (url != null && !url.isBlank()) sb.append("### URL: ").append(url.trim()).append('\n');
        block(sb, "Dettaglio", detail);
        block(sb, "Descrizione", background);
        block(sb, "Rimedio", remediation);
        return sb.toString();
    }

    private static void block(StringBuilder sb, String title, String html) {
        if (html == null || html.isBlank()) return;
        sb.append("### ").append(title).append('\n').append(html.trim()).append('\n');
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
