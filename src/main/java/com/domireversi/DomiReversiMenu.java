package com.domireversi;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.Direction;
import com.domireversi.core.Transcript;
import com.domireversi.ui.DomiReversiTab;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Voci del menu contestuale su tutto cio' che passa da Burp:
 * <ul>
 *   <li>request/response (Proxy history, Repeater, Logger, Site map, Intruder...),
 *       anche piu' di una alla volta, nella stessa sessione;</li>
 *   <li>messaggi WebSocket (WebSocket history ed editor): handshake + trascritto;</li>
 *   <li>issue dello Scanner (Dashboard, Target): dettaglio e rimedio da far
 *       rivedere all'LLM, con la richiesta che le ha generate.</li>
 * </ul>
 * Estrae i dati e li passa al tab, che li anonimizza col core Java.
 */
public final class DomiReversiMenu implements ContextMenuItemsProvider {

    /** Oltre questo numero di messaggi selezionati si usano solo i primi (sessione leggibile). */
    private static final int MAX_SELECTED = 100;

    private final DomiReversiTab tab;

    public DomiReversiMenu(DomiReversiTab tab) {
        this.tab = tab;
    }

    // ------------------------------------------------------------------ HTTP
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> sel = new ArrayList<>();
        try {
            if (event.selectedRequestResponses() != null) sel.addAll(event.selectedRequestResponses());
            if (sel.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
                sel.add(event.messageEditorRequestResponse().get().requestResponse());
            }
        } catch (Exception e) {
            return null;
        }
        if (sel.isEmpty()) return null;

        List<Component> items = new ArrayList<>();
        if (sel.size() > 1) {
            List<String[]> pairs = new ArrayList<>();
            for (HttpRequestResponse rr : sel.subList(0, Math.min(MAX_SELECTED, sel.size()))) {
                pairs.add(new String[]{rawRequest(rr), rawResponse(rr)});
            }
            JMenuItem many = new JMenuItem(tab.menuLabelMany(pairs.size()));
            many.addActionListener(e -> tab.loadMany(pairs));
            items.add(many);
        }
        HttpRequestResponse first = sel.get(0);
        String req = rawRequest(first);
        String resp = rawResponse(first);
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_BOTH), DomiReversiTab.SCOPE_BOTH, req, resp));
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_REQUEST), DomiReversiTab.SCOPE_REQUEST, req, resp));
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_RESPONSE), DomiReversiTab.SCOPE_RESPONSE, req, resp));
        return items;
    }

    // ------------------------------------------------------------- WebSocket
    @Override
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        List<WebSocketMessage> sel = new ArrayList<>();
        try {
            if (event.selectedWebSocketMessages() != null) sel.addAll(event.selectedWebSocketMessages());
            if (sel.isEmpty() && event.messageEditorWebSocket().isPresent()) {
                sel.add(event.messageEditorWebSocket().get().webSocketMessage());
            }
        } catch (Exception e) {
            return null;
        }
        if (sel.isEmpty()) return null;
        List<WebSocketMessage> msgs = sel.subList(0, Math.min(MAX_SELECTED, sel.size()));
        JMenuItem item = new JMenuItem(tab.menuLabelWebSocket(msgs.size()));
        item.addActionListener(e -> {
            List<Transcript.Frame> frames = new ArrayList<>();
            HttpRequest upgrade = null;
            for (WebSocketMessage m : msgs) {
                if (upgrade == null) upgrade = safeUpgrade(m);
                frames.add(new Transcript.Frame(m.direction() == Direction.CLIENT_TO_SERVER, text(m.payload())));
            }
            String upgradeRaw = upgrade == null ? "" : text(upgrade.toByteArray());
            String url = upgrade == null ? "" : safeUrl(upgrade);
            tab.loadTranscript(upgradeRaw, Transcript.webSocket(url, frames));
        });
        return List.of(item);
    }

    // ---------------------------------------------------------- issue Scanner
    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        List<AuditIssue> issues;
        try {
            issues = event.selectedIssues();
        } catch (Exception e) {
            return null;
        }
        if (issues == null || issues.isEmpty()) return null;
        List<AuditIssue> sel = issues.subList(0, Math.min(20, issues.size()));
        JMenuItem item = new JMenuItem(tab.menuLabelIssue(sel.size()));
        item.addActionListener(e -> {
            StringBuilder transcript = new StringBuilder();
            String req = "";
            for (AuditIssue i : sel) {
                String bg = "", remBg = "";
                try {
                    bg = i.definition() != null ? i.definition().background() : "";
                    remBg = i.definition() != null ? i.definition().remediation() : "";
                } catch (Exception ignored) {
                    // definizione non disponibile per le issue create da estensioni
                }
                String remediation = i.remediation() != null && !i.remediation().isBlank() ? i.remediation() : remBg;
                String t = Transcript.issue(i.name(), String.valueOf(i.severity()), String.valueOf(i.confidence()),
                        i.baseUrl(), i.detail(), bg, remediation);
                // solo la prima issue apre il trascritto; le altre diventano blocchi
                transcript.append(transcript.length() == 0 ? t : t.substring(t.indexOf('\n') + 1));
                if (req.isEmpty() && i.requestResponses() != null && !i.requestResponses().isEmpty()) {
                    req = rawRequest(i.requestResponses().get(0));
                }
            }
            tab.loadTranscript(req, transcript.toString());
        });
        return List.of(item);
    }

    // ------------------------------------------------------------------ util
    private JMenuItem menuItem(String label, int scope, String req, String resp) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> { tab.setScope(scope); tab.load(req, resp); });
        return item;
    }

    private static HttpRequest safeUpgrade(WebSocketMessage m) {
        try {
            return m.upgradeRequest();
        } catch (Exception e) {
            return null;
        }
    }

    private static String safeUrl(HttpRequest r) {
        try {
            return r.url();
        } catch (Exception e) {
            return "";
        }
    }

    private static String text(ByteArray b) {
        try {
            return b == null ? "" : b.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String rawRequest(HttpRequestResponse rr) {
        try {
            // toByteArray() restituisce il messaggio grezzo completo;
            // ByteArray.toString() ne da' la forma testuale.
            return rr.request() != null ? rr.request().toByteArray().toString() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private static String rawResponse(HttpRequestResponse rr) {
        try {
            return rr.response() != null ? rr.response().toByteArray().toString() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
