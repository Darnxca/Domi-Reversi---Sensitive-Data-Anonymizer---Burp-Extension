package com.domireversi;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.domireversi.ui.DomiReversiTab;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Voce di menu contestuale "Anonimizza con Domi Reversi" su una request/response
 * selezionata (Proxy history, Repeater, ...). Estrae il messaggio grezzo e lo
 * passa al tab, che lo anonimizza col core Java.
 */
public final class DomiReversiMenu implements ContextMenuItemsProvider {

    private final DomiReversiTab tab;

    public DomiReversiMenu(DomiReversiTab tab) {
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequestResponse selected = pick(event);
        if (selected == null) {
            return null;
        }
        String req = rawRequest(selected);
        String resp = rawResponse(selected);

        List<Component> items = new ArrayList<>();
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_BOTH), DomiReversiTab.SCOPE_BOTH, req, resp));
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_REQUEST), DomiReversiTab.SCOPE_REQUEST, req, resp));
        items.add(menuItem(tab.menuLabel(DomiReversiTab.SCOPE_RESPONSE), DomiReversiTab.SCOPE_RESPONSE, req, resp));
        return items;
    }

    private JMenuItem menuItem(String label, int scope, String req, String resp) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> { tab.setScope(scope); tab.load(req, resp); });
        return item;
    }

    private static HttpRequestResponse pick(ContextMenuEvent event) {
        List<HttpRequestResponse> sel = event.selectedRequestResponses();
        if (sel != null && !sel.isEmpty()) {
            return sel.get(0);
        }
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse();
        }
        return null;
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
