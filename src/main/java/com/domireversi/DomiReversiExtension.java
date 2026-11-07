package com.domireversi;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.domireversi.ui.DomiReversiTab;

/**
 * Entry point dell'estensione Burp (Montoya API).
 *
 * L'estensione e' interamente Java e AUTONOMA: la logica di anonimizzazione
 * (com.domireversi.core) e i pattern (risorse bundlate nel jar) girano dentro
 * Burp, senza processi esterni ne' dipendenze da installare. Requisito del
 * BApp Store.
 */
public final class DomiReversiExtension implements BurpExtension {

    // Nome dell'estensione (mostrato in Extensions e sul BApp Store).
    // Descrittivo apposta: chiarisce che anonimizza header e parametri/chiavi
    // di request e response. Cambialo qui se preferisci un altro suffisso.
    private static final String EXTENSION_NAME = "Domi Reversi - Sensitive Data Anonymizer";
    // Titolo del tab (corto, per stare nella barra dei tab di Burp).
    private static final String TAB_TITLE = "Domi Reversi";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        DomiReversiTab tab = new DomiReversiTab();
        try {
            tab.setEditorFont(api.userInterface().currentEditorFont());
        } catch (Throwable ignored) {
            // versioni di Burp senza questa API: resta il font monospazio di default
        }
        api.userInterface().registerSuiteTab(TAB_TITLE, tab.getComponent());
        api.userInterface().registerContextMenuItemsProvider(new DomiReversiMenu(tab));

        api.logging().logToOutput(
                EXTENSION_NAME + " caricato. Tasto destro su una request/response "
                + "> \"Anonimizza con Domi Reversi\", oppure usa il tab dedicato.");
    }
}
