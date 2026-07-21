package com.domireversi.ui;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.Overrides;
import com.domireversi.core.SubstitutionMap;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pannello UI dell'estensione (Swing puro + core). Logica interamente Java:
 * nessun processo esterno. Supporta lingua EN/IT ed esclusioni per-valore
 * (spunte nella tabella della mappa).
 */
public final class DomiReversiTab {

    public static final int SCOPE_BOTH = 0;
    public static final int SCOPE_REQUEST = 1;
    public static final int SCOPE_RESPONSE = 2;

    private static final Font MONO = new Font("Monospaced", Font.PLAIN, 12);

    private boolean english = true;                       // lingua: default EN (store)
    private final List<Runnable> relabelers = new ArrayList<>();

    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel(" ");
    private final Config config = Config.loadFromResources();

    private final JTextArea reqIn = area(true);
    private final JTextArea reqOut = area(false);
    private final JTextArea respIn = area(true);
    private final JTextArea respOut = area(false);
    private final JCheckBox chkUa = new JCheckBox();
    private final JComboBox<String> scopeBox = new JComboBox<>();
    private final JComboBox<String> langBox = new JComboBox<>(new String[]{"English", "Italiano"});

    private final DefaultTableModel mapModel = new DefaultTableModel(new Object[]{"", "", "", ""}, 0) {
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
    };
    private final JLabel mapNote = new JLabel();
    // valori che l'utente ha DESELEZIONATO (da NON anonimizzare): original -> type
    private final Map<String, String> excluded = new LinkedHashMap<>();
    // valori scelti a mano (selezione + Anonimizza) da anonimizzare -> CUSTOM_n
    private final Set<String> forcedValues = new LinkedHashSet<>();
    private boolean rebuilding = false;

    private final JTextArea deanonIn = area(true);
    private final JTextArea deanonOut = area(false);
    private Map<String, String> lastReverse = Map.of();

    private final JPanel root = new JPanel(new BorderLayout());

    public DomiReversiTab() {
        tabs.addTab("", buildAnonTab());
        tabs.addTab("", buildMapTab());
        tabs.addTab("", buildDeanonTab());
        root.add(tabs, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        langBox.setSelectedIndex(0);
        langBox.addActionListener(e -> { english = langBox.getSelectedIndex() == 0; relabel(); });

        mapModel.addTableModelListener(new TableModelListener() {
            @Override public void tableChanged(TableModelEvent e) {
                if (rebuilding || e.getColumn() != 0 || e.getType() != TableModelEvent.UPDATE) return;
                onCheckboxToggled(e.getFirstRow());
            }
        });
        installForceAnon(reqIn);
        installForceAnon(respIn);
        relabel();
    }

    public JComponent getComponent() { return root; }

    public void setScope(int scope) { scopeBox.setSelectedIndex(scope); }

    /** Etichetta del menu contestuale nella lingua corrente. */
    public String menuLabel(int scope) {
        switch (scope) {
            case SCOPE_REQUEST:  return tr("Anonimizza — solo request", "Anonymize — request only");
            case SCOPE_RESPONSE: return tr("Anonimizza — solo response", "Anonymize — response only");
            default:             return tr("Anonimizza (request + response)", "Anonymize (request + response)");
        }
    }

    /** Carica dal menu contestuale, rispettando l'ambito: "solo request" NON
     *  carica la response (e viceversa). */
    public void load(String request, String response) {
        int scope = scopeBox.getSelectedIndex();
        reqIn.setText(scope == SCOPE_RESPONSE ? "" : norm(request));
        respIn.setText(scope == SCOPE_REQUEST ? "" : norm(response));
        reqIn.setCaretPosition(0);
        respIn.setCaretPosition(0);
        excluded.clear();       // nuovo messaggio -> reset esclusioni
        forcedValues.clear();   // e reset dei valori forzati
        tabs.setSelectedIndex(0);
        anonymize();
    }

    // -------------------------------------------------------------------- i18n
    private String tr(String it, String en) { return english ? en : it; }

    private void relabel() {
        tabs.setTitleAt(0, tr("Anonimizzatore", "Anonymizer"));
        tabs.setTitleAt(1, tr("Mappa sostituzioni", "Substitution map"));
        tabs.setTitleAt(2, tr("De-anonimizza", "De-anonymize"));
        chkUa.setText(tr("Anonimizza User-Agent", "Anonymize User-Agent"));
        int sc = scopeBox.getSelectedIndex();
        scopeBox.setModel(new DefaultComboBoxModel<>(new String[]{
                "Request + Response", tr("Solo request", "Request only"), tr("Solo response", "Response only")}));
        scopeBox.setSelectedIndex(sc < 0 ? 0 : sc);
        mapModel.setColumnIdentifiers(new Object[]{
                tr("Anon.", "Anon."), tr("Originale", "Original"),
                "Placeholder", tr("Tipo", "Type")});
        mapNote.setText(tr(
                "<html>Togli la spunta a un valore per <b>tenerlo in chiaro</b> (si ri-anonimizza subito). NON incollare questa tabella nell'LLM.</html>",
                "<html>Uncheck a value to <b>keep it un-anonymized</b> (re-applies instantly). Do NOT paste this table into the LLM.</html>"));
        for (Runnable r : relabelers) r.run();
        if (!reqIn.getText().isBlank() || !respIn.getText().isBlank()) anonymize();
    }

    // -------------------------------------------------------------------- UI
    private static JTextArea area(boolean editable) {
        JTextArea a = new JTextArea();
        a.setEditable(editable);
        a.setFont(MONO);
        a.setLineWrap(true);           // evita il glitch delle righe lunghissime
        a.setWrapStyleWord(true);
        a.setTabSize(4);
        return a;
    }

    private static String norm(String s) {
        return s == null ? "" : s.replace("\r\n", "\n").replace('\r', '\n');
    }

    private JScrollPane titled(String it, String en, JComponent c) {
        JScrollPane sp = new JScrollPane(c);
        TitledBorder tb = BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), tr(it, en), TitledBorder.LEFT, TitledBorder.TOP);
        sp.setBorder(tb);
        relabelers.add(() -> tb.setTitle(tr(it, en)));
        return sp;
    }

    private JButton button(String it, String en, Runnable action) {
        JButton b = new JButton(tr(it, en));
        relabelers.add(() -> b.setText(tr(it, en)));
        b.addActionListener(e -> action.run());
        return b;
    }

    private JLabel label(String it, String en) {
        JLabel l = new JLabel(tr(it, en));
        relabelers.add(() -> l.setText(tr(it, en)));
        return l;
    }

    private JComponent buildAnonTab() {
        JSplitPane reqSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled("REQUEST — input", "REQUEST — input", reqIn),
                titled("REQUEST — anonimizzata", "REQUEST — anonymized", reqOut));
        JSplitPane respSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled("RESPONSE — input", "RESPONSE — input", respIn),
                titled("RESPONSE — anonimizzata", "RESPONSE — anonymized", respOut));
        reqSplit.setResizeWeight(0.5);
        respSplit.setResizeWeight(0.5);
        JSplitPane io = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqSplit, respSplit);
        io.setResizeWeight(0.5);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        bar.add(button("🔒 Anonimizza", "🔒 Anonymize", this::anonymize));
        bar.add(label("ambito:", "scope:"));
        bar.add(scopeBox);
        bar.add(button("Copia request", "Copy request", () -> copy(reqOut)));
        bar.add(button("Copia response", "Copy response", () -> copy(respOut)));
        bar.add(button("Pulisci", "Clear", this::clear));
        bar.add(chkUa);
        bar.add(new JLabel("  |  "));
        bar.add(new JLabel("Language:"));
        bar.add(langBox);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(io, BorderLayout.CENTER);
        panel.add(bar, BorderLayout.SOUTH);
        return panel;
    }

    private JComponent buildMapTab() {
        JTable table = new JTable(mapModel);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.setAutoCreateRowSorter(true);

        mapNote.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(mapNote, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildDeanonTab() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled("Risposta dell'LLM (con placeholder)", "LLM reply (with placeholders)", deanonIn),
                titled("Testo de-anonimizzato", "De-anonymized text", deanonOut));
        split.setResizeWeight(0.5);
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        bar.add(button("🔓 De-anonimizza", "🔓 De-anonymize", this::deanonymize));
        bar.add(button("Copia", "Copy", () -> copy(deanonOut)));
        bar.add(label("(usa la mappa dell'ultima anonimizzazione)", "(uses the last anonymization map)"));
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        panel.add(bar, BorderLayout.SOUTH);
        return panel;
    }

    // ---------------------------------------------------------------- azioni
    private void onCheckboxToggled(int row) {
        try {
            boolean anon = Boolean.TRUE.equals(mapModel.getValueAt(row, 0));
            String original = String.valueOf(mapModel.getValueAt(row, 1));
            String type = String.valueOf(mapModel.getValueAt(row, 3));
            if (anon) excluded.remove(original);
            else excluded.put(original, type);
            anonymize();  // ri-anonimizza subito onorando le esclusioni
        } catch (Exception ignored) {
        }
    }

    // ---- anonimizzazione manuale della selezione ----
    private void installForceAnon(JTextArea area) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copy = new JMenuItem();
        JMenuItem paste = new JMenuItem();
        JMenuItem anon = new JMenuItem();
        relabelers.add(() -> {
            copy.setText(tr("Copia", "Copy"));
            paste.setText(tr("Incolla", "Paste"));
            anon.setText(tr("Anonimizza selezione", "Anonymize selection") + "  (Ctrl+Shift+A)");
        });
        copy.addActionListener(e -> area.copy());
        paste.addActionListener(e -> area.paste());
        anon.addActionListener(e -> anonymizeSelection(area));
        menu.add(copy);
        menu.add(paste);
        menu.addSeparator();
        menu.add(anon);
        area.setComponentPopupMenu(menu);

        // scorciatoia Ctrl+Shift+A sull'input
        area.getInputMap().put(KeyStroke.getKeyStroke("ctrl shift A"), "anonSel");
        area.getActionMap().put("anonSel", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { anonymizeSelection(area); }
        });
    }

    private void anonymizeSelection(JTextArea area) {
        String sel = area.getSelectedText();
        if (sel == null || sel.trim().isEmpty()) {
            status.setText(" " + tr("Nessuna selezione da anonimizzare.", "No selection to anonymize."));
            return;
        }
        forcedValues.add(sel);
        excluded.remove(sel);
        anonymize();
        String s = sel.length() > 40 ? sel.substring(0, 40) + "…" : sel;
        status.setText(" " + tr("Anonimizzate le occorrenze di: ", "Anonymized occurrences of: ") + s);
    }

    private void anonymize() {
        try {
            config.anonymizeUserAgent = chkUa.isSelected();
            Overrides ov = Overrides.empty()
                    .withValues(new ArrayList<>(excluded.keySet()))
                    .withForced(new ArrayList<>(forcedValues));
            SubstitutionMap map = new SubstitutionMap(ov.excludeValues);
            Anonymizer eng = new Anonymizer(config, map, ov);

            int scope = scopeBox.getSelectedIndex();
            String req = (scope != SCOPE_RESPONSE) ? reqIn.getText() : "";
            String resp = (scope != SCOPE_REQUEST) ? respIn.getText() : "";
            reqOut.setText(req.isBlank() ? "" : eng.anonymizeRequest(req));
            respOut.setText(resp.isBlank() ? "" : eng.anonymizeResponse(resp));
            reqOut.setCaretPosition(0);
            respOut.setCaretPosition(0);

            rebuildMap(map);
            lastReverse = map.reverseMap();
            status.setText(" " + tr("Fatto. ", "Done. ") + map.size()
                    + tr(" valori sostituiti.", " values substituted.")
                    + (excluded.isEmpty() ? "" : "  " + excluded.size() + tr(" esclusi.", " excluded.")));
        } catch (Exception ex) {
            status.setText(" " + tr("Errore: ", "Error: ") + ex.getMessage());
        }
    }

    private void rebuildMap(SubstitutionMap map) {
        rebuilding = true;
        try {
            mapModel.setRowCount(0);
            for (SubstitutionMap.Entry e : map.entries()) {
                mapModel.addRow(new Object[]{Boolean.TRUE, e.original, e.placeholder, e.type});
            }
            // righe per i valori esclusi (deselezionati), cosi' si possono ri-attivare
            for (Map.Entry<String, String> e : excluded.entrySet()) {
                mapModel.addRow(new Object[]{Boolean.FALSE, e.getKey(),
                        tr("(in chiaro)", "(kept as-is)"), e.getValue()});
            }
        } finally {
            rebuilding = false;
        }
    }

    private void deanonymize() {
        if (lastReverse.isEmpty()) {
            status.setText(" " + tr("Nessuna mappa: anonimizza prima.", "No map: anonymize first."));
            return;
        }
        deanonOut.setText(Anonymizer.deanonymize(deanonIn.getText(), lastReverse));
        deanonOut.setCaretPosition(0);
        status.setText(" " + tr("De-anonimizzazione completata.", "De-anonymization done."));
    }

    private void clear() {
        for (JTextArea a : List.of(reqIn, reqOut, respIn, respOut, deanonIn, deanonOut)) a.setText("");
        excluded.clear();
        forcedValues.clear();
        rebuilding = true;
        mapModel.setRowCount(0);
        rebuilding = false;
        lastReverse = Map.of();
        status.setText(" " + tr("Pulito.", "Cleared."));
    }

    private void copy(JTextArea a) {
        String t = a.getText();
        if (t == null || t.isEmpty()) { status.setText(" " + tr("Niente da copiare.", "Nothing to copy.")); return; }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(t), null);
        status.setText(" " + tr("Copiato.", "Copied."));
    }
}
