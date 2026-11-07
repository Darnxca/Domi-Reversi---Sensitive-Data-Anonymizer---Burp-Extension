package com.domireversi.ui;

import com.domireversi.core.Anonymizer;
import com.domireversi.core.Config;
import com.domireversi.core.Overrides;
import com.domireversi.core.SubstitutionMap;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Pannello UI dell'estensione (Swing puro + core). Supporta lingua EN/IT,
 * esclusioni per-valore (spunte nella mappa), anonimizzazione manuale della
 * selezione ed evidenziazione di cosa viene sostituito. Colori derivati dal
 * tema corrente, quindi leggibili sia col tema chiaro sia con quello scuro di Burp.
 */
public final class DomiReversiTab {

    public static final int SCOPE_BOTH = 0;
    public static final int SCOPE_REQUEST = 1;
    public static final int SCOPE_RESPONSE = 2;

    private Font editorFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);

    private boolean english = true;                       // lingua: default EN (store)
    private final List<Runnable> relabelers = new ArrayList<>();
    private final List<HiArea> areas = new ArrayList<>();

    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel(" ");
    private final JLabel summary = new JLabel(" ");
    private final Config config = Config.loadFromResources();

    private final HiArea reqIn = new HiArea(true, () -> tr(
            "Incolla qui una request HTTP grezza\noppure, in Burp: tasto destro su una request → Anonymize",
            "Paste a raw HTTP request here\nor, in Burp: right-click a request → Anonymize"));
    private final HiArea reqOut = new HiArea(false, null);
    private final HiArea respIn = new HiArea(true, () -> tr(
            "Incolla qui la response HTTP grezza (facoltativa)",
            "Paste the raw HTTP response here (optional)"));
    private final HiArea respOut = new HiArea(false, null);
    private final JLabel reqCount = countLabel();
    private final JLabel respCount = countLabel();
    private final JCheckBox chkUa = new JCheckBox();
    private final JComboBox<String> scopeBox = new JComboBox<>();
    private final JComboBox<String> langBox = new JComboBox<>(new String[]{"English", "Italiano"});
    private final JComboBox<String> levelBox = new JComboBox<>();

    private final DefaultTableModel mapModel = new DefaultTableModel(new Object[]{"", "", "", ""}, 0) {
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
    };
    private final JTable mapTable = new JTable(mapModel);
    private final JLabel mapNote = new JLabel();
    private final JTextField mapSearch = new JTextField(18);
    // valori che l'utente ha DESELEZIONATO (da NON anonimizzare): original -> type
    private final Map<String, String> excluded = new LinkedHashMap<>();
    // valori scelti a mano (selezione + Anonimizza) da anonimizzare -> CUSTOM_n
    private final Set<String> forcedValues = new LinkedHashSet<>();
    private boolean rebuilding = false;

    private final HiArea deanonIn = new HiArea(true, () -> tr(
            "Incolla qui la risposta dell'LLM che contiene i segnaposto (HOST_1, EMAIL_2, ...)",
            "Paste the LLM reply containing placeholders (HOST_1, EMAIL_2, ...)"));
    private final HiArea deanonOut = new HiArea(false, null);
    private Map<String, String> lastReverse = Map.of();

    private final JPanel root = new JPanel(new BorderLayout());

    /** Lavoro di anonimizzazione in corso (gira fuori dal thread grafico). */
    private SwingWorker<String[], Void> currentJob;

    public DomiReversiTab() {
        tabs.addTab("", buildAnonTab());
        tabs.addTab("", buildMapTab());
        tabs.addTab("", buildDeanonTab());
        root.add(tabs, BorderLayout.CENTER);
        root.add(buildStatusBar(), BorderLayout.SOUTH);

        langBox.setSelectedIndex(0);
        langBox.addActionListener(e -> { english = langBox.getSelectedIndex() == 0; relabel(); });
        levelBox.addActionListener(e -> {
            if (levelBox.getSelectedIndex() < 0) return;
            String lv = levelBox.getSelectedIndex() == 1 ? Config.LEVEL_STRICT : Config.LEVEL_STANDARD;
            if (lv.equals(config.level)) return;
            config.level = lv;
            if (!reqIn.getText().isBlank() || !respIn.getText().isBlank()) anonymize();
        });

        mapModel.addTableModelListener(e -> {
            if (rebuilding || e.getColumn() != 0 || e.getType() != TableModelEvent.UPDATE) return;
            onCheckboxToggled(e.getFirstRow());
        });
        installForceAnon(reqIn);
        installForceAnon(respIn);
        clearHighlightsOnEdit(reqIn);
        clearHighlightsOnEdit(respIn);
        bindKey(reqIn, "ctrl ENTER", this::anonymize);
        bindKey(respIn, "ctrl ENTER", this::anonymize);
        bindKey(deanonIn, "ctrl ENTER", this::deanonymize);
        relabel();
    }

    public JComponent getComponent() { return root; }

    public void setScope(int scope) { scopeBox.setSelectedIndex(scope); }

    /** Font degli editor di Burp (chiamato dall'entry point, facoltativo). */
    public void setEditorFont(Font font) {
        if (font == null) return;
        editorFont = font;
        for (HiArea a : areas) a.setFont(font);
        mapTable.setRowHeight(Math.max(mapTable.getRowHeight(), mapTable.getFontMetrics(font).getHeight() + 6));
        mapTable.repaint();
    }

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
                tr("Anon.", "Anon."), tr("Originale", "Original"), "Placeholder", tr("Tipo", "Type")});
        sizeMapColumns();
        // testo semplice: Burp disattiva il rendering HTML nelle etichette
        mapNote.setText(tr(
                "Togli la spunta a un valore per tenerlo in chiaro (si ri-anonimizza subito). Non incollare questa tabella nell'LLM.",
                "Uncheck a value to keep it in clear (re-applies instantly). Do not paste this table into the LLM."));
        int lv = levelBox.getSelectedIndex();
        levelBox.setModel(new DefaultComboBoxModel<>(new String[]{
                tr("Standard (ID leggibili)", "Standard (IDs readable)"),
                tr("Rigoroso (anche gli ID)", "Strict (IDs too)")}));
        levelBox.setSelectedIndex(lv < 0 ? (config.strictIds() ? 1 : 0) : lv);
        for (Runnable r : relabelers) r.run();
        for (HiArea a : areas) a.repaint();
        if (!reqIn.getText().isBlank() || !respIn.getText().isBlank()) anonymize();
    }

    // -------------------------------------------------------------------- UI
    private static String norm(String s) {
        return s == null ? "" : s.replace("\r\n", "\n").replace('\r', '\n');
    }

    private static JLabel countLabel() {
        JLabel l = new JLabel();
        l.setFont(l.getFont().deriveFont(Font.PLAIN));
        l.setEnabled(false); // colore attenuato del tema
        return l;
    }

    private JButton button(String it, String en, Runnable action) {
        JButton b = new JButton(tr(it, en));
        relabelers.add(() -> b.setText(tr(it, en)));
        b.addActionListener(e -> action.run());
        return b;
    }

    private JButton smallButton(String it, String en, Runnable action) {
        JButton b = button(it, en, action);
        b.setMargin(new Insets(1, 8, 1, 8));
        b.setFocusable(false);
        return b;
    }

    private JLabel label(String it, String en) {
        JLabel l = new JLabel(tr(it, en));
        relabelers.add(() -> l.setText(tr(it, en)));
        return l;
    }

    private void tooltip(JComponent c, String it, String en) {
        relabelers.add(() -> c.setToolTipText(tr(it, en)));
    }

    /** Pannello editor con intestazione: titolo, contatore e azioni a destra. */
    private JComponent pane(String it, String en, HiArea area, JLabel count, JComponent... actions) {
        JLabel title = new JLabel();
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        relabelers.add(() -> title.setText(tr(it, en)));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        left.setOpaque(false);
        left.add(title);
        if (count != null) left.add(count);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        right.setOpaque(false);
        for (JComponent a : actions) right.add(a);

        JPanel head = new JPanel(new BorderLayout());
        head.setBorder(BorderFactory.createEmptyBorder(4, 2, 4, 4));
        head.add(left, BorderLayout.WEST);
        head.add(right, BorderLayout.EAST);

        JPanel p = new JPanel(new BorderLayout());
        p.add(head, BorderLayout.NORTH);
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildAnonTab() {
        JComponent reqInP = pane("Request — originale", "Request — original", reqIn, null);
        JComponent reqOutP = pane("Request — anonimizzata", "Request — anonymized", reqOut, reqCount,
                smallButton("Copia", "Copy", () -> copy(reqOut)));
        JComponent respInP = pane("Response — originale", "Response — original", respIn, null);
        JComponent respOutP = pane("Response — anonimizzata", "Response — anonymized", respOut, respCount,
                smallButton("Copia", "Copy", () -> copy(respOut)));

        JSplitPane reqSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqInP, reqOutP);
        JSplitPane respSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, respInP, respOutP);
        for (JSplitPane s : List.of(reqSplit, respSplit)) {
            s.setResizeWeight(0.5);
            s.setContinuousLayout(true);
            s.setBorder(null);
        }
        JSplitPane io = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqSplit, respSplit);
        io.setResizeWeight(0.5);
        io.setContinuousLayout(true);
        io.setBorder(null);

        JButton anon = button("🔒 Anonimizza", "🔒 Anonymize", this::anonymize);
        anon.setFont(anon.getFont().deriveFont(Font.BOLD));
        tooltip(anon, "Anonimizza request e response (Ctrl+Invio)", "Anonymize request and response (Ctrl+Enter)");
        JButton clear = button("Pulisci", "Clear", this::clear);
        tooltip(chkUa, "Sostituisce anche lo User-Agent con un segnaposto",
                "Also replace the User-Agent with a placeholder");

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        left.add(anon);
        left.add(Box.createHorizontalStrut(6));
        left.add(label("Ambito:", "Scope:"));
        left.add(scopeBox);
        left.add(Box.createHorizontalStrut(6));
        left.add(label("Livello:", "Level:"));
        left.add(levelBox);
        tooltip(levelBox,
                "Standard: id, *_id, *_ref, hash e header di tracing restano leggibili per il debug. Rigoroso: diventano ID_n.",
                "Standard: id, *_id, *_ref, hashes and tracing headers stay readable for debugging. Strict: they become ID_n.");
        left.add(Box.createHorizontalStrut(6));
        left.add(chkUa);
        left.add(clear);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        right.add(legend(false, "dato nascosto", "hidden value"));
        right.add(legend(true, "segnaposto", "placeholder"));
        right.add(Box.createHorizontalStrut(4));
        right.add(new JLabel("Language:"));
        right.add(langBox);

        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createEmptyBorder(6, 2, 6, 4));
        bar.add(left, BorderLayout.WEST);
        bar.add(right, BorderLayout.EAST);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(bar, BorderLayout.NORTH);
        panel.add(io, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildMapTab() {
        mapTable.setFillsViewportHeight(true);
        mapTable.setShowVerticalLines(false);
        mapTable.setIntercellSpacing(new Dimension(0, 1));
        mapTable.setRowHeight(Math.max(mapTable.getRowHeight(), 22));
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(mapModel);
        mapTable.setRowSorter(sorter);

        DefaultTableCellRenderer cells = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, focus, row, col);
                int mr = t.convertRowIndexToModel(row);
                boolean kept = !Boolean.TRUE.equals(mapModel.getValueAt(mr, 0));
                int mc = t.convertColumnIndexToModel(col);
                setFont(mc == 1 || mc == 2 ? editorFont : t.getFont());
                if (kept) setFont(getFont().deriveFont(Font.ITALIC));
                if (!sel) setForeground(kept ? UIManager.getColor("Label.disabledForeground") : t.getForeground());
                setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 6));
                setToolTipText(mc == 1 && v != null && v.toString().length() > 60 ? abbrev(v.toString(), 300) : null);
                return this;
            }
        };
        mapTable.setDefaultRenderer(String.class, cells);

        mapSearch.getDocument().addDocumentListener(new DocumentListener() {
            private void apply() {
                String q = mapSearch.getText().trim();
                sorter.setRowFilter(q.isEmpty() ? null
                        : RowFilter.regexFilter("(?i)" + Pattern.quote(q), 1, 2, 3));
            }
            @Override public void insertUpdate(DocumentEvent e) { apply(); }
            @Override public void removeUpdate(DocumentEvent e) { apply(); }
            @Override public void changedUpdate(DocumentEvent e) { apply(); }
        });
        tooltip(mapSearch, "Filtra per valore, segnaposto o tipo", "Filter by value, placeholder or type");

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.add(label("Cerca:", "Search:"));
        right.add(mapSearch);
        JButton reset = button("Riattiva tutti", "Re-enable all", () -> {
            if (excluded.isEmpty()) return;
            excluded.clear();
            anonymize();
        });
        tooltip(reset, "Anonimizza di nuovo tutti i valori tenuti in chiaro", "Anonymize again every value kept in clear");
        right.add(reset);

        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 4));
        top.add(mapNote, BorderLayout.CENTER);
        top.add(right, BorderLayout.EAST);

        JScrollPane sp = new JScrollPane(mapTable);
        sp.setBorder(BorderFactory.createEmptyBorder());
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(top, BorderLayout.NORTH);
        panel.add(sp, BorderLayout.CENTER);
        return panel;
    }

    private void sizeMapColumns() {
        if (mapTable.getColumnModel().getColumnCount() < 4) return;
        int[][] w = {{60, 60, 70}, {420, 120, Integer.MAX_VALUE}, {170, 110, 260}, {120, 80, 180}};
        for (int i = 0; i < 4; i++) {
            var col = mapTable.getColumnModel().getColumn(i);
            col.setPreferredWidth(w[i][0]);
            col.setMinWidth(w[i][1]);
            col.setMaxWidth(w[i][2]);
        }
    }

    private JComponent buildDeanonTab() {
        JComponent inP = pane("Risposta dell'LLM (con segnaposto)", "LLM reply (with placeholders)", deanonIn, null);
        JComponent outP = pane("Testo con i valori reali", "Text with real values", deanonOut, null,
                smallButton("Copia", "Copy", () -> copy(deanonOut)));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, inP, outP);
        split.setResizeWeight(0.5);
        split.setContinuousLayout(true);
        split.setBorder(null);

        JButton go = button("🔓 De-anonimizza", "🔓 De-anonymize", this::deanonymize);
        go.setFont(go.getFont().deriveFont(Font.BOLD));
        tooltip(go, "Sostituisce i segnaposto con i valori reali (Ctrl+Invio)",
                "Replace placeholders with the real values (Ctrl+Enter)");
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        bar.setBorder(BorderFactory.createEmptyBorder(6, 2, 6, 4));
        bar.add(go);
        bar.add(label("Usa la mappa dell'ultima anonimizzazione.", "Uses the map of the last anonymization."));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(bar, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildStatusBar() {
        JPanel p = new JPanel(new BorderLayout(12, 0));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIManager.getColor("Separator.foreground") != null
                        ? UIManager.getColor("Separator.foreground") : Color.GRAY),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        summary.setEnabled(false);
        p.add(status, BorderLayout.CENTER);
        p.add(summary, BorderLayout.EAST);
        return p;
    }

    // -------------------------------------------------------------- colori
    private static boolean isDark(Component c) {
        Color b = c != null ? c.getBackground() : null;
        if (b == null) b = UIManager.getColor("TextArea.background");
        if (b == null) return false;
        double l = (0.299 * b.getRed() + 0.587 * b.getGreen() + 0.114 * b.getBlue()) / 255.0;
        return l < 0.5;
    }

    private static Color placeholderColor(Component c) {
        return isDark(c) ? new Color(76, 175, 80, 95) : new Color(129, 199, 132, 120);
    }

    private static Color originalColor(Component c) {
        return isDark(c) ? new Color(239, 83, 80, 95) : new Color(229, 115, 115, 105);
    }

    /** Etichetta di legenda con un quadratino del colore di evidenziazione. */
    private JLabel legend(boolean placeholder, String it, String en) {
        JLabel l = label(it, en);
        l.setIcon(new Icon() {
            @Override public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(placeholder ? placeholderColor(reqOut) : originalColor(reqIn));
                g2.fillRoundRect(x, y + 1, 12, 12, 4, 4);
                g2.dispose();
            }
            @Override public int getIconWidth() { return 12; }
            @Override public int getIconHeight() { return 14; }
        });
        return l;
    }

    // -------------------------------------------------------- evidenziazione
    /**
     * Evidenzia nel testo tutte le occorrenze dei valori indicati.
     * placeholder = true: segnaposto (parole intere); false: valori originali.
     * Ritorna quante occorrenze sono state evidenziate.
     */
    private static int highlight(JTextArea a, Collection<String> values, boolean placeholder) {
        Highlighter h = a.getHighlighter();
        h.removeAllHighlights();
        if (values == null || values.isEmpty() || a.getDocument().getLength() == 0) return 0;
        List<String> list = values.stream()
                .filter(Objects::nonNull)
                .map(DomiReversiTab::norm)
                .filter(s -> s.trim().length() >= (placeholder ? 1 : 3))
                .distinct()
                .sorted((x, y) -> Integer.compare(y.length(), x.length()))
                .limit(3000)
                .collect(Collectors.toList());
        if (list.isEmpty()) return 0;
        String alt = list.stream().map(Pattern::quote).collect(Collectors.joining("|"));
        Pattern p = placeholder
                ? Pattern.compile("(?<![\\w])(?:" + alt + ")(?![\\w])")
                : Pattern.compile(alt, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(
                placeholder ? placeholderColor(a) : originalColor(a));
        Matcher m = p.matcher(a.getText());
        int n = 0;
        while (m.find() && n < 20000) {
            if (m.end() == m.start()) continue;
            try { h.addHighlight(m.start(), m.end(), painter); } catch (BadLocationException ignored) { }
            n++;
        }
        return n;
    }

    private void clearHighlightsOnEdit(HiArea a) {
        a.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { a.getHighlighter().removeAllHighlights(); }
            @Override public void removeUpdate(DocumentEvent e) { a.getHighlighter().removeAllHighlights(); }
            @Override public void changedUpdate(DocumentEvent e) { }
        });
    }

    private void applyHighlights(SubstitutionMap map) {
        Map<String, String> tips = new LinkedHashMap<>(map.reverseMap());
        Set<String> placeholders = new LinkedHashSet<>();
        List<String> originals = new ArrayList<>();
        for (SubstitutionMap.Entry e : map.entries()) {
            placeholders.add(e.placeholder);
            originals.add(e.original);
            tips.putIfAbsent(e.placeholder, tr("(valore nascosto, non reversibile)", "(hidden value, not reversible)"));
        }
        reqOut.tips = tips;
        respOut.tips = tips;
        deanonIn.tips = tips;
        int rq = highlight(reqOut, placeholders, true);
        int rs = highlight(respOut, placeholders, true);
        highlight(reqIn, originals, false);
        highlight(respIn, originals, false);
        reqCount.setText(reqOut.getText().isEmpty() ? "" : rq + tr(" sostituzioni", " replacements"));
        respCount.setText(respOut.getText().isEmpty() ? "" : rs + tr(" sostituzioni", " replacements"));
    }

    private void updateSummary(SubstitutionMap map) {
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (SubstitutionMap.Entry e : map.entries()) byType.merge(e.type, 1, Integer::sum);
        String s = byType.entrySet().stream()
                .sorted((x, y) -> y.getValue() - x.getValue())
                .limit(8)
                .map(e -> e.getKey() + " " + e.getValue())
                .collect(Collectors.joining("  ·  "));
        summary.setText(s.isEmpty() ? " " : s);
    }

    // ---------------------------------------------------------------- azioni
    private void bindKey(JComponent c, String key, Runnable action) {
        c.getInputMap().put(KeyStroke.getKeyStroke(key), key);
        c.getActionMap().put(key, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { action.run(); }
        });
    }

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
        bindKey(area, "ctrl shift A", () -> anonymizeSelection(area));
    }

    private void anonymizeSelection(JTextArea area) {
        String sel = area.getSelectedText();
        if (sel == null || sel.trim().isEmpty()) {
            status.setText(tr("Nessuna selezione da anonimizzare.", "No selection to anonymize."));
            return;
        }
        forcedValues.add(sel);
        excluded.remove(sel);
        anonymize();
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
            if (req.isBlank() && resp.isBlank()) {
                status.setText(tr("Niente da anonimizzare: incolla una request o una response.",
                        "Nothing to anonymize: paste a request or a response."));
                return;
            }
            status.setText(tr("Anonimizzazione in corso…", "Anonymizing…"));

            if (currentJob != null) currentJob.cancel(true);
            SwingWorker<String[], Void> job = new SwingWorker<>() {
                @Override
                protected String[] doInBackground() {
                    eng.reserveLiterals(req, resp); // request + response = una sessione
                    return new String[]{
                            req.isBlank() ? "" : eng.anonymizeRequest(req),
                            resp.isBlank() ? "" : eng.anonymizeResponse(resp)};
                }

                @Override
                protected void done() {
                    if (isCancelled() || this != currentJob) return;
                    try {
                        String[] r = get();
                        reqOut.setText(r[0]);
                        respOut.setText(r[1]);
                        reqOut.setCaretPosition(0);
                        respOut.setCaretPosition(0);
                        rebuildMap(map);
                        lastReverse = map.reverseMap();
                        applyHighlights(map);
                        updateSummary(map);
                        status.setText(tr("Fatto: ", "Done: ") + map.size()
                                + tr(" valori sostituiti", " values replaced")
                                + (excluded.isEmpty() ? "" : ", " + excluded.size() + tr(" tenuti in chiaro", " kept in clear"))
                                + tr(". Rivedi l'output prima di condividerlo.", ". Review the output before sharing it."));
                    } catch (Exception ex) {
                        Throwable c = ex.getCause() != null ? ex.getCause() : ex;
                        status.setText(tr("Errore: ", "Error: ") + c.getMessage());
                    }
                }
            };
            currentJob = job;
            job.execute();
        } catch (Exception ex) {
            status.setText(tr("Errore: ", "Error: ") + ex.getMessage());
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
        tabs.setTitleAt(1, tr("Mappa sostituzioni", "Substitution map") + " (" + map.size() + ")");
    }

    private void deanonymize() {
        if (lastReverse.isEmpty()) {
            status.setText(tr("Nessuna mappa: anonimizza prima un messaggio.", "No map yet: anonymize a message first."));
            return;
        }
        String in = deanonIn.getText();
        String out = Anonymizer.deanonymize(in, lastReverse);
        deanonOut.setText(out);
        deanonOut.setCaretPosition(0);
        int n = highlight(deanonIn, lastReverse.keySet(), true);
        highlight(deanonOut, lastReverse.values(), false);
        status.setText(n == 0
                ? tr("Nessun segnaposto riconosciuto nel testo.", "No known placeholder found in the text.")
                : tr("De-anonimizzazione completata: ", "De-anonymization done: ") + n
                        + tr(" segnaposto sostituiti.", " placeholders replaced."));
    }

    private void clear() {
        if (currentJob != null) {
            currentJob.cancel(true);
            currentJob = null;
        }
        for (JTextArea a : List.of(reqIn, reqOut, respIn, respOut, deanonIn, deanonOut)) {
            a.setText("");
            a.getHighlighter().removeAllHighlights();
        }
        excluded.clear();
        forcedValues.clear();
        rebuilding = true;
        mapModel.setRowCount(0);
        rebuilding = false;
        lastReverse = Map.of();
        reqCount.setText("");
        respCount.setText("");
        summary.setText(" ");
        tabs.setTitleAt(1, tr("Mappa sostituzioni", "Substitution map"));
        status.setText(tr("Pulito.", "Cleared."));
    }

    private void copy(JTextArea a) {
        String t = a.getText();
        if (t == null || t.isEmpty()) { status.setText(tr("Niente da copiare.", "Nothing to copy.")); return; }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(t), null);
        status.setText(tr("Copiato negli appunti.", "Copied to clipboard."));
    }

    private static String abbrev(String s, int max) {
        String one = s.replace("\r", "").replace("\n", "⏎");
        return one.length() > max ? one.substring(0, max) + "…" : one;
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ---------------------------------------------------------- editor
    /** Area di testo con testo guida quando vuota e tooltip sui segnaposto. */
    private final class HiArea extends JTextArea {
        private final Supplier<String> hint;
        Map<String, String> tips = Map.of();

        HiArea(boolean editable, Supplier<String> hint) {
            this.hint = hint;
            setEditable(editable);
            setFont(editorFont);
            setLineWrap(true);           // evita il glitch delle righe lunghissime
            setWrapStyleWord(true);
            setTabSize(4);
            setMargin(new Insets(6, 8, 6, 8));
            ToolTipManager.sharedInstance().registerComponent(this);
            areas.add(this);
        }

        @Override
        public String getToolTipText(MouseEvent e) {
            if (tips.isEmpty()) return null;
            int pos = viewToModel2D(e.getPoint());
            String t = getText();
            if (pos < 0 || pos >= t.length()) return null;
            int s = pos, en = pos;
            while (s > 0 && isWordChar(t.charAt(s - 1))) s--;
            while (en < t.length() && isWordChar(t.charAt(en))) en++;
            if (en <= s) return null;
            String w = t.substring(s, en);
            String o = tips.get(w);
            if (o == null) return null;
            return w + "  ←  " + abbrev(o, 160); // testo semplice (niente HTML in Burp)
        }

        private boolean isWordChar(char c) {
            return Character.isLetterOrDigit(c) || c == '_';
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (hint == null || getDocument().getLength() > 0) return;
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            Color c = UIManager.getColor("Label.disabledForeground");
            g2.setColor(c != null ? c : Color.GRAY);
            g2.setFont(getFont().deriveFont(Font.ITALIC));
            Insets in = getInsets();
            FontMetrics fm = g2.getFontMetrics();
            int y = in.top + fm.getAscent();
            for (String line : hint.get().split("\n")) {
                g2.drawString(line, in.left, y);
                y += fm.getHeight();
            }
            g2.dispose();
        }
    }
}
