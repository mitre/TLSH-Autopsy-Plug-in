/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
/*
 * NOTICE
 * 
 * This software (or technical data) was produced for the U. S. Government and
 * is subject to the Rights in Data-General Clause 52.227-14,
 * Alt. IV (May 2014) – Alternative IV (Dec 2007)
 *
 * © 2023 The MITRE Corporation.
 */
package org.mitre.tlshmodule;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.swing.DefaultComboBoxModel;
import javax.swing.Timer;
import javax.swing.table.DefaultTableModel;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 * GUI class with the logic for setting for the current ingest. All files being processed by
 * the current ingest will follow these settings when processing.
 */
public class TlshIngestModuleIngestJobSettingsPanel extends IngestModuleIngestJobSettingsPanel
        implements ActionListener, ItemListener {

    private ArrayList<String> savedSettings = new ArrayList<>();
    private ArrayList<String> savedMimeTypes = new ArrayList<String>() {
        {
            add("*/*");
            add("application/*");
            add("application/octet-stream");
            add("application/msword");
            add("application/gzip");
            add("application/json");
            add("application/pdf");
            add("application/zip");
            add("application/x-7z-compressed");
            add("application/vnd.rar");
            add("image/*");
            add("image/jpeg");
            add("image/png");
            add("text/*");
            add("text/plain");
            add("video/*");
            add("video/mp4");
            add("video/mpeg");
        }
    };
    private String savedMimeSelected = "*/*";

    // Set up the timer variables
    private int timerDelay = 1000; // milliseconds
    Timer timer = new Timer(timerDelay, this);

    /**
     * Creates the TlshIngestModuleIngestJobSettingsPanel form instance
     */
    public TlshIngestModuleIngestJobSettingsPanel(TlshModuleIngestJobSettings settings) {
        initComponents();
        customizeComponents(settings);

        timer.start();
    }

    /**
     * Gets all of the settings inputted by the user to be used by Autopsy during ingest.
     * 
     * @return The settings selected by the user to be used during ingest. 
     */
    @Override
    public IngestModuleIngestJobSettings getSettings() {
        // Stop the timer because the settings page will be closed
        timer.stop();

        // Loop through table of hash sets to see which hash sets are enabled. More hashsets
        // could have been imported or removed during the time the window is open. This is why
        // it needs to be checked frequently.
        DefaultTableModel tableModel = (DefaultTableModel) this.knownHashTable.getModel();
        List<String> enabledHashSets = new ArrayList<String>();

        for (int i = 0; i < tableModel.getRowCount(); i++) {
            // Check if the value is enabled
            if (Boolean.valueOf(this.knownHashTable.getValueAt(i, 0).toString())) {
                enabledHashSets.add(this.knownHashTable.getValueAt(i, 1).toString());
            }
        }

        // Get the hashes from the TLSH Quick Search Text Area if there are any 
        String[] inputedHashes = ParseTlshObj.ParseHashLinesWithComments(this.hashTextArea.getText());

        this.savedMimeSelected = (String) this.mimeFileTypeComboBox.getSelectedItem();

        // enabledHashSets.toArray(new String[0]) is needed to convert the enabledHashSets to String[] reasoning here:
        // https://stackoverflow.com/questions/4042434/converting-arrayliststring-to-string-in-java
        String[] convertedArray = enabledHashSets.toArray(new String[0]);
        
        return new TlshModuleIngestJobSettings(inputedHashes.length != 0, inputedHashes,
                (Integer) this.thresholdDistanceSpinner.getValue(), this.compareLengthCheckbox.isSelected(),
                convertedArray, this.mimeFileTypeComboBox.getSelectedItem().toString(), UUID.randomUUID().toString());
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        thresholdDistanceLabel = new javax.swing.JLabel();
        thresholdDistanceSpinner = new javax.swing.JSpinner();
        compareLengthCheckbox = new javax.swing.JCheckBox();
        knownHashSetsLabel = new javax.swing.JLabel();
        hashLabel = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        hashTextArea = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        knownHashTable = new javax.swing.JTable();
        mimeDescLabel = new javax.swing.JLabel();
        mimeFileTypeComboBox = new javax.swing.JComboBox<>();

        org.openide.awt.Mnemonics.setLocalizedText(thresholdDistanceLabel, org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.thresholdDistanceLabel.text")); // NOI18N
        thresholdDistanceLabel.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.thresholdDistanceLabel.toolTipText")); // NOI18N

        thresholdDistanceSpinner.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        org.openide.awt.Mnemonics.setLocalizedText(compareLengthCheckbox, org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.compareLengthCheckbox.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(knownHashSetsLabel, org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.knownHashSetsLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(hashLabel, org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.hashLabel.text")); // NOI18N
        hashLabel.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.hashLabel.toolTipText")); // NOI18N

        hashTextArea.setColumns(20);
        hashTextArea.setRows(5);
        jScrollPane2.setViewportView(hashTextArea);

        knownHashTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Enabled", "Hash Set"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Boolean.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                true, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPane3.setViewportView(knownHashTable);
        if (knownHashTable.getColumnModel().getColumnCount() > 0) {
            knownHashTable.getColumnModel().getColumn(0).setHeaderValue(org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.knownHashTable.columnModel.title0")); // NOI18N
            knownHashTable.getColumnModel().getColumn(1).setHeaderValue(org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.knownHashTable.columnModel.title1")); // NOI18N
        }

        org.openide.awt.Mnemonics.setLocalizedText(mimeDescLabel, org.openide.util.NbBundle.getMessage(TlshIngestModuleIngestJobSettingsPanel.class, "TlshIngestModuleIngestJobSettingsPanel.mimeDescLabel.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(thresholdDistanceSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, 116, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(thresholdDistanceLabel)
                            .addComponent(knownHashSetsLabel)
                            .addComponent(mimeDescLabel)
                            .addComponent(compareLengthCheckbox)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 280, Short.MAX_VALUE)
                            .addComponent(mimeFileTypeComboBox, 0, 0, Short.MAX_VALUE))
                        .addComponent(hashLabel)))
                .addGap(0, 20, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(thresholdDistanceLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(thresholdDistanceSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(compareLengthCheckbox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(mimeDescLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(mimeFileTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(knownHashSetsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hashLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    /**
     * For the generation of the tables with digests
     * 
     * @param ev Required action event for the function to trigger
     */
    public void actionPerformed(ActionEvent ev) {
        if (this.newElementsToRender()) {
            this.RenderTable();
        }
    }

    /**
     * Allows for Autopsy to save the state of the GUI so the user doesn't have to input
     * their settings again.
     * 
     * @param ie Event used for the state tracking
     */
    public void itemStateChanged(ItemEvent ie) {
        if (ie.getStateChange() == ItemEvent.SELECTED) {
            String searchText = (String) this.mimeFileTypeComboBox.getSelectedItem();

            DefaultComboBoxModel<String> comboModel
                    = (DefaultComboBoxModel<String>) this.mimeFileTypeComboBox.getModel();

            if (!searchText.isEmpty() && comboModel.getIndexOf(searchText) == -1) {
                comboModel.addElement(searchText);
                this.savedMimeTypes.add(searchText);
            }

        }
    }

    /**
     * Allows for customization of the ingest job settings panel GUI.
     * 
     * @param settings The settings value that gets passed by Autopsy.
     */
    private void customizeComponents(TlshModuleIngestJobSettings settings) {
        this.knownHashTable.getColumnModel().getColumn(0).setMaxWidth(100);
        this.compareLengthCheckbox.setSelected(settings.getCompareLength());
        this.thresholdDistanceSpinner.setValue(settings.getTargetDistance());

        // Sets combo boxes with either the default values of enabled or the last settings
        // used by the user.
        DefaultComboBoxModel<String> comboModel
                = (DefaultComboBoxModel<String>) this.mimeFileTypeComboBox.getModel();
        comboModel.removeAllElements();
        for (String mimeType : this.savedMimeTypes) {
            comboModel.addElement(mimeType);
        }
        comboModel.setSelectedItem(settings.getCompareMimeType());

        this.mimeFileTypeComboBox.setEditable(true);
        this.mimeFileTypeComboBox.addItemListener(this);

        RenderTable();
    }

    /**
     * Render the table with all of the global settings
     *
     * @return The number of settings that were rendered
     */
    private int RenderTable() {
        DefaultTableModel tableModel = (DefaultTableModel) this.knownHashTable.getModel();
        tableModel.setRowCount(0);
        Map<String, String> moduleSettings = ModuleSettings.getConfigSettings(TlshIngestModuleFactory.getModuleName());

        this.savedSettings.clear();
        int idx = 0;
        for (Map.Entry<String, String> entry : moduleSettings.entrySet()) {
            tableModel.addRow(new Object[0]);
            tableModel.setValueAt(false, idx, 0);
            tableModel.setValueAt(entry.getKey(), idx, 1);

            this.savedSettings.add(entry.getKey());
            idx++;
        }

        return moduleSettings.size();
    }

    /**
     * Checks if there was a change in elements in the table
     *
     * @return true if there are more elements that need to be rendered, false if there was no change
     */
    private boolean newElementsToRender() {
        Map<String, String> moduleSettings = ModuleSettings.getConfigSettings(TlshIngestModuleFactory.getModuleName());

        if (moduleSettings.size() != this.savedSettings.size()) {
            return true;
        }

        for (Map.Entry<String, String> entry : moduleSettings.entrySet()) {
            if (!this.savedSettings.contains(entry.getKey())) {
                return true;
            }
        }

        return false;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox compareLengthCheckbox;
    private javax.swing.JLabel hashLabel;
    private javax.swing.JTextArea hashTextArea;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JLabel knownHashSetsLabel;
    private javax.swing.JTable knownHashTable;
    private javax.swing.JLabel mimeDescLabel;
    private javax.swing.JComboBox<String> mimeFileTypeComboBox;
    private javax.swing.JLabel thresholdDistanceLabel;
    private javax.swing.JSpinner thresholdDistanceSpinner;
    // End of variables declaration//GEN-END:variables
}