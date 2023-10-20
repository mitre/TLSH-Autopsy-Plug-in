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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;

/**
 * Global settings panel for adding hash list digests that can be used to compare against the files being ingested. When
 * a hash matches one of these, the comparison will include the name and the hash.
 *
 * There are two ModuleSettings that end up getting saved: MODULE_NAME - "TLSHIngestModule" This is where all the of
 * hashes get saved to.
 *
 * MODULE_NAME_FILES - "TLSHIngestModuleFiles" This is where all of the files for the refresh hash list are saved.
 */
public class TlshIngestModuleGlobalSettingsPanel extends IngestModuleGlobalSettingsPanel {

    private final String MODULE_NAME = TlshIngestModuleFactory.getModuleName();
    private final String MODULE_NAME_FILES = TlshIngestModuleFactory.getModuleName() + "Files";

    private static final Logger logger = Logger.getLogger(TlshIngestModuleGlobalSettingsPanel.class.getName());

    private final CreateTlshHashSetDialog createHashSetDialog;
    private CreateTlshHashSetDialog editHashSetDialog;

    // For adding and removing rows from the table
    DefaultTableModel tableModel = new DefaultTableModel();

    /**
     * Creates the TlshIngestModuleGlobalSettingsPanel instance.
     */
    public TlshIngestModuleGlobalSettingsPanel() {
        initComponents();
        // Sets a single columm in the tableModel and adds the rows
        tableModel.addColumn("Available Hash Sets");

        // Create the config file if it does not exist already
        if (!ModuleSettings.configExists(MODULE_NAME)) {
            ModuleSettings.makeConfigFile(MODULE_NAME);
        }

        if (!ModuleSettings.configExists(MODULE_NAME_FILES)) {
            ModuleSettings.makeConfigFile(MODULE_NAME_FILES);
        }

        // Update the table once something is added to it.
        TableRerender();

        // Sets the Dialog for creating and editing a hash set
        createHashSetDialog = new CreateTlshHashSetDialog((JFrame) WindowManager.getDefault().getMainWindow(),
                true, true, "");
    }

    public void saveSettings() {
    }

    private void TableRerender() {
        tableModel.setRowCount(0); // Sets the rows in the table to be zero before populating it
        Map<String, String> settings = ModuleSettings.getConfigSettings(TlshIngestModuleFactory.getModuleName());
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            tableModel.addRow(new Object[]{entry.getKey()});
        }
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        hashSetLabel = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        hashSetTable = new javax.swing.JTable();
        createHashSetButton = new javax.swing.JButton();
        exportHashSetButton = new javax.swing.JButton();
        deleteHashSetButton = new javax.swing.JButton();
        editHashSetButton = new javax.swing.JButton();
        importHashSetButton = new javax.swing.JButton();
        refreshFilesButton = new javax.swing.JButton();
        refreshSelectedButton = new javax.swing.JButton();

        org.openide.awt.Mnemonics.setLocalizedText(hashSetLabel, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.hashSetLabel.text")); // NOI18N

        hashSetTable.setModel(tableModel);
        jScrollPane1.setViewportView(hashSetTable);

        org.openide.awt.Mnemonics.setLocalizedText(createHashSetButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.createHashSetButton.text")); // NOI18N
        createHashSetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createHashSetButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(exportHashSetButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.exportHashSetButton.text")); // NOI18N
        exportHashSetButton.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.exportHashSetButton.toolTipText")); // NOI18N
        exportHashSetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportHashSetButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(deleteHashSetButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.deleteHashSetButton.text")); // NOI18N
        deleteHashSetButton.setMaximumSize(new java.awt.Dimension(125, 23));
        deleteHashSetButton.setMinimumSize(new java.awt.Dimension(125, 23));
        deleteHashSetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteHashSetButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(editHashSetButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.editHashSetButton.text")); // NOI18N
        editHashSetButton.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.editHashSetButton.toolTipText")); // NOI18N
        editHashSetButton.setMaximumSize(new java.awt.Dimension(125, 23));
        editHashSetButton.setMinimumSize(new java.awt.Dimension(125, 23));
        editHashSetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editHashSetButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(importHashSetButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.importHashSetButton.text")); // NOI18N
        importHashSetButton.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.importHashSetButton.toolTipText")); // NOI18N
        importHashSetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                importHashSetButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(refreshFilesButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.refreshFilesButton.text")); // NOI18N
        refreshFilesButton.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.refreshFilesButton.toolTipText")); // NOI18N
        refreshFilesButton.setActionCommand(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.refreshFilesButton.actionCommand")); // NOI18N
        refreshFilesButton.setMaximumSize(new java.awt.Dimension(125, 23));
        refreshFilesButton.setMinimumSize(new java.awt.Dimension(125, 23));
        refreshFilesButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshFilesButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(refreshSelectedButton, org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.refreshSelectedButton.text")); // NOI18N
        refreshSelectedButton.setToolTipText(org.openide.util.NbBundle.getMessage(TlshIngestModuleGlobalSettingsPanel.class, "TlshIngestModuleGlobalSettingsPanel.refreshSelectedButton.toolTipText")); // NOI18N
        refreshSelectedButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                refreshSelectedButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(hashSetLabel)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(refreshFilesButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(createHashSetButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(importHashSetButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(deleteHashSetButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(exportHashSetButton, javax.swing.GroupLayout.DEFAULT_SIZE, 143, Short.MAX_VALUE))
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(editHashSetButton, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(refreshSelectedButton, javax.swing.GroupLayout.PREFERRED_SIZE, 232, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(hashSetLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 380, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(createHashSetButton)
                    .addComponent(deleteHashSetButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(editHashSetButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(exportHashSetButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(importHashSetButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(refreshFilesButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(refreshSelectedButton))
                .addContainerGap(13, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void createHashSetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createHashSetButtonActionPerformed
        createHashSetDialog.isAlwaysOnTop();
        createHashSetDialog.setVisible(true);

        // Wait until the user is done adding values to the table
        while (createHashSetDialog.isVisible()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }

        TableRerender();
    }//GEN-LAST:event_createHashSetButtonActionPerformed

    private void deleteHashSetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteHashSetButtonActionPerformed
        int[] rows = hashSetTable.getSelectedRows();

        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "No rows selected.", "Delete Hash Lists", JOptionPane.WARNING_MESSAGE);
            return;
        }

        for (int row : rows) {
            String rowVal = (String) hashSetTable.getValueAt(row, 0);
            ModuleSettings.removeProperty(MODULE_NAME, rowVal);
            ModuleSettings.removeProperty(MODULE_NAME_FILES, rowVal);
        }

        TableRerender();
    }//GEN-LAST:event_deleteHashSetButtonActionPerformed

    private void editHashSetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editHashSetButtonActionPerformed
        int selectedRow = hashSetTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }

        String rowVal = (String) hashSetTable.getValueAt(selectedRow, 0);
        this.editHashSetDialog = new CreateTlshHashSetDialog((JFrame) WindowManager.getDefault().getMainWindow(),
                true, false, rowVal);

        this.editHashSetDialog.isAlwaysOnTop();
        this.editHashSetDialog.setVisible(true);

        // Wait until the user is done adding values to the table
        while (createHashSetDialog.isVisible()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }
    }//GEN-LAST:event_editHashSetButtonActionPerformed

    private void exportHashSetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportHashSetButtonActionPerformed
        int[] rows = hashSetTable.getSelectedRows();

        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "No rows selected.", "Export Hash Lists", JOptionPane.WARNING_MESSAGE);
            return;
        }

        final JFileChooser fc = new JFileChooser();
        fc.setMultiSelectionEnabled(false);
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int retVal = fc.showOpenDialog(TlshIngestModuleGlobalSettingsPanel.this);

        if (retVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            String dirPath = file.getAbsolutePath();

            for (int row : rows) {
                String rowVal = (String) hashSetTable.getValueAt(row, 0);
                String data = ModuleSettings.getConfigSetting(MODULE_NAME, rowVal);

                try {
                    FileWriter out;
                    if (rowVal.endsWith(".txt")) {
                        out = new FileWriter(dirPath + "/" + rowVal);
                    } else {
                        out = new FileWriter(dirPath + "/" + rowVal + ".txt");
                    }

                    out.write(data);
                    out.close();
                } catch (FileNotFoundException ex) {
                    logger.log(Level.INFO, "Could not write file to path {0}", dirPath + "/" + rowVal);
                } catch (IOException ex) {
                    logger.log(Level.INFO, "IOException occurred during file writing {0}", dirPath + "/" + rowVal);
                }
            }

        }

    }//GEN-LAST:event_exportHashSetButtonActionPerformed

    private void importHashSetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_importHashSetButtonActionPerformed
        final JFileChooser fc = new JFileChooser();
        fc.setMultiSelectionEnabled(true);
        fc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fc.setFileFilter(new FileNameExtensionFilter("Hash List Text Files", "txt"));

        int retVal = fc.showOpenDialog(TlshIngestModuleGlobalSettingsPanel.this);

        if (retVal == JFileChooser.APPROVE_OPTION) {
            File[] files = getAllFilesAndSubFiles(fc.getSelectedFiles());

            for (File file : files) {
                String settingValue = readTextFromFile(file);

                // Set the setting from hash file being imported
                if (!settingValue.equals("")) {
                    if (!ModuleSettings.settingExists(MODULE_NAME, file.getName())) {
                        ModuleSettings.setConfigSetting(MODULE_NAME, file.getName(), settingValue);
                        ModuleSettings.setConfigSetting(MODULE_NAME_FILES, file.getName(), file.getAbsolutePath());
                    } else {
                        JOptionPane.showMessageDialog(this,
                                "File was not imported because hashset with that name already exists: " + file.getName(),
                                "Import Hash Lists", JOptionPane.WARNING_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this,
                            "This file was empty: " + file.getName());
                }
            }

            TableRerender();
        }
    }//GEN-LAST:event_importHashSetButtonActionPerformed

    private void refreshFilesButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshFilesButtonActionPerformed
        Map<String, String> filePaths = ModuleSettings.getConfigSettings(MODULE_NAME_FILES);
        if (filePaths.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No files imported from disk.",
                    "Refresh Hash Lists", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show a confirmation dialog before running the refresh
        int buttonOutput = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to refresh all the hash lists?", "Refresh Hash Lists",
                JOptionPane.YES_NO_OPTION);
        if (buttonOutput != 0) {
            return;
        }

        // Refresh the hash lists from disk
        for (Map.Entry<String, String> entry : filePaths.entrySet()) {
            String hashSetName = entry.getKey();
            String hashSetPath = entry.getValue();

            if (!ModuleSettings.settingExists(MODULE_NAME, hashSetName)) {
                ModuleSettings.removeProperty(MODULE_NAME_FILES, hashSetName);
                continue;
            }

            File file;
            try {
                file = new File(hashSetPath);
            } catch (NullPointerException ex) {
                JOptionPane.showMessageDialog(this, "File no longer exists on disk: " + hashSetPath,
                        "Refresh Hash Lists", JOptionPane.ERROR_MESSAGE);
                logger.log(Level.WARNING, "File not longer exists: {0}", hashSetPath);
                ModuleSettings.removeProperty(MODULE_NAME_FILES, hashSetName);
                continue;
            }
            String newSettingVal = readTextFromFile(file);
            ModuleSettings.setConfigSetting(MODULE_NAME, hashSetName, newSettingVal);
        }
    }//GEN-LAST:event_refreshFilesButtonActionPerformed

    private void refreshSelectedButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_refreshSelectedButtonActionPerformed
        int[] rows = hashSetTable.getSelectedRows();

        if (rows.length == 0) {
            JOptionPane.showMessageDialog(this, "No rows selected.", "Refresh Hash Lists", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show a confirmation dialog before running the refresh
        int buttonOutput = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to refresh the selected hash lists?", "Refresh Hash Lists",
                JOptionPane.YES_NO_OPTION);
        if (buttonOutput != 0) {
            return;
        }

        // Refresh the selected hash lists
        for (int row : rows) {
            String rowVal = (String) hashSetTable.getValueAt(row, 0);
            if (!ModuleSettings.settingExists(MODULE_NAME_FILES, rowVal)) {
                continue;
            }

            if (!ModuleSettings.settingExists(MODULE_NAME, rowVal)) {
                ModuleSettings.removeProperty(MODULE_NAME_FILES, rowVal);
            }

            String filePath = ModuleSettings.getConfigSetting(MODULE_NAME_FILES, rowVal);
            File file;
            try {
                file = new File(filePath);
            } catch (NullPointerException ex) {
                JOptionPane.showMessageDialog(this, "File no longer exists on disk: " + filePath,
                        "Refresh Hash Lists", JOptionPane.ERROR_MESSAGE);
                logger.log(Level.WARNING, "File not longer exists: {0}", filePath);
                ModuleSettings.removeProperty(MODULE_NAME_FILES, rowVal);
                continue;
            }

            String newSettingVal = readTextFromFile(file);
            ModuleSettings.setConfigSetting(MODULE_NAME, rowVal, newSettingVal);
        }
    }//GEN-LAST:event_refreshSelectedButtonActionPerformed

    /**
     * This recursively traverses all the files that have been passed to it and if it is a directory it will go as to
     * each of its subfolders. This function also only searches for .txt files.
     *
     * @param initFiles List of files and directories to get text files from.
     *
     * @return A list of the filtered files including the ones in any subdirectory if a directory is passed.
     */
    private File[] getAllFilesAndSubFiles(File[] initFiles) {
        List<File> files = new ArrayList<>();

        for (File file : initFiles) {
            if (file.isDirectory()) {
                files.addAll(Arrays.asList(getAllFilesAndSubFiles(file.listFiles())));
            } else {
                if (file.getName().endsWith("txt")) {
                    files.add(file);
                }
            }
        }

        return files.toArray(new File[0]);
    }

    private String readTextFromFile(File file) {
        String settingValue = "";
        try {
            Scanner reader = new Scanner(file);
            while (reader.hasNextLine()) {
                settingValue += reader.nextLine() + System.lineSeparator();
            }
        } catch (FileNotFoundException e) {
            System.out.println(e);
        }
        return settingValue;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton createHashSetButton;
    private javax.swing.JButton deleteHashSetButton;
    private javax.swing.JButton editHashSetButton;
    private javax.swing.JButton exportHashSetButton;
    private javax.swing.JLabel hashSetLabel;
    private javax.swing.JTable hashSetTable;
    private javax.swing.JButton importHashSetButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton refreshFilesButton;
    private javax.swing.JButton refreshSelectedButton;
    // End of variables declaration//GEN-END:variables
}
