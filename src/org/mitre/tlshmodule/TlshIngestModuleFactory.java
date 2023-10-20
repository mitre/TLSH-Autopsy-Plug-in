/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
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

import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 * Required class by Autopsy for the creation of ingest modules.
 */
@ServiceProvider(service = IngestModuleFactory.class)
public class TlshIngestModuleFactory implements IngestModuleFactory {
    
    private static final String VERSION_NUMBER = "1.0.0";

    static String getModuleName() {
        return "TLSHIngestModule";
    }

    @Override
    public String getModuleDisplayName() {
        return "TLSH Ingest Module";
    }

    @Override
    public String getModuleDescription() {
        return "Module that gets the TLSH hash of all the given files and then compares their distance to a given file."
                + "Distance references how closely the files are related in the TLSH algorithm.";
    }

    @Override
    public String getModuleVersionNumber() {
        return TlshIngestModuleFactory.VERSION_NUMBER;
    }

    // Tells ingest panel about the settings panel
    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new TlshModuleIngestJobSettings();
    }

    // Global Ingest settings panel
    @Override
    public boolean hasGlobalSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        return new TlshIngestModuleGlobalSettingsPanel();
    }

    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(
        IngestModuleIngestJobSettings settings) {

        if (!(settings instanceof TlshModuleIngestJobSettings)) {
            // If the settings variable is equal to the string “None”,
            // this allows an instance of it to be created for use with the module.
            settings = new TlshModuleIngestJobSettings();
            if (!(settings instanceof TlshModuleIngestJobSettings)) {
                throw new IllegalArgumentException(
                    "Expected settings argument to be instanceof TlshModuleIngestJobSettings");
            }
        }
        
        return new TlshIngestModuleIngestJobSettingsPanel(
            (TlshModuleIngestJobSettings) settings);
    }

    // Tells that this IngestModule is capable of reading files
    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        if (!(settings instanceof TlshModuleIngestJobSettings)) {
            throw new IllegalArgumentException(
                "Expected settings argument to be instanceof TlshModuleIngestJobSettings");
        }
        return new TlshFileIngestModule((TlshModuleIngestJobSettings) settings);
    }

    // Sets all the extra settings to false
    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return false;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        throw new UnsupportedOperationException();
    }
}
