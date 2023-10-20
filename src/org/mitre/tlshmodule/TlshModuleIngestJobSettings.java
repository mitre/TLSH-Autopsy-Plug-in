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

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 * This class holds all the settings for the current ingest job. Autopsy will use these
 * when running the ingest to know how to use the TLSH module.
 */
public class TlshModuleIngestJobSettings implements IngestModuleIngestJobSettings {

    private static final long serialVersionUID = 1L;

    private String ingestUUID = "";

    // Compare for hashlist (if a single hash is needed it works here too)
    private boolean runTlshComparison = false;
    private String[] tlshHashes = new String[0];

    private int targetDistance = 10;
    private boolean compareLength = false;

    private String[] enabledHashSets = new String[0];

    private String compareMimeType = "*/*";

    // Empty Constructor
    TlshModuleIngestJobSettings() {
    }

    // Constructor with settings
    TlshModuleIngestJobSettings(boolean runTlshComparison, String[] tlshHashes,
                                int targetDistance, boolean compareLength, String[] enabledHashSets,
                                String compareMimeType, String ingestUUID) {

        // Set local variables
        this.runTlshComparison = runTlshComparison;
        this.tlshHashes = tlshHashes;
        this.targetDistance = targetDistance;
        this.compareLength = compareLength;
        this.enabledHashSets = enabledHashSets;
        this.compareMimeType = compareMimeType;
        this.ingestUUID = ingestUUID;
    }

    @Override
    public long getVersionNumber() {
        return this.serialVersionUID;
    }

    void setIngestUUID(String uuidStr) {
        this.ingestUUID = uuidStr;
    }

    String getIngestUUID() {
        return this.ingestUUID;
    }

    void setRunTlshComparison(boolean enabled) {
        this.runTlshComparison = enabled;
    }

    boolean getRunTlshComparison() {
        return this.runTlshComparison;
    }

    void setTlshHashes(String[] hashes) {
        this.tlshHashes = hashes;
    }

    String[] getTlshHashes() {
        return this.tlshHashes;
    }

    void setTargetDistance(int distance) {
        this.targetDistance = distance;
    }

    int getTargetDistance() {
        return this.targetDistance;
    }

    void setCompareLength(boolean compareLength) {
        this.compareLength = compareLength;
    }

    boolean getCompareLength() {
        return this.compareLength;
    }

    void setEnabledHashSets(String[] enabledHashSets) {
        this.enabledHashSets = enabledHashSets;
    }

    String[] getEnabledHashSets() {
        return this.enabledHashSets;
    }

    void setCompareMimeType(String mimeType) {
        this.compareMimeType = mimeType;
    }

    String getCompareMimeType() {
        return this.compareMimeType;
    }
}
