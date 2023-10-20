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

import com.trendmicro.tlsh.Tlsh;
import com.trendmicro.tlsh.TlshCreator;
import java.util.ArrayList;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.ingest.FileIngestModuleAdapter;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.autopsy.modules.filetypeid.FileTypeDetector;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * A file ingest module, which will hash the file with TLSH and compare with another TLSH file hash if it is provided.
 * Those options can be set during the Ingest configuration time.
 */
public class TlshFileIngestModule extends FileIngestModuleAdapter {

    // UUID is used for comparison hits so that there are different sections for each ingest.
    // Note: UUID needs to be set in the settings because if done in the startup() function it will generate
    //       multiple per ingest
    private String ingestUUID = new String();

    private static final Logger logger = Logger.getLogger(TlshFileIngestModule.class.getName());
    private final String ModuleArtifactName = "TLSH (Trend Micro Locality Sensitive Hash)";

    private IngestJobContext context = null;

    private Case currentCase = null;
    private Blackboard blackboard = null;

    // Variables for the settings panel GUI
    private boolean runTlshComparison = false;
    private String[] tlshHashStrings = new String[0];
    private final ArrayList<ParseTlshObj> tlshHashes = new ArrayList<>();
    private int thresholdDistance = 10;
    private boolean compareLength = false;

    private List<String> enabledHashSets = new ArrayList<>();
    private final Map<String, ArrayList<ParseTlshObj>> hashSetMap = new HashMap<>();

    private String compareMimeType;

    /**
     * Class constructor which takes in settings that were configured via the Autopsy GUI.
     * 
     * @param settings TLSH settings class that get configured by the user and has fault values set.
     */
    TlshFileIngestModule(TlshModuleIngestJobSettings settings) {
        // It is important to set the settings to local variables because if another job is started with different
        // settings than these will not change

        this.ingestUUID = settings.getIngestUUID();

        this.runTlshComparison = settings.getRunTlshComparison();
        this.tlshHashStrings = settings.getTlshHashes();

        this.thresholdDistance = settings.getTargetDistance();
        this.compareLength = settings.getCompareLength();

        this.enabledHashSets = new ArrayList<>(Arrays.asList(settings.getEnabledHashSets()));

        this.compareMimeType = settings.getCompareMimeType();
    }

    /**
     * Required function by Autopsy to start the ingest manager.
     */
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
        try {
            currentCase = Case.getCurrentCaseThrows();
        } catch (NoCurrentCaseException ex) {
            logger.log(Level.SEVERE, "Exception while getting open case.", ex);
            throw new IngestModuleException("Exception while getting open case.", ex);
        }

        // Convert the hash list to ParseTlshObj class objects
        for (String hashStr : this.tlshHashStrings) {
            ParseTlshObj hashObj = new ParseTlshObj();
            hashObj.ParseObjFromStr(hashStr);
            this.tlshHashes.add(hashObj);
        }

        // Convert all the of the module settings that are ParseTlshObj
        Map<String, String> moduleSettings = ModuleSettings.getConfigSettings(TlshIngestModuleFactory.getModuleName());
        for (Map.Entry<String, String> entry : moduleSettings.entrySet()) {
            if (this.enabledHashSets.contains(entry.getKey())) {

                hashSetMap.put(entry.getKey(), new ArrayList<ParseTlshObj>());
                String[] hashes = ParseTlshObj.ParseHashLinesWithComments(entry.getValue());

                for (String hashStr : hashes) {
                    ParseTlshObj hashObj = new ParseTlshObj();
                    hashObj.ParseObjFromStr(entry.getKey(), hashStr);

                    ArrayList<ParseTlshObj> oldVal = hashSetMap.get(entry.getKey());
                    oldVal.add(hashObj);
                    hashSetMap.put(entry.getKey(), oldVal);
                }
            }
        }
    }

    /**
     * Function called by Autopsy on each file it has saved for TLSH ingest module processing. This is where the main
     * logic for the module takes place. Any filtering of specific files happens here.
     * 
     * @param file File passed in by Autopsy including the metadata that it has tagged it with.
     * @return The result of processing the file.
     */
    @Override
    public IngestModule.ProcessResult process(AbstractFile file) {

        // Skip anything other than actual file system files.
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS)
                || (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS)
                || (file.isFile() == false)) {
            return IngestModule.ProcessResult.OK;
        }

        // Skip anything that is not the MIME file type that is being searched for
        // Detect the MIME file type. If it is null, detect it, then continue
        String mimeFileType = file.getMIMEType();
        if (mimeFileType == null) {
            try {
                FileTypeDetector ftd = new FileTypeDetector();
                mimeFileType = ftd.getMIMEType(file);
            } catch (FileTypeDetector.FileTypeDetectorInitException ex) {
                logger.log(Level.WARNING, "Could not open file detector, MIME file types might be null:", ex);
            }
        }
        if (!MimeTypeComparison.MatchingMimeTypes(mimeFileType, compareMimeType)) {
            return IngestModule.ProcessResult.OK;
        }

        blackboard = currentCase.getSleuthkitCase().getBlackboard();

        // Check if the file has already been ingested and has a TLSH hash attached
        String knownHash = this.knownTlshFile(file);

        // Hash has already been calculated on this file - skip it or run comparison
        if (knownHash != null) {
            ProcessResult retResult = IngestModule.ProcessResult.OK;
            if (this.runTlshComparison) {
                retResult = this.processWithComparison(file, Tlsh.fromTlshStr(knownHash));
            }
            if (!hashSetMap.isEmpty()) {
                retResult = this.processWithHashSets(file, Tlsh.fromTlshStr(knownHash));
            }
            return retResult;
        }

        // Calculate the hash and check if it is null
        Tlsh hash = calculateTlshHash(file);
        if (hash == null) {
            return IngestModule.ProcessResult.ERROR;
        }

        // Create the artifact to post to the blackboard
        postHashToBlackboard(hash.getEncoded(), file);

        ProcessResult retResult = IngestModule.ProcessResult.OK;
        if (this.runTlshComparison) {
            retResult = this.processWithComparison(file, hash);
        }
        if (!hashSetMap.isEmpty()) {
            retResult = this.processWithHashSets(file, hash);
        }

        return retResult;
    }

    /**
     * Gets the known TLSH hash value that has already been calculated and attached to the file. It does this by pulling
     * from the blackboard values and checking if one is present for the same file.
     *
     * @param file The AbstractFile type from process that is being checked for a known hash.
     *
     * @return tlshStrHash or null if it could not find one attached to the file
     */
    private String knownTlshFile(AbstractFile file) {
        String knownHash = null;
        try {
            ArrayList<BlackboardArtifact> arrArt
                    = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT);

            // Loop through the interesting file hits and see if they have already been calculated
            for (BlackboardArtifact i : arrArt) {
                String artFileName = i.getParent().getName();  // File name of the artifact

                if (artFileName.equals(file.getName())) {
                    BlackboardAttribute tmpAttr = i.getAttribute(BlackboardAttribute.Type.TSK_VALUE);
                    if (tmpAttr == null) {
                        break;
                    }

                    // Verifies that the data is from this module
                    List<String> tmp = tmpAttr.getSources();
                    if (tmp.contains("TLSHIngestModule")) {
                        knownHash = tmpAttr.getValueString();
                        break;
                    }
                }
            }

        } catch (TskCoreException ex) {
            logger.log(Level.INFO, "Failed to get attributes from file: {0}", file.getName());
        }

        return knownHash;
    }

    /**
     * Uses the official TLSH library to calculate the hash of the file and return the TLSH object.
     * 
     * @param file The Autopsy file object passed in by the process function.
     * @return Calculated TLSH object or null if it failed.
     */
    private Tlsh calculateTlshHash(AbstractFile file) {
        // Read file into the TlshCreator
        TlshCreator tlshCreator = new TlshCreator();

        try { // Used to catch the exceptions from .read()
            // Read the file and input them in the TlshCreator
            byte[] buf = new byte[(int) file.getSize()];
            int bytesRead = file.read(buf, 0, buf.length);

            if (bytesRead != file.getSize()) {
                logger.log(Level.WARNING, "Could not read all of the file for creating TLSH hash: {0}", file.getName());
            }

            tlshCreator.update(buf, 0, bytesRead);
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Exception while reading the file.", ex);
            return null;
        }

        // Get the hash from the TlshCreator
        Tlsh hash;
        try { // Attempts to catch the exception from .getHash()
            hash = tlshCreator.getHash();
        } catch (IllegalStateException ex) {
            logger.log(Level.WARNING, "Exception while generating the hash for the file.", ex);
            return null;
        }

        return hash;
    }

    /**
     * Post the hash string that was calculated for the file to the Autopsy blackboard. This is what needs to be called
     * in order to display the hash to the user. 
     * 
     * @param hashStr The TLSH hash string.
     * @param file The Autopsy file that the hash will be attached to.
     */
    private void postHashToBlackboard(String hashStr, AbstractFile file) {
        BlackboardArtifact artifact = null;
        try {
            artifact = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                    Score.SCORE_NONE,
                    null, null, "Calculated the TLSH for this file.",
                    Arrays.asList(
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SET_NAME,
                                    TlshIngestModuleFactory.getModuleName(),
                                    this.ModuleArtifactName),
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE,
                                    TlshIngestModuleFactory.getModuleName(),
                                    hashStr)
                    ))
                    .getAnalysisResult();
        } catch (TskCoreException ex) {
            logger.log(Level.INFO, "Failed to add hash attribute to file: {0}", file.getName());
        }

        try {
            blackboard.postArtifact(artifact, TlshIngestModuleFactory.getModuleName());
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Unable to index blackboard artifact " + artifact.getArtifactID(), ex);
        }
    }

    /**
     * Process the current file and it's hash against the hash list that was configured by the user before running the
     * ingest module.
     * 
     * @param file The Autopsy file so that results can be posted to the blackboard.
     * @param genHash The file's TLSH hash object.
     * @return IngestModule.ProcessResult.OK
     */
    private IngestModule.ProcessResult processWithComparison(AbstractFile file, Tlsh genHash) {
        // Compare with all the hashes in the hash list
        for (ParseTlshObj compHash : this.tlshHashes) {
            Tlsh tlshObj;
            try {
                tlshObj = Tlsh.fromTlshStr(compHash.hashStr);
            } catch (IllegalArgumentException ex) {
                logger.log(Level.INFO, "Invalid inputted hash " + compHash.hashStr + ":", ex);
                continue;
            }

            int distance = tlshObj.totalDiff(genHash, this.compareLength);

            if (distance <= this.thresholdDistance) {
                postComparisonToBlackboard(distance, genHash.getEncoded(), compHash, file);
            }
        }

        return IngestModule.ProcessResult.OK;
    }

    /**
     * Post the hash comparison to the blackboard for the user to view.
     * 
     * @param distance TLSH hash distance calculated by the TLSH algorithm.
     * @param currentHash The hash of the current file.
     * @param compObj Reference to the class containing all the compared to TLSH object information.
     * @param file The Autopsy file used to tag all the information to.
     */
    private void postComparisonToBlackboard(int distance, String currentHash, ParseTlshObj compObj, AbstractFile file) {
        BlackboardArtifact artifact = null;
        BlackboardArtifact total_artifact = null;

        String configStr;
        if (compObj.comment.equals("")) {
            configStr = "Compared with: " + compObj.hashStr;
        } else {
            configStr = "Compared with - " + compObj.comment + ": " + compObj.hashStr;
        }

        try {
            artifact = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                    Score.SCORE_NOTABLE,
                    "Distance is: " + distance,
                    configStr,
                    "TLSH comparison threshold met.",
                    Arrays.asList(
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SET_NAME,
                                    TlshIngestModuleFactory.getModuleName(),
                                    "TLSH Comparison Hits - " + this.ingestUUID),
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE,
                                    TlshIngestModuleFactory.getModuleName(),
                                    currentHash)
                    ))
                    .getAnalysisResult();

            total_artifact = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                    Score.SCORE_NOTABLE,
                    "Distance is: " + distance,
                    configStr,
                    "TLSH comparison threshold met.",
                    Arrays.asList(
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SET_NAME,
                                    TlshIngestModuleFactory.getModuleName(),
                                    "TLSH Comparison Hits"),
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE,
                                    TlshIngestModuleFactory.getModuleName(),
                                    currentHash)
                    ))
                    .getAnalysisResult();
        } catch (TskCoreException ex) {
            logger.log(Level.INFO, "Failed to add hash attribute to file: {0}", file.getName());
        }

        try {
            blackboard.postArtifact(artifact, TlshIngestModuleFactory.getModuleName());
            blackboard.postArtifact(total_artifact, TlshIngestModuleFactory.getModuleName());
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Unable to index blackboard artifact " + artifact.getArtifactID(), ex);
        }
    }

    /**
     * Process the current file and it's hash against the hash set groups that were configured by the user before
     * running the ingest module.
     * 
     * @param file The Autopsy file so that results can be posted to the blackboard.
     * @param genHash The file's TLSH hash object.
     * @return IngestModule.ProcessResult.OK
     */
    private IngestModule.ProcessResult processWithHashSets(AbstractFile file, Tlsh genHash) {
        // Compare with all the known hash set groups that were created
        for (Map.Entry<String, ArrayList<ParseTlshObj>> entry : hashSetMap.entrySet()) {
            for (ParseTlshObj hashObj : entry.getValue()) {
                Tlsh tlshObj;
                try {
                    tlshObj = Tlsh.fromTlshStr(hashObj.hashStr);
                } catch (IllegalArgumentException ex) {
                    logger.log(Level.INFO, "Invalid inputed hash " + hashObj.hashStr + "from digest - "
                            + entry.getKey() + ": ", ex);
                    continue;
                }

                int distance = tlshObj.totalDiff(genHash, this.compareLength);

                if (distance <= this.thresholdDistance) {
                    postHashSetComparisonToBlackboard(distance, genHash.getEncoded(), hashObj, file);
                }
            }
        }

        return IngestModule.ProcessResult.OK;
    }

    /**
     * Post the hash comparison to the blackboard for the user to view. This also tags the hash set that the match
     * was discovered in.
     * 
     * @param distance TLSH hash distance calculated by the TLSH algorithm.
     * @param currentHash The hash of the current file.
     * @param compObj Reference to the class containing all the compared to TLSH object information.
     * @param file The Autopsy file used to tag all the information to.
     */
    private void postHashSetComparisonToBlackboard(int distance, String currentHash, ParseTlshObj compObj,
            AbstractFile file) {

        BlackboardArtifact artifact = null;
        BlackboardArtifact total_artifact = null;

        String configStr;
        if (compObj.comment.equals("")) {
            configStr = "For hashset " + compObj.listName + ": " + compObj.hashStr;
        } else {
            configStr = "For hashset " + compObj.listName + " - " + compObj.comment + ": " + compObj.hashStr;
        }

        try {
            artifact = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                    Score.SCORE_NOTABLE,
                    "Distance is: " + distance,
                    configStr,
                    "TLSH comparison threshold met.",
                    Arrays.asList(
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SET_NAME,
                                    TlshIngestModuleFactory.getModuleName(),
                                    "TLSH Comparison Hits - " + this.ingestUUID),
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE,
                                    TlshIngestModuleFactory.getModuleName(),
                                    currentHash)
                    ))
                    .getAnalysisResult();

            total_artifact = file.newAnalysisResult(
                    BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                    Score.SCORE_NOTABLE,
                    "Distance is: " + distance,
                    configStr,
                    "TLSH comparison threshold met.",
                    Arrays.asList(
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SET_NAME,
                                    TlshIngestModuleFactory.getModuleName(),
                                    "TLSH Comparison Hits"),
                            new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VALUE,
                                    TlshIngestModuleFactory.getModuleName(),
                                    currentHash)
                    ))
                    .getAnalysisResult();
        } catch (TskCoreException ex) {
            logger.log(Level.INFO, "Failed to add hash attribute to file: {0}", file.getName());
        }

        try {
            blackboard.postArtifact(artifact, TlshIngestModuleFactory.getModuleName());
            blackboard.postArtifact(total_artifact, TlshIngestModuleFactory.getModuleName());
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Unable to index blackboard artifact " + artifact.getArtifactID(), ex);
        }

    }

}
