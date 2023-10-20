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

/**
 * A class that hold functionality to run comparisons on String versions of MIME File Types
 */
public class MimeTypeComparison {

    /**
     * Compare the two types and return if they are a match or not. The second parameter supports wild cards
     * for an entire type, but not partial types. Ex: *\/* or application\/*. If the function is passed in a 
     * null string it will fail to open (true). Ensure to check the Strings that are being passed into the function.
     *
     * @param1 mimeType
     *  The mime type that is going to be compared to the second parameter. If it is null it will return true.
     *
     * @param2 compareType
     *  The type to be compared to. This can contain wild cards '*'
     *
     * @return will return true if there is a match or false if there is not
     */
    public static boolean MatchingMimeTypes(String mimeType, String compareType) {

        // Check if a null value is passed in, if so fail to true
        if (mimeType == null) {
            return true;
        }

        // Do base comparisons
        if (compareType.equals("*/*")) {
            return true;
        }

        if (mimeType.equals(compareType)) {
            return true;
        }

        // Error check the sizes for other comparisons
        String[] splitType = mimeType.split("/");
        String[] splitCompare = compareType.split("/");

        if (splitType.length != 2 || splitCompare.length != 2) {
            return false;
        }

        // Do final comparisons
        if (splitCompare[0].contains("*")) {
            if (splitCompare[1].equals(splitType[1])) {
                return true;
            }
        }

        if (splitCompare[1].contains("*")) {
            if (splitCompare[0].equals(splitType[0])) {
                return true;
            }
        }

        return false;
    }

}
