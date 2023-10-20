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

import java.util.ArrayList;
import java.util.List;

/**
 * Designed to parse TLSH hashes out of a large string inputted by a user. Most of these are based on line separators
 * and should parse out comments. This is also a class that allows for the the hash list, hash, and comments to be
 * stored in a single object. Then only one object variable has to be stored and passed around instead of 3 separate
 * arrays with all the information.
 */
public class ParseTlshObj {

    public String listName;
    public String hashStr;
    public String comment;

    /**
     * Initialize and empty ParseTlshObj.
     */
    ParseTlshObj() {
        this.listName = "";
        this.hashStr = "";
        this.comment = "";
    }

    /**
     * Initialize a ParseTlshObj with just a hash string.
     * 
     * @param hashStr TLSH hash string.
     */
    ParseTlshObj(String hashStr) {
        this.listName = "";
        this.hashStr = hashStr;
        this.comment = "";
    }

    /**
     * Initialize a ParseTlshObj with a hash string that is connected to a list.
     * 
     * @param listName Hash list name.
     * @param hashStr TLSH hash string.
     */
    ParseTlshObj(String listName, String hashStr) {
        this.listName = listName;
        this.hashStr = hashStr;
        this.comment = "";
    }

    /**
     * Initialize a ParseTlshObj with a list name, hash string, and a comment about the hash.
     * 
     * @param listName Hash list name.
     * @param hashStr TLSH hash string.
     * @param comment Comment about the hash.
     */
    ParseTlshObj(String listName, String hashStr, String comment) {
        this.listName = listName;
        this.hashStr = hashStr;
        this.comment = comment;
    }

    /**
     * Given a line from a hash list inputted by the user it will parse out the hash string and comment.
     * 
     * @param objStr Line containing a hash string and possibly a follow on comment.
     */
    public void ParseObjFromStr(String objStr) {
        String[] splitStr;

        if (objStr.contains("#")) {
            splitStr = objStr.trim().split("#", 2);
        } else if (objStr.contains("//")) {
            splitStr = objStr.trim().split("//", 2);
        } else {
            // test if there is just a hash
            splitStr = objStr.trim().split(" ", 2);
            if (splitStr.length == 1) { // This means if contained a # and it has 1 string so it is not a hash
                this.hashStr = splitStr[0].trim();
                return;
            }
        }

        if (splitStr.length != 2) {
            // This means that there is something wrong with the parsing.
            return;
        }

        this.hashStr = splitStr[0].trim();
        this.comment = splitStr[1].trim();
    }

    /**
     * Given a line from a hash list inputted by the user it will parse out the hash string and comment. It will also
     * tag the hash with the list that it came from.
     * 
     * @param listStr The hash list that the line came from.
     * @param objStr Line containing a hash string and possibly a follow on comment.
     */
    public void ParseObjFromStr(String listStr, String objStr) {
        String[] splitStr;

        this.listName = listStr;

        if (objStr.contains("#")) {
            splitStr = objStr.trim().split("#", 2);
        } else if (objStr.contains("//")) {
            splitStr = objStr.trim().split("//", 2);
        } else {
            // test if there is just a hash
            splitStr = objStr.trim().split(" ", 2);
            if (splitStr.length == 1) { // This means if contained a # and it has 1 string so it is not a hash
                this.hashStr = splitStr[0].trim();
                return;
            }
        }

        if (splitStr.length != 2) {
            // This means that there is something wrong with the parsing.
            return;
        }

        this.hashStr = splitStr[0].trim();
        this.comment = splitStr[1].trim();
    }

    /**
     * Parses an entire hash digest inputted by the user and DOES preserve the comments.
     * 
     * @param digest Blob of text with a hash one every line. Comments with accepted characters may be present.
     * @return String array of all the parsed out hashes and their comments if applicable.
     */
    public static String[] ParseHashLinesWithComments(String digest) {
        List<String> hashArr = new ArrayList<>();
        String[] lines = digest.split(System.lineSeparator());

        for (String line : lines) {
            if (!line.isEmpty() && !(line.trim().startsWith("#") || line.trim().startsWith("//"))) {
                hashArr.add(line.trim());
            }
        }

        // hashArr.toArray(new String[0]) is needed to convert the hashArr to String[] reasoning here:
        // https://stackoverflow.com/questions/4042434/converting-arrayliststring-to-string-in-java
        return hashArr.toArray(new String[0]);
    }

    /**
     * Parses and entire hash digest inputted by the user and DOES NOT preserve the comments attached.
     * 
     * @param digest Blob of text with a hash one every line. Comments with accepted characters may be present.
     * @return String array of all the parsed out hashes. 
     */
    public static String[] ParseHashesFromDigest(String digest) {
        List<String> hashArr = new ArrayList<>();
        String[] lines = digest.split(System.lineSeparator());

        for (String line : lines) {
            if (line.isEmpty()) {
                continue;
            } else if (line.contains("#") || line.contains("//")) {
                if (line.trim().startsWith("#") || line.trim().startsWith("//")) {
                    continue;
                }

                // Gets rid of leading and trailing spaces and if the comment is after the hash it will ignore it
                String[] splitStr = line.trim().split(" ", 2);
                if (splitStr.length != 2) { // This means if contained a # and it has 1 string so it is not a hash
                    continue;
                }

                hashArr.add(splitStr[0]);
            } else {
                hashArr.add(line.trim());
            }
        }

        // hashArr.toArray(new String[0]) is needed to convert the hashArr to String[] reasoning here:
        // https://stackoverflow.com/questions/4042434/converting-arrayliststring-to-string-in-java
        return hashArr.toArray(new String[0]);
    }

}
