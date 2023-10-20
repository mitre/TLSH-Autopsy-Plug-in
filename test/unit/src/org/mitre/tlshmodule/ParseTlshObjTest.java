/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/UnitTests/JUnit4TestClass.java to edit this template
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
import org.junit.Assert;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Used to test all the TLSH parsing functionality in order to ensure proper functionality.
 */
public class ParseTlshObjTest {

    private static final String testDigestHash1 = "T1994320230BBBCA63C5CBA3B4B0877B47D210FD213EE65DD68754EA180EE57866148F49";
    private static final String testDigestHash2 = "T19853837B03B1C4B3C48E98B4D4466B565F16F8A53BE248D1835DFE384F91B0A4F8DA4A";
    private static final String testDigestHash3 = "T15942D71FA381233B496102B5770EA2CBEB15C0BC5369A571A45EC12E3367D7C937B9E8";
    
    // This hash is just used in comments to verify it won't try to parse them.
    private static final String testDigestHash4 = "T15942D71FA3B15C0BC5369A571A45EC12E3367D7C937B9E8";
    
    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string.
     */
    @Test
    public void testParseObjFromStrPlain() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrPlain()");
        
        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr(testDigestHash1);
        Assert.assertEquals("", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("", results.comment);
    }

    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string and a trailing comment
     */
    @Test
    public void testParseObjFromStrInlineComment() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrInlineComment()");
        String testDigest
                = testDigestHash1 + " // tmp comment hello";

        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr(testDigest);
        Assert.assertEquals("", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("tmp comment hello", results.comment);
    }

    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string and a comment above the hash
     */
    @Test
    public void testParseObjFromStrCommentAbove() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrCommentAbove()");
        String testDigest = "# above comment" + System.lineSeparator()
                + testDigestHash1;

        String[] hashes = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertEquals(1, hashes.length);

        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr(hashes[0]);
        Assert.assertEquals("", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("", results.comment);
    }

    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string and passing a list name. This is important
     * for mapping hashes back to specific sets a user may input.
     */
    @Test
    public void testParseObjFromStrPlainWithList() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrPlain()");
        String testDigest = testDigestHash1;

        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr("test_list", testDigest);
        Assert.assertEquals("test_list", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("", results.comment);
    }

    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string, trailing comment, and passing a list name. 
     * The list name variant is important for mapping hashes back to specific sets a user may input.
     */
    @Test
    public void testParseObjFromStrInlineCommentWithList() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrInlineComment()");
        String testDigest
                = testDigestHash1 + " // tmp comment hello";

        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr("test_list", testDigest);
        Assert.assertEquals("test_list", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("tmp comment hello", results.comment);
    }

    /**
     * Testing the `ParseObjFromStr` function with a single TLSH string, comment above, and passing a list name. 
     * The list name variant is important for mapping hashes back to specific sets a user may input.
     */    
    @Test
    public void testParseObjFromStrCommentAboveWithList() {
        System.out.println("** ParseTlshFromStringsTest: testParseObjFromStrCommentAbove()");
        String testDigest = "# above comment" + System.lineSeparator()
                + testDigestHash1;

        String[] hashes = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertEquals(1, hashes.length);

        ParseTlshObj results = new ParseTlshObj();
        results.ParseObjFromStr("test_list", hashes[0]);
        Assert.assertEquals("test_list", results.listName);
        Assert.assertEquals(testDigestHash1, results.hashStr);
        Assert.assertEquals("", results.comment);
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with multiple TLSH lines and no comments.
     */
    @Test
    public void testPlainDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testPlainDigestWithComments()");
        String testDigest
                = testDigestHash1 + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3;

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with empty digest.
     */
    @Test
    public void testEmptyDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testEmptyDigestWithComments()");
        String testDigest = new String();

        List<String> expectedOutput = new ArrayList<>();

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));

        // Testing "" because sometimes the text input is returned as that as well
        testDigest = "";
        results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with multiple new lines between TLSH string values.
     */
    @Test
    public void testWithNewLinesDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testWithNewLinesDigestWithComments()");
        String testDigest
                = testDigestHash1
                + System.lineSeparator() + System.lineSeparator() + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + System.lineSeparator()
                + System.lineSeparator() + System.lineSeparator() + System.lineSeparator();

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with multiple TLSH strings and multiple trailing comments.
     */
    @Test
    public void testInlineCommentedDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testInlineCommentedDigestWithComments()");
        String testDigest
                = testDigestHash1 + " # Hello"
                + System.lineSeparator()
                + testDigestHash2 + "     #hello2"
                + System.lineSeparator()
                + testDigestHash3 + " #anotherone";

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1 + " # Hello");
                add(testDigestHash2 + "     #hello2");
                add(testDigestHash3 + " #anotherone");
            }
        };

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with multiple TLSH strings and multiple types of comments
     * spread through the digest.
     */
    @Test
    public void testFullCommentedDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testFullCommentedDigestWithComments()");
        String testDigest
                = testDigestHash1 + " # testesttest"
                + System.lineSeparator()
                + "# Group 2 Set" + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + "      # Test again"
                + System.lineSeparator()
                + "# Below is an invalid hash" + System.lineSeparator()
                + "# " + testDigestHash4;

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1 + " # testesttest");
                add(testDigestHash2);
                add(testDigestHash3 + "      # Test again");
            }
        };

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashLinesWithComments` function with multiple TLSH strings and multiple types of comments
     * spread through the digest. There was also multiple line separators to ensure all functioned as expected.
     */
    @Test
    public void testEverythingDigestWithComments() {
        System.out.println("** ParseTlshFromStringsTest: testEverythingDigest()");
        String testDigest
                = testDigestHash1 + " # testesttest"
                + System.lineSeparator()
                + "# Group 2 Set" + System.lineSeparator() + System.lineSeparator() + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + "      # Test again"
                + System.lineSeparator() + System.lineSeparator()
                + "# Below is an invalid hash" + System.lineSeparator() + System.lineSeparator()
                + "# " + testDigestHash4 + System.lineSeparator();

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1 + " # testesttest");
                add(testDigestHash2);
                add(testDigestHash3 + "      # Test again");
            }
        };

        String[] results = ParseTlshObj.ParseHashLinesWithComments(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }


    /**
     * Testing the `ParseHashesFromDigest` function with multiple lines of TLSH hash strings.
     */
    @Test
    public void testPlainDigest() {
        System.out.println("** ParseTlshFromStringsTest: testPlainDigest()");
        String testDigest
                = testDigestHash1 + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3;

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashesFromDigest` function with an empty digest.
     */
    @Test
    public void testEmptyDigest() {
        System.out.println("** ParseTlshFromStringsTest: testEmptyDigest()");
        String testDigest = new String();

        List<String> expectedOutput = new ArrayList<>();

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));

        // Testing "" because sometimes the text input is returned as that as well
        testDigest = "";
        results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashesFromDigest` function with multiple new lines between TLSH strings.
     */
    @Test
    public void testWithNewLinesDigest() {
        System.out.println("** ParseTlshFromStringsTest: testWithNewLinesDigest()");
        String testDigest
                = testDigestHash1
                + System.lineSeparator() + System.lineSeparator() + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + System.lineSeparator()
                + System.lineSeparator() + System.lineSeparator() + System.lineSeparator();

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashesFromDigest` function with multiple new lines between TLSH strings and trailing comments.
     */
    @Test
    public void testInlineCommentedDigest() {
        System.out.println("** ParseTlshFromStringsTest: testInlineCommentedDigest()");
        String testDigest
                = testDigestHash1 + " # Hello"
                + System.lineSeparator()
                + testDigestHash2 + "     #hello2"
                + System.lineSeparator()
                + testDigestHash3 + " #anotherone";

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashesFromDigest` function with multiple new lines between TLSH strings and many different 
     * possible comment types.
     */
    @Test
    public void testFullCommentedDigest() {
        System.out.println("** ParseTlshFromStringsTest: testFullCommentedDigest()");
        String testDigest
                = testDigestHash1 + " # testesttest"
                + System.lineSeparator()
                + "# Group 2 Set" + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + "      # Test again"
                + System.lineSeparator()
                + "# Below is an invalid hash" + System.lineSeparator()
                + "# " + testDigestHash4;

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

    /**
     * Testing the `ParseHashesFromDigest` function with multiple new lines between TLSH strings and many different 
     * possible comment types.
     */
    @Test
    public void testEverythingDigest() {
        System.out.println("** ParseTlshFromStringsTest: testEverythingDigest()");
        String testDigest
                = testDigestHash1 + " # testesttest"
                + System.lineSeparator()
                + "# Group 2 Set" + System.lineSeparator() + System.lineSeparator() + System.lineSeparator()
                + testDigestHash2 + System.lineSeparator()
                + testDigestHash3 + "      # Test again"
                + System.lineSeparator() + System.lineSeparator()
                + "# Below is an invalid hash" + System.lineSeparator() + System.lineSeparator()
                + "# " + testDigestHash4 + System.lineSeparator();

        List<String> expectedOutput = new ArrayList<String>() {
            {
                add(testDigestHash1);
                add(testDigestHash2);
                add(testDigestHash3);
            }
        };

        String[] results = ParseTlshObj.ParseHashesFromDigest(testDigest);
        Assert.assertArrayEquals(results, expectedOutput.toArray(new String[0]));
    }

}
