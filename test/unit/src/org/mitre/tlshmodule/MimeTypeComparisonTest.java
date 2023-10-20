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

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Used to test all the Mime file type comparison functions to ensure that they are
 * functioning as expected. 
 */
public class MimeTypeComparisonTest {

    /**
     * Ensure that `true` is returned when `null` is passed into the `MachingMimeTypes` function. This is the
     * fail to open (true) result that is expected.
     */
    @Test
    public void testNullParam() {
        System.out.println("** MimeTypeComparisonUnitTest: testNullParam()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes(null, "*/*");
        assertEquals(retVal, true);
    }

    /**
     * Ensure that `true` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has two wildcards as the compare value.
     */
    @Test
    public void testBothWildCards() {
        System.out.println("** MimeTypeComparisonUnitTest: testBothWildCards()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("text/plain", "*/*");
        assertEquals(retVal, true);
    }

    /**
     * Ensure that `true` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has the same matching mime type as the compare value.
     */
    @Test
    public void testValuesEqual() {
        System.out.println("** MimeTypeComparisonUnitTest: testValuesEqual()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("text/plain", "text/plain");
        assertEquals(retVal, true);
    }

    /**
     * Ensure that `true` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has the one matching mime type and a wild card on one side as the compare value.
     */
    @Test
    public void testFrontWildCard() {
        System.out.println("** MimeTypeComparisonUnitTest: testFrontWildCard()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("text/plain", "*/plain");
        assertEquals(retVal, true);
    }

    /**
     * Ensure that `true` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has the one matching mime type and a wild card on one side as the compare value.
     */
    @Test
    public void testBackWildCard() {
        System.out.println("** MimeTypeComparisonUnitTest: testBackWildCard()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("application/octet-stream", "application/*");
        assertEquals(retVal, true);
    }

    /**
     * Ensure that `false` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has a non-matching mime type and no wildcards as the compare value.
     */
    @Test
    public void testNotEqual() {
        System.out.println("** MimeTypeComparisonUnitTest: testNotEqual()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("application/octet-stream", "application/fake");
        assertEquals(retVal, false);
    }

    /**
     * Ensure that `false` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has a non-matching mime type and wildcards as the compare value.
     */
    @Test
    public void testFrontWildCardNotEqual() {
        System.out.println("** MimeTypeComparisonUnitTest: testFrontWildCardNotEqual()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("application/octet-stream", "*/fake");
        assertEquals(retVal, false);
    }

    /**
     * Ensure that `false` is returned when a specific mime type is passed into the `MachingMimeTypes` function
     * that has a non-matching mime type and wildcards as the compare value.
     */
    @Test
    public void testBackWildCardNotEqual() {
        System.out.println("** MimeTypeComparisonUnitTest: testBackWildCardNotEqual()");
        boolean retVal = MimeTypeComparison.MatchingMimeTypes("application/octet-stream", "text/*");
        assertEquals(retVal, false);
    }
    
}
