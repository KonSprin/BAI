package com.security.lab.xss;

import java.io.FileWriter;
import java.io.IOException;

public class Main {
    
    public static void main(String[] args) {
        Vulnerable_XSS_Konrad_Springer vulnerableApp = new Vulnerable_XSS_Konrad_Springer();
        Fixed_XSS_Konrad_Springer secureApp = new Fixed_XSS_Konrad_Springer();
        EnvironmentContext context = new EnvironmentContext();
        
        System.out.println("=================================================================");
        System.out.println("       XSS SECURITY TEST - CROSS-SITE SCRIPTING");
        System.out.println("=================================================================\n");
        
        // TEST 1: Prawidłowe dane
        System.out.println("TEST 1: Valid input - Normal review");
        String validInput = "{\"name\":\"Jan Kowalski\",\"review\":\"Great product, highly recommended!\"}";
        System.out.println("Input: " + validInput + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, validInput, "vulnerable_test1.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, validInput, "secure_test1.html");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        
        // TEST 2: XSS w name - script tag
        System.out.println("TEST 2: XSS Attack - Script in name field");
        String xssName = "{\"name\":\"<script>alert('XSS')</script>\",\"review\":\"Good product\"}";
        System.out.println("Input: " + xssName + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, xssName, "vulnerable_test2.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, xssName, "secure_test2.html");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        
        // TEST 3: XSS w review - img onerror
        System.out.println("TEST 3: XSS Attack - Image onerror in review");
        String xssReview = "{\"name\":\"Jan Kowalski\",\"review\":\"Nice<img src=x onerror='alert(1)'>product\"}";
        System.out.println("Input: " + xssReview + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, xssReview, "vulnerable_test3.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, xssReview, "secure_test3.html");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        
        // TEST 4: XSS - iframe injection
        System.out.println("TEST 4: XSS Attack - Iframe injection");
        String xssIframe = "{\"name\":\"Jan Hackerman\",\"review\":\"<iframe src='javascript:alert(1)'></iframe>Check this out\"}";
        System.out.println("Input: " + xssIframe + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, xssIframe, "vulnerable_test4.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, xssIframe, "secure_test4.html");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        
        // TEST 5: XSS - SVG onload
        System.out.println("TEST 5: XSS Attack - SVG onload");
        String xssSvg = "{\"name\":\"<svg/onload=alert('XSS')>\",\"review\":\"Amazing!\"}";
        System.out.println("Input: " + xssSvg + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, xssSvg, "vulnerable_test5.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, xssSvg, "secure_test5.html");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        
        // TEST 6: XSS - Event handler
        System.out.println("TEST 6: XSS Attack - Event handler in both fields");
        String xssEvent = "{\"name\":\"<div onmouseover='alert(1)'>Hover</div>\",\"review\":\"<span onclick='alert(2)'>Click me</span>\"}";
        System.out.println("Input: " + xssEvent + "\n");
        
        System.out.println("VULNERABLE VERSION:");
        testApp(vulnerableApp, context, xssEvent, "vulnerable_test6.html");
        
        System.out.println("\nSECURE VERSION:");
        testApp(secureApp, context, xssEvent, "secure_test6.html");
        
    }
    
    private static void testApp(VulnerabilityLogic app, EnvironmentContext context, 
                                String input, String filename) {
        try {
            String html = app.process(input, context);
            saveHtmlToFile(html, filename);
            System.out.println("Generated: " + filename);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }
    
    private static void saveHtmlToFile(String html, String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(html);
        } catch (IOException e) {
            System.err.println("Failed to save file: " + e.getMessage());
        }
    }
}
