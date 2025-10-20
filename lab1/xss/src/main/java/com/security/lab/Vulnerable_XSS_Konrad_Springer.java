package com.security.lab.xss;

import org.json.JSONObject;

// Interface
interface VulnerabilityLogic {
    String process(String userInput, EnvironmentContext context) throws Exception;
}

// Klasa kontekstu
class EnvironmentContext {
    private final java.util.Map<String, String> context = new java.util.concurrent.ConcurrentHashMap<>();
    
    public String getString(String key, String defaultValue) {
        return context.getOrDefault(key, defaultValue);
    }
    
    public void put(String key, String value) {
        context.put(key, value);
    }
}

// PODATNA WERSJA - Cross-Site Scripting (XSS)
public class Vulnerable_XSS_Konrad_Springer implements VulnerabilityLogic {
    
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        JSONObject json = new JSONObject(userInput);
        
        // PODATNOSC: Bezposrednie uzycie danych bez walidacji
        String name = json.getString("name");
        String review = json.getString("review");
        
        return generateHtmlPage(name, review);
    }
    
    private String generateHtmlPage(String name, String review) {
        // KRYTYCZNA PODATNOSC: name i review nie sa escapowane!
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <title>Product Review - Vulnerable</title>
                <style>
                    body { font-family: Arial; margin: 40px; background: #f5f5f5; }
                    .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; }
                    h1 { color: #333; border-bottom: 2px solid #e74c3c; }
                    .warning { background: #fff3cd; padding: 10px; margin: 20px 0; }
                    .review { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
                    .name { font-weight: bold; font-size: 18px; }
                    .content { margin-top: 10px; color: #555; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h1>Product Review (VULNERABLE VERSION)</h1>
                    <div class='warning'>WARNING: This version is vulnerable to XSS attacks!</div>
                    <div class='review'>
                        <div class='name'>%s</div>
                        <div class='content'>%s</div>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(name, review);
    }
}
