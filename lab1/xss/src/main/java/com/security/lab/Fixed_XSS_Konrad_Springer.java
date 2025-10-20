package com.security.lab.xss;

import org.json.JSONObject;
import org.owasp.encoder.Encode;

// ZABEZPIECZONA WERSJA - Ochrona przed XSS
public class Fixed_XSS_Konrad_Springer implements VulnerabilityLogic {
    
    private static final int MAX_NAME_LENGTH = 100;
    private static final int MAX_REVIEW_LENGTH = 1000;
    
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        if (userInput == null || userInput.isEmpty()) {
            throw new IllegalArgumentException("Input cannot be empty");
        }
        
        if (userInput.length() > 10000) {
            throw new IllegalArgumentException("Input too long");
        }
        
        JSONObject json = new JSONObject(userInput);
        
        String rawName = json.getString("name");
        String rawReview = json.getString("review");
        
        // Walidacja
        if (rawName == null || rawName.trim().isEmpty()) {
            throw new IllegalArgumentException("Name cannot be empty");
        }
        
        if (rawReview == null || rawReview.trim().isEmpty()) {
            throw new IllegalArgumentException("Review cannot be empty");
        }
        
        String name = rawName.trim();
        String review = rawReview.trim();
        
        if (name.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("Name too long");
        }
        
        if (review.length() > MAX_REVIEW_LENGTH) {
            throw new IllegalArgumentException("Review too long");
        }
        
        return generateSafeHtmlPage(name, review);
    }
    
    private String generateSafeHtmlPage(String name, String review) {
        // KRYTYCZNA OCHRONA: Uzycie OWASP Encoder do escapowania HTML
        String safeName = Encode.forHtml(name);
        String safeReview = Encode.forHtml(review);
        
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <meta http-equiv='Content-Security-Policy' content="default-src 'self'; script-src 'none'; style-src 'unsafe-inline';">
                <title>Product Review - Secure</title>
                <style>
                    body { font-family: Arial; margin: 40px; background: #f5f5f5; }
                    .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; }
                    h1 { color: #333; border-bottom: 2px solid #27ae60; }
                    .security-info { background: #d4edda; padding: 10px; margin: 20px 0; }
                    .review { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }
                    .name { font-weight: bold; font-size: 18px; word-wrap: break-word; }
                    .content { margin-top: 10px; color: #555; word-wrap: break-word; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h1>Product Review (SECURE VERSION)</h1>
                    <div class='security-info'>
                        PROTECTED: HTML encoding with OWASP Encoder + Content Security Policy
                    </div>
                    <div class='review'>
                        <div class='name'>%s</div>
                        <div class='content'>%s</div>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(safeName, safeReview);
    }
}
