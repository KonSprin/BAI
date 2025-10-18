package com.security.lab;

import org.json.JSONObject;
import org.json.JSONException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.HashSet;
import javax.management.StringValueExp;

// Interface
interface VulnerabilityLogic {
    String process(String userInput, EnvironmentContext context) throws Exception;
}

// // Klasa kontekstu
// class EnvironmentContext {
//     // Kontekst środowiska (na potrzeby demo)
// }

// Główna klasa z podatnością
public class Fixed_Trust_Boundry_Konrad_Springer implements VulnerabilityLogic {
    
    // Bezpieczeństwo dawki
    private static final int MAX_SNGLE_DOSAGE = 100;
    private static final int MAX_DAILY_DOSAGE = 1000;
    private static final int MIN_DOSAGE = 0;

    // Walidacja wejścia
    private static final int MAX_JSON_LENGTH = 10000;
    private static final Pattern SAFE_ITEM_NAME = Pattern.compile("^[a-zA-Z0-9_-]{1,50}$");
    private static final Set<String> ALLOWED_JSON_FIELDS = Set.of("patient", "dosage_mg", "medication", "nonce");
    
    // Rate limiting
    private final RateLimiter rateLimiter = new RateLimiter(10, 60); // 10 req/min per user
    
    // Anti-replay attack
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();
    private static final long NONCE_EXPIRY_SECONDS = 300; // 5 minut
    
    // Katalog pacjentów (w produkcji z bazy danych)
    private static final Map<String, Patient> PATIENT_CATALOG = new ConcurrentHashMap<>();
    
    static {
        PATIENT_CATALOG.put("1", new Patient(
            1,
            "Jan Kowalski",
            Set.of("paracetamol", "aspiryna"),
            0,
            true
        ));
        PATIENT_CATALOG.put("2", new Patient(
            2,
            "Anna Nowak",
            Set.of("paracetamol", "morfina"),
            10,
            true
        ));
        PATIENT_CATALOG.put("2", new Patient(
            2,
            "Andrzej Suchy",
            Set.of("paracetamol"),
            0,
            false // Wypisany ze szpitala
        ));
    }

    // Klucz do podpisywania (w produkcji z secure vault)
    private static final String HMAC_KEY = getHmacKey();
    
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        try {
            // 1. Walidacja długości wejścia
            if (userInput == null || userInput.length() > MAX_JSON_LENGTH) {
                return createErrorResponse("INVALID_INPUT", "Input too large or null");
            }

            // 2. Rate limiting
            String userId = context.getString("userId", "anonymous");
            if (!rateLimiter.allowRequest(userId)) {
                return createErrorResponse("RATE_LIMIT", "Too many requests");
            }

            // 3. Bezpieczne parsowanie JSON
            OrderRequest request = parseAndValidateJson(userInput);
            
            // 4. Sprawdzenie nonce (ochrona przed replay attack)
            if (!validateNonce(request.nonce)) {
                return createErrorResponse("INVALID_NONCE", "Duplicate or expired request");
            }

            // 5. Walidacja dostępności pacjęta (czy nie został wypisany ze szpitala)

            // 6. Walidacja leku (czy można podać pacjentowi)
            
            // 7. Obliczanie dawki po podaniu

            // 8. Utworzenie zlecenia podania leku
            
            // 9. Aktualizacja leków podanych pacjentowi
            
            // 10. Zwróć podpisaną odpowiedź

        } catch (Exception e) {
        }        
        JSONObject json = new JSONObject(userInput);
        
        // BŁĄD: Bezpośrednie użycie danych medycznych bez walidacji
        // Użytkownik może podać:
        // - Ujemną dawkę leku
        // - Zero mg (brak leku)
        // - Dawkę przekraczającą bezpieczne limity (np. 100000 mg zamiast 100 mg)
        // - Nieprawidłowe dane pacjenta
        String patientName = json.getString("patient");
        double dosageMg = json.getDouble("dosage_mg");
        String medication = json.getString("medication");
        
        // Symulacja zapisania informacji o podaniu leku
        // NIEBEZPIECZNE: Brak walidacji czy dawka jest w bezpiecznym zakresie!
        String result = "Medication administered: " + medication + 
                       "\nPatient: " + patientName + 
                       "\nDosage: " + dosageMg + " mg";
        
        return result;
    }

    /**
     * Bezpieczne parsowanie i walidacja JSON
     */
    private OrderRequest parseAndValidateJson(String jsonString) throws JSONException {
        JSONObject json = new JSONObject(jsonString);

        // Sprawdź czy nie ma nieoczekiwanych pól

        // Pobierz i zwaliduj pole patient
        String patientName = json.getString("patient").trim().toLowerCase();
        
        // Pobierz i zwaliduj dosage_mg
        int dosage_mg = json.optInt("dosage_mg", 1);
        
        // Pobierz i zwaliduj medication
        String medication = json.getString("medication").trim().toLowerCase();

        // Nonce dla ochrony przed replay
        String nonce = json.optString("nonce", UUID.randomUUID().toString());
        
        return new OrderRequest(patientName, dosage_mg, medication, nonce);
    }

    /**
     * Walidacja nonce
     */
    private boolean validateNonce(String nonce) {
        if (nonce == null || nonce.isEmpty()) {
            return false;
        }
        
        // Sprawdź czy nonce był już użyty
        if (!usedNonces.add(nonce)) {
            return false; // Nonce już użyty
        }
        
        // Wyczyść stare nonce (w produkcji użyj scheduled task)
        cleanupOldNonces();
        
        return true;
    }
    
    /**
     * Czyszczenie starych nonce
     */
    private void cleanupOldNonces() {
        // W produkcji: użyj Redis z TTL lub scheduled cleanup
        if (usedNonces.size() > 10000) {
            usedNonces.clear(); // Uproszczone dla przykładu
        }
    }
    
    /**
     * Tworzenie odpowiedzi błędu
     */
    private String createErrorResponse(String code, String message) {
        JSONObject error = new JSONObject();
        error.put("error", true);
        error.put("code", code);
        error.put("message", message);
        error.put("timestamp", Instant.now().toEpochMilli());
        return error.toString();
    }

    /**
     * Generowanie HMAC
     */
    private String generateHmac(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
            HMAC_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
        );
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);
    }
    
    /**
     * Pobieranie klucza HMAC
     */
    private static String getHmacKey() {
        String key = System.getenv("ORDER_HMAC_KEY");
        if (key == null || key.isEmpty()) {
            // Tylko dla development - NIGDY w produkcji!
            return "dev-key-change-in-production";
        }
        return key;
    }

    // Klasy pomocnicze
    
    private static class Patient {
        int id;
        String name;
        Set<String> allowed_medications;
        int dosage_applied; // Sum of all medications
        boolean available;
        
        Patient(int id, String name, Set allowed_medications, int dosage_applied, boolean available) {
            this.id = id;
            this.name = name;
            this.allowed_medications = allowed_medications;
            this.dosage_applied = dosage_applied;
            this.available = available;
        }
    }

    private record OrderRequest(String itemName, int quantity, String coupon, String nonce) {}
    

    private class RateLimiter {
        private final Map<String, Long> lastRequest = new ConcurrentHashMap<>();
        private final int maxRequests;
        private final int windowSeconds;
        
        RateLimiter(int maxRequests, int windowSeconds) {
            this.maxRequests = maxRequests;
            this.windowSeconds = windowSeconds;
        }
        
        synchronized boolean allowRequest(String userId) {
            long now = System.currentTimeMillis();
            Long last = lastRequest.get(userId);
            
            if (last == null || (now - last) > windowSeconds * 1000) {
                lastRequest.put(userId, now);
                return true;
            }
            
            return false;
        }
    }
}

/*
PRZYKŁAD ATAKU - użytkownik może wysłać JSON:
{
    "patient": "Jan Kowalski",
    "medication": "Paracetamol",
    "dosage_mg": -500
}

lub:

{
    "patient": "'; DROP TABLE patients; --",
    "medication": "Morfina",
    "dosage_mg": 999999
}

BRAK WALIDACJI:
- Czy dawka jest dodatnia
- Czy dawka mieści się w bezpiecznym zakresie (np. 0-1000 mg)
- Czy nazwa pacjenta nie zawiera złośliwych znaków
- Czy lek istnieje w bazie zatwierdzonych leków
- Czy użytkownik ma uprawnienia do podawania tego leku
*/
