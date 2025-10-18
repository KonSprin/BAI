package com.security.lab;

import org.json.JSONObject;
import org.json.JSONException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Set;
import java.nio.charset.StandardCharsets;

// Interface
interface VulnerabilityLogic {
    String process(String userInput, EnvironmentContext context) throws Exception;
}

// Klasa kontekstu
class EnvironmentContext {
    private final Map<String, String> context = new ConcurrentHashMap<>();
    
    public String getString(String key, String defaultValue) {
        return context.getOrDefault(key, defaultValue);
    }
    
    public void put(String key, String value) {
        context.put(key, value);
    }
}

// Zabezpieczona klasa do podawania leków
public class Fixed_Trust_Boundry_Konrad_Springer implements VulnerabilityLogic {
    
    // Bezpieczeństwo dawki
    private static final int MAX_SINGLE_DOSAGE = 1000;  // 1000mg max pojedyncza dawka
    private static final int MAX_DAILY_DOSAGE = 4000;   // 4000mg max dzienna dawka
    private static final int MIN_DOSAGE = 1;             // minimum 1mg
    
    // Walidacja wejścia
    private static final int MAX_JSON_LENGTH = 10000;
    private static final Pattern SAFE_NAME = Pattern.compile("^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ\\s]{2,100}$");
    private static final Pattern SAFE_MEDICATION = Pattern.compile("^[a-zA-Z]{2,50}$");
    private static final Set<String> ALLOWED_JSON_FIELDS = Set.of("patient_id", "dosage_mg", "medication", "nonce");
    
    // Rate limiting
    private final RateLimiter rateLimiter = new RateLimiter(10, 60); // 10 req/min
    
    // Anti-replay attack
    private final Set<String> usedNonces = ConcurrentHashMap.newKeySet();
    private static final long NONCE_EXPIRY_SECONDS = 300; // 5 minut
    
    // Katalog pacjentów (w produkcji z bazy danych)
    private static final Map<String, Patient> PATIENT_CATALOG = new ConcurrentHashMap<>();
    
    // Katalog dozwolonych leków z maksymalnymi dawkami
    private static final Map<String, Medication> MEDICATION_CATALOG = new ConcurrentHashMap<>();
    
    static {
        // Inicjalizacja pacjentów
        PATIENT_CATALOG.put("1", new Patient(
            "1",
            "Jan Kowalski",
            Set.of("paracetamol", "aspiryna"),
            0,
            true
        ));
        PATIENT_CATALOG.put("2", new Patient(
            "2",
            "Anna Nowak",
            Set.of("paracetamol", "morfina"),
            500,
            true
        ));
        PATIENT_CATALOG.put("3", new Patient(
            "3",
            "Andrzej Suchy",
            Set.of("paracetamol"),
            0,
            false // Wypisany ze szpitala
        ));
        
        // Inicjalizacja leków z bezpiecznymi dawkami
        MEDICATION_CATALOG.put("paracetamol", new Medication(
            "paracetamol",
            "Paracetamol",
            1000,  // max single dose
            4000,  // max daily dose
            true
        ));
        MEDICATION_CATALOG.put("morfina", new Medication(
            "morfina",
            "Morfina",
            15,    // max single dose
            60,    // max daily dose
            true
        ));
        MEDICATION_CATALOG.put("aspiryna", new Medication(
            "aspiryna",
            "Aspiryna",
            500,
            3000,
            true
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
            MedicationRequest request = parseAndValidateJson(userInput);
            
            // 4. Sprawdzenie nonce (ochrona przed replay attack)
            if (!validateNonce(request.nonce)) {
                return createErrorResponse("INVALID_NONCE", "Duplicate or expired request");
            }
            
            // 5. Walidacja dostępności pacjenta
            Patient patient = validatePatient(request.patientId);
            
            // 6. Walidacja leku
            Medication medication = validateMedication(request.medicationName);
            
            // 7. Sprawdź czy pacjent może otrzymać ten lek
            validatePatientMedication(patient, medication);
            
            // 8. Walidacja dawki
            validateDosage(request.dosageMg, medication, patient);
            
            // 9. Utworzenie zlecenia podania leku
            MedicationOrder order = createMedicationOrder(userId, patient, medication, request.dosageMg);
            
            // 10. Aktualizacja leków podanych pacjentowi
            updatePatientDosage(patient, request.dosageMg);
            
            // 11. Zwróć podpisaną odpowiedź
            return createSecureResponse(order);
            
        } catch (ValidationException e) {
            return createErrorResponse(e.getCode(), e.getMessage());
        } catch (JSONException e) {
            return createErrorResponse("INVALID_JSON", "Malformed JSON input");
        } catch (Exception e) {
            // Loguj błąd ale nie ujawniaj szczegółów
            logError(e);
            return createErrorResponse("INTERNAL_ERROR", "Medication administration failed");
        }
    }
    
    /**
     * Bezpieczne parsowanie i walidacja JSON
     */
    private MedicationRequest parseAndValidateJson(String jsonString) throws JSONException {
        JSONObject json = new JSONObject(jsonString);
        
        // Sprawdź czy nie ma nieoczekiwanych pól
        for (String key : json.keySet()) {
            if (!ALLOWED_JSON_FIELDS.contains(key)) {
                throw new ValidationException("INVALID_FIELD", 
                    "Unexpected field in request: " + key);
            }
        }
        
        // Pobierz i zwaliduj pole patient_id
        String patientId = json.getString("patient_id").trim();
        if (patientId.isEmpty() || patientId.length() > 20) {
            throw new ValidationException("INVALID_PATIENT_ID", 
                "Invalid patient ID format");
        }
        
        // Pobierz i zwaliduj dosage_mg
        int dosageMg = json.getInt("dosage_mg");
        if (dosageMg < MIN_DOSAGE || dosageMg > MAX_SINGLE_DOSAGE) {
            throw new ValidationException("INVALID_DOSAGE", 
                "Dosage must be between " + MIN_DOSAGE + " and " + MAX_SINGLE_DOSAGE + " mg");
        }
        
        // Pobierz i zwaliduj medication
        String medication = json.getString("medication").trim().toLowerCase();
        if (!SAFE_MEDICATION.matcher(medication).matches()) {
            throw new ValidationException("INVALID_MEDICATION", 
                "Invalid medication name format");
        }
        
        // Nonce dla ochrony przed replay
        String nonce = json.optString("nonce", UUID.randomUUID().toString());
        
        return new MedicationRequest(patientId, dosageMg, medication, nonce);
    }
    
    /**
     * Walidacja pacjenta
     */
    private Patient validatePatient(String patientId) {
        Patient patient = PATIENT_CATALOG.get(patientId);
        
        if (patient == null) {
            throw new ValidationException("UNKNOWN_PATIENT", 
                "Patient not found: " + patientId);
        }
        
        if (!patient.available) {
            throw new ValidationException("PATIENT_UNAVAILABLE", 
                "Patient has been discharged or is unavailable");
        }
        
        return patient;
    }
    
    /**
     * Walidacja leku
     */
    private Medication validateMedication(String medicationName) {
        Medication medication = MEDICATION_CATALOG.get(medicationName);
        
        if (medication == null) {
            throw new ValidationException("UNKNOWN_MEDICATION", 
                "Medication not found: " + medicationName);
        }
        
        if (!medication.available) {
            throw new ValidationException("MEDICATION_UNAVAILABLE", 
                "Medication currently unavailable");
        }
        
        return medication;
    }
    
    /**
     * Sprawdź czy pacjent może otrzymać ten lek
     */
    private void validatePatientMedication(Patient patient, Medication medication) {
        if (!patient.allowedMedications.contains(medication.id)) {
            throw new ValidationException("MEDICATION_NOT_ALLOWED", 
                "Patient is not authorized to receive " + medication.name);
        }
    }
    
    /**
     * Walidacja dawki
     */
    private void validateDosage(int dosageMg, Medication medication, Patient patient) {
        // Sprawdź czy dawka nie przekracza maksymalnej pojedynczej dawki dla leku
        if (dosageMg > medication.maxSingleDose) {
            throw new ValidationException("DOSAGE_TOO_HIGH", 
                String.format("Dosage exceeds maximum single dose for %s (%d mg)", 
                    medication.name, medication.maxSingleDose));
        }
        
        // Sprawdź czy suma dziennych dawek nie przekroczy limitu
        int totalDailyDosage = patient.dosageAppliedToday + dosageMg;
        if (totalDailyDosage > medication.maxDailyDose) {
            throw new ValidationException("DAILY_LIMIT_EXCEEDED", 
                String.format("Daily dosage limit exceeded for %s. Current: %d mg, Requested: %d mg, Max: %d mg", 
                    medication.name, patient.dosageAppliedToday, dosageMg, medication.maxDailyDose));
        }
        
        // Sprawdź globalny dzienny limit
        if (totalDailyDosage > MAX_DAILY_DOSAGE) {
            throw new ValidationException("GLOBAL_DAILY_LIMIT", 
                "Total daily medication dosage limit exceeded");
        }
    }
    
    /**
     * Utworzenie zlecenia podania leku
     */
    private MedicationOrder createMedicationOrder(String userId, Patient patient, 
                                                   Medication medication, int dosageMg) {
        return new MedicationOrder(
            UUID.randomUUID().toString(),
            patient.id,
            patient.name,
            medication.id,
            medication.name,
            dosageMg,
            userId,
            Instant.now().toEpochMilli(),
            "ADMINISTERED"
        );
    }
    
    /**
     * Aktualizacja dawki leku podanej pacjentowi
     */
    private synchronized void updatePatientDosage(Patient patient, int dosageMg) {
        patient.dosageAppliedToday += dosageMg;
        // W produkcji: zapisz do bazy danych z timestampem
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
            return false; // Nonce już użyty - replay attack!
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
     * Tworzenie podpisanej odpowiedzi
     */
    private String createSecureResponse(MedicationOrder order) throws Exception {
        JSONObject response = new JSONObject();
        response.put("orderId", order.orderId);
        response.put("patientId", order.patientId);
        response.put("patientName", order.patientName);
        response.put("medication", order.medicationName);
        response.put("dosage_mg", order.dosageMg);
        response.put("status", order.status);
        response.put("timestamp", order.timestamp);
        response.put("administeredBy", order.administeredBy);
        
        // Dodaj podpis HMAC dla integralności
        String signature = generateHmac(response.toString());
        response.put("signature", signature);
        
        return response.toString();
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
        String key = System.getenv("MEDICATION_HMAC_KEY");
        if (key == null || key.isEmpty()) {
            // Tylko dla development - NIGDY w produkcji!
            return "dev-medical-key-change-in-production";
        }
        return key;
    }
    
    /**
     * Logowanie błędów
     */
    private void logError(Exception e) {
        // W produkcji użyj właściwego loggera (Log4j, SLF4J)
        System.err.println("Medication administration error: " + e.getClass().getSimpleName());
    }
    
    // ============= KLASY POMOCNICZE =============
    
    /**
     * Klasa reprezentująca pacjenta
     */
    private static class Patient {
        String id;
        String name;
        Set<String> allowedMedications;
        int dosageAppliedToday; // Suma wszystkich leków podanych dzisiaj
        boolean available;
        
        Patient(String id, String name, Set<String> allowedMedications, 
                int dosageAppliedToday, boolean available) {
            this.id = id;
            this.name = name;
            this.allowedMedications = allowedMedications;
            this.dosageAppliedToday = dosageAppliedToday;
            this.available = available;
        }
    }
    
    /**
     * Klasa reprezentująca lek
     */
    private static class Medication {
        String id;
        String name;
        int maxSingleDose;  // Maksymalna pojedyncza dawka w mg
        int maxDailyDose;   // Maksymalna dzienna dawka w mg
        boolean available;
        
        Medication(String id, String name, int maxSingleDose, 
                   int maxDailyDose, boolean available) {
            this.id = id;
            this.name = name;
            this.maxSingleDose = maxSingleDose;
            this.maxDailyDose = maxDailyDose;
            this.available = available;
        }
    }
    
    /**
     * Żądanie podania leku
     */
    private record MedicationRequest(String patientId, int dosageMg, 
                                     String medicationName, String nonce) {}
    
    /**
     * Zlecenie podania leku
     */
    private record MedicationOrder(String orderId, String patientId, String patientName,
                                   String medicationId, String medicationName, int dosageMg,
                                   String administeredBy, long timestamp, String status) {}
    
    /**
     * Wyjątek walidacji
     */
    private class ValidationException extends RuntimeException {
        private final String code;
        
        ValidationException(String code, String message) {
            super(message);
            this.code = code;
        }
        
        String getCode() {
            return code;
        }
    }
    
    /**
     * Rate Limiter - ograniczanie liczby żądań
     */
    private class RateLimiter {
        private final Map<String, RequestWindow> requestWindows = new ConcurrentHashMap<>();
        private final int maxRequests;
        private final int windowSeconds;
        
        RateLimiter(int maxRequests, int windowSeconds) {
            this.maxRequests = maxRequests;
            this.windowSeconds = windowSeconds;
        }
        
        synchronized boolean allowRequest(String userId) {
            long now = System.currentTimeMillis();
            RequestWindow window = requestWindows.get(userId);
            
            if (window == null) {
                // Pierwsze żądanie od tego użytkownika
                window = new RequestWindow(now);
                requestWindows.put(userId, window);
                return true;
            }
            
            // Sprawdź czy okno czasowe wygasło
            if (now - window.windowStart > windowSeconds * 1000) {
                // Reset okna
                window.windowStart = now;
                window.requestCount = 1;
                return true;
            }
            
            // Sprawdź czy nie przekroczono limitu
            if (window.requestCount < maxRequests) {
                window.requestCount++;
                return true;
            }
            
            return false; // Limit przekroczony
        }
        
        private class RequestWindow {
            long windowStart;
            int requestCount;
            
            RequestWindow(long windowStart) {
                this.windowStart = windowStart;
                this.requestCount = 1;
            }
        }
    }
}
