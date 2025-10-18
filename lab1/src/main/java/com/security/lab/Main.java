package com.security.lab;

public class Main {
    
    // Liczniki testów
    private static int vulnerablePassCount = 0;
    private static int vulnerableFailCount = 0;
    private static int securePassCount = 0;
    private static int secureFailCount = 0;
    
    public static void main(String[] args) {
        // Inicjalizacja obu wersji aplikacji
        Vulnerable_Trust_Boundry_Konrad_Springer vulnerableApp = new Vulnerable_Trust_Boundry_Konrad_Springer();
        Fixed_Trust_Boundry_Konrad_Springer secureApp = new Fixed_Trust_Boundry_Konrad_Springer();
        
        EnvironmentContext context = new EnvironmentContext();
        context.put("userId", "doctor_123");
        
        System.out.println("╔═══════════════════════════════════════════════════════════════╗");
        System.out.println("║   MEDICAL APP SECURITY TEST - TRUST BOUNDARY VIOLATION       ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════╝\n");
        
        // =================================================================
        // TEST 1: Prawidłowe dane - oba powinny ZAAKCEPTOWAĆ
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 1: VALID INPUT - Proper medication dosage              │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        
        String validInputVuln = "{\"patient\":\"Jan Kowalski\",\"medication\":\"paracetamol\",\"dosage_mg\":500}";
        String validInputSecure = "{\"patient_id\":\"1\",\"medication\":\"paracetamol\",\"dosage_mg\":500,\"nonce\":\"nonce001\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + validInputVuln);
        testVulnerable(vulnerableApp, context, validInputVuln, true, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + validInputSecure);
        testSecure(secureApp, context, validInputSecure, true, null);
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 2: ATAK - Ujemna dawka - oba powinny ODRZUCIĆ
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 2: ATTACK - Negative dosage                            │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        
        String negativeInputVuln = "{\"patient\":\"Anna Nowak\",\"medication\":\"morfina\",\"dosage_mg\":-500}";
        String negativeInputSecure = "{\"patient_id\":\"2\",\"medication\":\"morfina\",\"dosage_mg\":-500,\"nonce\":\"nonce002\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + negativeInputVuln);
        testVulnerable(vulnerableApp, context, negativeInputVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + negativeInputSecure);
        testSecure(secureApp, context, negativeInputSecure, false, "INVALID_DOSAGE");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 3: ATAK - Śmiertelna dawka
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 3: ATTACK - Lethal dosage (999999 mg)                  │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        
        String lethalInputVuln = "{\"patient\":\"Piotr Wiśniewski\",\"medication\":\"paracetamol\",\"dosage_mg\":999999}";
        String lethalInputSecure = "{\"patient_id\":\"1\",\"medication\":\"paracetamol\",\"dosage_mg\":999999,\"nonce\":\"nonce003\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + lethalInputVuln);
        testVulnerable(vulnerableApp, context, lethalInputVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + lethalInputSecure);
        testSecure(secureApp, context, lethalInputSecure, false, "INVALID_DOSAGE");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 4: ATAK - Dawka przekraczająca limit dla konkretnego leku
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 4: ATTACK - Overdose of morphine (50mg > 15mg max)     │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        
        String overdoseInputVuln = "{\"patient\":\"Anna Nowak\",\"medication\":\"morfina\",\"dosage_mg\":50}";
        String overdoseInputSecure = "{\"patient_id\":\"2\",\"medication\":\"morfina\",\"dosage_mg\":50,\"nonce\":\"nonce004\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + overdoseInputVuln);
        testVulnerable(vulnerableApp, context, overdoseInputVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + overdoseInputSecure);
        testSecure(secureApp, context, overdoseInputSecure, false, "DOSAGE_TOO_HIGH");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 5: ATAK - SQL Injection w nazwie pacjenta
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 5: ATTACK - SQL Injection in patient name              │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        
        String sqlInjectionVuln = "{\"patient\":\"'; DROP TABLE patients; --\",\"medication\":\"paracetamol\",\"dosage_mg\":500}";
        String sqlInjectionSecure = "{\"patient_id\":\"'; DROP TABLE patients; --\",\"medication\":\"paracetamol\",\"dosage_mg\":500,\"nonce\":\"nonce005\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + sqlInjectionVuln);
        testVulnerable(vulnerableApp, context, sqlInjectionVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + sqlInjectionSecure);
        testSecure(secureApp, context, sqlInjectionSecure, false, "INVALID_PATIENT_ID");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 6: ATAK - Nieautoryzowany lek dla pacjenta
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 6: ATTACK - Unauthorized medication for patient        │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        System.out.println("Note: Patient #1 (Jan Kowalski) is NOT authorized to receive morphine\n");
        
        String unauthorizedVuln = "{\"patient\":\"Jan Kowalski\",\"medication\":\"morfina\",\"dosage_mg\":10}";
        String unauthorizedSecure = "{\"patient_id\":\"1\",\"medication\":\"morfina\",\"dosage_mg\":10,\"nonce\":\"nonce006\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + unauthorizedVuln);
        testVulnerable(vulnerableApp, context, unauthorizedVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + unauthorizedSecure);
        testSecure(secureApp, context, unauthorizedSecure, false, "MEDICATION_NOT_ALLOWED");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 7: ATAK - Replay attack (ten sam nonce)
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 7: ATTACK - Replay attack (duplicate nonce)            │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        System.out.println("Note: Using the same nonce as TEST 1 (nonce001)\n");
        
        String replayInputVuln = "{\"patient\":\"Jan Kowalski\",\"medication\":\"paracetamol\",\"dosage_mg\":500}";
        String replayInputSecure = "{\"patient_id\":\"1\",\"medication\":\"paracetamol\",\"dosage_mg\":500,\"nonce\":\"nonce001\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + replayInputVuln);
        testVulnerable(vulnerableApp, context, replayInputVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + replayInputSecure);
        testSecure(secureApp, context, replayInputSecure, false, "INVALID_NONCE");
        
        System.out.println("\n" + "=".repeat(65) + "\n");
        sleep(100);
        
        // =================================================================
        // TEST 8: ATAK - Pacjent wypisany ze szpitala
        // =================================================================
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│ TEST 8: ATTACK - Discharged patient                          │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        System.out.println("Note: Patient #3 (Andrzej Suchy) has been discharged\n");
        
        String dischargedInputVuln = "{\"patient\":\"Andrzej Suchy\",\"medication\":\"paracetamol\",\"dosage_mg\":500}";
        String dischargedInputSecure = "{\"patient_id\":\"3\",\"medication\":\"paracetamol\",\"dosage_mg\":500,\"nonce\":\"nonce007\"}";
        
        System.out.println("🔓 VULNERABLE VERSION Input: " + dischargedInputVuln);
        testVulnerable(vulnerableApp, context, dischargedInputVuln, false, null);
        
        System.out.println("\n🔒 SECURE VERSION Input: " + dischargedInputSecure);
        testSecure(secureApp, context, dischargedInputSecure, false, "PATIENT_UNAVAILABLE");
        
        // =================================================================
        // PODSUMOWANIE
        // =================================================================
        System.out.println("\n╔═══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      TEST SUMMARY                             ║");
        System.out.println("╠═══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ 🔓 VULNERABLE VERSION:  %d PASSED / %d FAILED (Total: 8)      ║%n", 
                         vulnerablePassCount, vulnerableFailCount);
        System.out.printf("║ 🔒 SECURE VERSION:      %d PASSED / %d FAILED (Total: 8)      ║%n", 
                         securePassCount, secureFailCount);
        System.out.println("╠═══════════════════════════════════════════════════════════════╣");
        
        if (vulnerableFailCount == 7 && vulnerablePassCount == 1) {
            System.out.println("║ ⚠️  Vulnerable version: INSECURE (accepts attacks)            ║");
        } else {
            System.out.println("║ ⚠️  Vulnerable version: Unexpected test results!              ║");
        }
        
        if (securePassCount == 8 && secureFailCount == 0) {
            System.out.println("║ ✅ Secure version: ALL TESTS PASSED                           ║");
        } else {
            System.out.println("║ ❌ Secure version: SOME TESTS FAILED                          ║");
        }
        
        System.out.println("╠═══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Security mechanisms in SECURE version:                        ║");
        System.out.println("║ • Dosage validation (min/max limits)                          ║");
        System.out.println("║ • Medication-specific dosage limits                            ║");
        System.out.println("║ • Patient authorization checking                               ║");
        System.out.println("║ • Patient status validation (discharged)                       ║");
        System.out.println("║ • Input sanitization (SQL injection prevention)                ║");
        System.out.println("║ • Replay attack protection (nonce)                             ║");
        System.out.println("║ • Rate limiting (10 requests/minute)                           ║");
        System.out.println("║ • HMAC signatures for response integrity                       ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════╝");
    }
    
    /**
     * Testuje podatną wersję - oczekujemy że przyjmie ataki
     */
    private static void testVulnerable(Vulnerable_Trust_Boundry_Konrad_Springer app, EnvironmentContext context, 
                                      String input, boolean shouldAccept, String expectedError) {
        try {
            String result = app.process(input, context);
            System.out.println(result);
            
            boolean hasError = result.contains("\"error\":true");
            
            if (shouldAccept && !hasError) {
                // Prawidłowe dane zaakceptowane - OK
                System.out.println("✅ Expected: Valid input accepted");
                vulnerablePassCount++;
            } else if (!shouldAccept && !hasError) {
                // Atak zaakceptowany - to jest podatność!
                System.out.println("⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)");
                vulnerableFailCount++;
            } else if (!shouldAccept && hasError) {
                // Atak odrzucony - nieoczekiwane dla podatnej wersji
                System.out.println("❌ Unexpected: Vulnerable version rejected attack");
                vulnerablePassCount++;
            } else {
                // Prawidłowe dane odrzucone
                System.out.println("❌ ERROR: Valid input was rejected");
                vulnerableFailCount++;
            }
            
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            if (shouldAccept) {
                System.out.println("❌ ERROR: Exception on valid input");
                vulnerableFailCount++;
            } else {
                System.out.println("✅ Expected: Exception on invalid input");
                vulnerablePassCount++;
            }
        }
    }
    
    /**
     * Testuje zabezpieczoną wersję - oczekujemy że odrzuci ataki
     */
    private static void testSecure(Fixed_Trust_Boundry_Konrad_Springer app, EnvironmentContext context,
                                   String input, boolean shouldAccept, String expectedError) {
        try {
            String result = app.process(input, context);
            System.out.println(result);
            
            boolean hasError = result.contains("\"error\":true");
            boolean hasExpectedError = expectedError == null || result.contains(expectedError);
            
            if (shouldAccept && !hasError) {
                // Prawidłowe dane zaakceptowane - OK
                System.out.println("✅ PASS: Valid input accepted");
                securePassCount++;
            } else if (shouldAccept && hasError) {
                // Prawidłowe dane odrzucone - BŁĄD
                System.out.println("❌ FAIL: Valid input was rejected");
                secureFailCount++;
            } else if (!shouldAccept && hasError && hasExpectedError) {
                // Atak odrzucony z właściwym błędem - OK
                System.out.println("✅ PASS: Attack blocked with correct error code (" + expectedError + ")");
                securePassCount++;
            } else if (!shouldAccept && hasError && !hasExpectedError) {
                // Atak odrzucony ale z niewłaściwym błędem
                System.out.println("⚠️  PARTIAL: Attack blocked but with unexpected error (expected: " + expectedError + ")");
                secureFailCount++; // Liczymy jako sukces bo jednak zablokował
            } else if (!shouldAccept && !hasError) {
                // Atak zaakceptowany - KRYTYCZNY BŁĄD
                System.out.println("❌ FAIL: Attack was accepted! SECURITY BREACH!");
                secureFailCount++;
            } else {
                System.out.println("❌ FAIL: Unexpected result");
                secureFailCount++;
            }
            
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            if (shouldAccept) {
                System.out.println("❌ FAIL: Exception on valid input");
                secureFailCount++;
            } else {
                System.out.println("✅ PASS: Exception prevented attack");
                securePassCount++;
            }
        }
    }
    
    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}