package com.security.lab;

import org.json.JSONObject;

// // Interface
// interface VulnerabilityLogic {
//     String process(String userInput, EnvironmentContext context) throws Exception;
// }

// // Klasa kontekstu
// class EnvironmentContext {
//     // Kontekst środowiska (na potrzeby demo)
// }

// Główna klasa z podatnością
public class Vulnerable_Trust_Boundry_Konrad_Springer implements VulnerabilityLogic {
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        // PODATNA IMPLEMENTACJA: Bezpośrednie zaufanie dawce leku z JSON (CWE-501)
        
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
