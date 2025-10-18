import org.json.JSONObject;

public class VulnerableMedicalApp implements VulnerabilityLogic {
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        // PODATNA IMPLEMENTACJA: Bezpośrednie zaufanie dawce leku z JSON (CWE-501)
        
        // Parsowanie JSON od użytkownika
        JSONObject json = new JSONObject(userInput);
        
        // BŁĄD: Bezpośrednie użycie danych medycznych z JSON bez walidacji
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
