package com.security.lab;

public class Main {
    public static void main(String[] args) {
        Vulnerable_Trust_Boundry_Konrad_Springer app = new Vulnerable_Trust_Boundry_Konrad_Springer();
        EnvironmentContext context = new EnvironmentContext();
        
        // Przykład 1: Prawidłowe dane
        String validInput = "{\"patient\":\"Jan Kowalski\",\"medication\":\"Paracetamol\",\"dosage_mg\":500}";
        
        // Przykład 2: ATAK - ujemna dawka
        String attackInput1 = "{\"patient\":\"Anna Nowak\",\"medication\":\"Morfina\",\"dosage_mg\":-500}";
        
        // Przykład 3: ATAK - śmiertelna dawka
        String attackInput2 = "{\"patient\":\"Piotr Wiśniewski\",\"medication\":\"Paracetamol\",\"dosage_mg\":999999}";
        
        try {
            System.out.println("=== TEST 1: Prawidłowe dane ===");
            System.out.println(app.process(validInput, context));
            System.out.println();
            
            System.out.println("=== TEST 2: ATAK - Ujemna dawka ===");
            System.out.println(app.process(attackInput1, context));
            System.out.println("PODATNOŚĆ: System zaakceptował ujemną dawkę!");
            System.out.println();
            
            System.out.println("=== TEST 3: ATAK - Śmiertelna dawka ===");
            System.out.println(app.process(attackInput2, context));
            System.out.println("PODATNOŚĆ: System zaakceptował śmiertelnie wysoką dawkę!");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
