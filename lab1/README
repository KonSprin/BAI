# Trust Boundary 

```

~/Projects/BAI/lab1/trust_boundary$ mvn clean compile exec:java
[INFO] Scanning for projects...
[INFO] 
[INFO] -------------< com.security.lab:medical-app-vulnerability >-------------
[INFO] Building Medical App - Trust Boundary Violation Demo 1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[INFO] --- clean:3.2.0:clean (default-clean) @ medical-app-vulnerability ---
[INFO] 
[INFO] --- resources:3.3.1:resources (default-resources) @ medical-app-vulnerability ---
[INFO] skip non existing resourceDirectory /home/konrad/Projects/BAI/lab1/trust_boundary/src/main/resources
[INFO] 
[INFO] --- compiler:3.13.0:compile (default-compile) @ medical-app-vulnerability ---
[INFO] Recompiling the module because of changed source code.
[INFO] Compiling 3 source files with javac [debug target 21] to target/classes
[INFO] 
[INFO] --- exec:3.4.1:java (default-cli) @ medical-app-vulnerability ---
## MEDICAL APP SECURITY TEST - TRUST BOUNDARY VIOLATION
│ TEST 1: VALID INPUT - Proper medication dosage
🔓 VULNERABLE VERSION Input: {"patient":"Jan Kowalski","medication":"paracetamol","dosage_mg":500}
Medication administered: paracetamol
Patient: Jan Kowalski
Dosage: 500.0 mg
✅ Expected: Valid input accepted

🔒 SECURE VERSION Input: {"patient_id":"1","medication":"paracetamol","dosage_mg":500,"nonce":"nonce001"}
{"patientName":"Jan Kowalski","orderId":"9b26d299-c7ff-4701-a049-71725f0b5efd","patientId":"1","signature":"_famh4fbRg8odwkarwi9XuRIQ5Tio45TF1L-CadBpUo","dosage_mg":500,"medication":"Paracetamol","administeredBy":"doctor_123","status":"ADMINISTERED","timestamp":1760815581391}
✅ PASS: Valid input accepted

=================================================================

│ TEST 2: ATTACK - Negative dosage
🔓 VULNERABLE VERSION Input: {"patient":"Anna Nowak","medication":"morfina","dosage_mg":-500}
Medication administered: morfina
Patient: Anna Nowak
Dosage: -500.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"2","medication":"morfina","dosage_mg":-500,"nonce":"nonce002"}
{"code":"INVALID_DOSAGE","error":true,"message":"Dosage must be between 1 and 1000 mg","timestamp":1760815581525}
✅ PASS: Attack blocked with correct error code (INVALID_DOSAGE)

=================================================================

│ TEST 3: ATTACK - Lethal dosage (999999 mg)
🔓 VULNERABLE VERSION Input: {"patient":"Piotr Wiśniewski","medication":"paracetamol","dosage_mg":999999}
Medication administered: paracetamol
Patient: Piotr Wiśniewski
Dosage: 999999.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"1","medication":"paracetamol","dosage_mg":999999,"nonce":"nonce003"}
{"code":"INVALID_DOSAGE","error":true,"message":"Dosage must be between 1 and 1000 mg","timestamp":1760815581628}
✅ PASS: Attack blocked with correct error code (INVALID_DOSAGE)

=================================================================

│ TEST 4: ATTACK - Overdose of morphine (50mg > 15mg max)
🔓 VULNERABLE VERSION Input: {"patient":"Anna Nowak","medication":"morfina","dosage_mg":50}
Medication administered: morfina
Patient: Anna Nowak
Dosage: 50.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"2","medication":"morfina","dosage_mg":50,"nonce":"nonce004"}
{"code":"DOSAGE_TOO_HIGH","error":true,"message":"Dosage exceeds maximum single dose for Morfina (15 mg)","timestamp":1760815581731}
✅ PASS: Attack blocked with correct error code (DOSAGE_TOO_HIGH)

=================================================================

│ TEST 5: ATTACK - SQL Injection in patient name
🔓 VULNERABLE VERSION Input: {"patient":"'; DROP TABLE patients; --","medication":"paracetamol","dosage_mg":500}
Medication administered: paracetamol
Patient: '; DROP TABLE patients; --
Dosage: 500.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"'; DROP TABLE patients; --","medication":"paracetamol","dosage_mg":500,"nonce":"nonce005"}
{"code":"INVALID_PATIENT_ID","error":true,"message":"Invalid patient ID format","timestamp":1760815581832}
✅ PASS: Attack blocked with correct error code (INVALID_PATIENT_ID)

=================================================================

│ TEST 6: ATTACK - Unauthorized medication for patient
Note: Patient #1 (Jan Kowalski) is NOT authorized to receive morphine

🔓 VULNERABLE VERSION Input: {"patient":"Jan Kowalski","medication":"morfina","dosage_mg":10}
Medication administered: morfina
Patient: Jan Kowalski
Dosage: 10.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"1","medication":"morfina","dosage_mg":10,"nonce":"nonce006"}
{"code":"MEDICATION_NOT_ALLOWED","error":true,"message":"Patient is not authorized to receive Morfina","timestamp":1760815581935}
✅ PASS: Attack blocked with correct error code (MEDICATION_NOT_ALLOWED)

=================================================================

│ TEST 7: ATTACK - Replay attack (duplicate nonce)
Note: Using the same nonce as TEST 1 (nonce001)

🔓 VULNERABLE VERSION Input: {"patient":"Jan Kowalski","medication":"paracetamol","dosage_mg":500}
Medication administered: paracetamol
Patient: Jan Kowalski
Dosage: 500.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"1","medication":"paracetamol","dosage_mg":500,"nonce":"nonce001"}
{"code":"INVALID_NONCE","error":true,"message":"Duplicate or expired request","timestamp":1760815582037}
✅ PASS: Attack blocked with correct error code (INVALID_NONCE)

=================================================================

│ TEST 8: ATTACK - Discharged patient
Note: Patient #3 (Andrzej Suchy) has been discharged

🔓 VULNERABLE VERSION Input: {"patient":"Andrzej Suchy","medication":"paracetamol","dosage_mg":500}
Medication administered: paracetamol
Patient: Andrzej Suchy
Dosage: 500.0 mg
⚠️  VULNERABILITY: Attack was accepted (expected behavior for vulnerable version)

🔒 SECURE VERSION Input: {"patient_id":"3","medication":"paracetamol","dosage_mg":500,"nonce":"nonce007"}
{"code":"PATIENT_UNAVAILABLE","error":true,"message":"Patient has been discharged or is unavailable","timestamp":1760815582139}
✅ PASS: Attack blocked with correct error code (PATIENT_UNAVAILABLE)

╔═══════════════════════════════════════════════════════════════╗
║                      TEST SUMMARY                             ║
╠═══════════════════════════════════════════════════════════════╣
║ 🔓 VULNERABLE VERSION:  1 PASSED / 7 FAILED (Total: 8)      ║
║ 🔒 SECURE VERSION:      8 PASSED / 0 FAILED (Total: 8)      ║
╠═══════════════════════════════════════════════════════════════╣
║ ⚠️  Vulnerable version: INSECURE (accepts attacks)            ║
║ ✅ Secure version: ALL TESTS PASSED                           ║
╠═══════════════════════════════════════════════════════════════╣
║ Security mechanisms in SECURE version:                        ║
║ • Dosage validation (min/max limits)                          ║
║ • Medication-specific dosage limits                            ║
║ • Patient authorization checking                               ║
║ • Patient status validation (discharged)                       ║
║ • Input sanitization (SQL injection prevention)                ║
║ • Replay attack protection (nonce)                             ║
║ • Rate limiting (10 requests/minute)                           ║
║ • HMAC signatures for response integrity                       ║
╚═══════════════════════════════════════════════════════════════╝
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  2.435 s
[INFO] Finished at: 2025-10-18T21:26:22+02:00
[INFO] ------------------------------------------------------------------------
```