# XSS

```
=================================================================
       XSS SECURITY TEST - CROSS-SITE SCRIPTING
=================================================================

TEST 1: Valid input - Normal review
Input: {"name":"Jan Kowalski","review":"Great product, highly recommended!"}

VULNERABLE VERSION:
Generated: vulnerable_test1.html

SECURE VERSION:
Generated: secure_test1.html

=================================================================

TEST 2: XSS Attack - Script in name field
Input: {"name":"<script>alert('XSS')</script>","review":"Good product"}

VULNERABLE VERSION:
Generated: vulnerable_test2.html

SECURE VERSION:
Generated: secure_test2.html

=================================================================

TEST 3: XSS Attack - Image onerror in review
Input: {"name":"Jan Kowalski","review":"Nice<img src=x onerror='alert(1)'>product"}

VULNERABLE VERSION:
Generated: vulnerable_test3.html

SECURE VERSION:
Generated: secure_test3.html

=================================================================

TEST 4: XSS Attack - Iframe injection
Input: {"name":"Jan Hackerman","review":"<iframe src='javascript:alert(1)'></iframe>Check this out"}

VULNERABLE VERSION:
Generated: vulnerable_test4.html

SECURE VERSION:
Generated: secure_test4.html

=================================================================

TEST 5: XSS Attack - SVG onload
Input: {"name":"<svg/onload=alert('XSS')>","review":"Amazing!"}

VULNERABLE VERSION:
Generated: vulnerable_test5.html

SECURE VERSION:
Generated: secure_test5.html

=================================================================

TEST 6: XSS Attack - Event handler in both fields
Input: {"name":"<div onmouseover='alert(1)'>Hover</div>","review":"<span onclick='alert(2)'>Click me</span>"}

VULNERABLE VERSION:
Generated: vulnerable_test6.html

SECURE VERSION:
Generated: secure_test6.html
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.175 s
[INFO] Finished at: 2025-10-20T22:30:45+02:00
[INFO] ------------------------------------------------------------------------
```
