# WebPT Assistant Report

Target: http://10.0.3.15:8081/

## Executive summary

```text
Executive summary:
- Total unique issue groups: 21
- Top priorities:
  - [Medium] Directory Browsing (instances: 4)
  - [Medium] Content Security Policy (CSP) Header Not Set (instances: 2)
  - [Medium] Missing Anti-clickjacking Header (instances: 1)
  - [Medium] Relative Path Confusion (instances: 1)
  - [Low] Server Leaks Version Information via "Server" HTTP Response Header Field (instances: 10)
  - [Low] X-Content-Type-Options Header Missing (instances: 5)
  - [Low] Cross-Origin-Resource-Policy Header Missing or Invalid (instances: 5)
  - [Low] Cookie No HttpOnly Flag (instances: 4)
```

## Scan stats

- Raw alert instances: 209
- Unique issue groups: 21
- Exploitability instance counts: {'Informational': 168, 'Potentially Exploitable': 41}
- ZAP risk instance counts: {'Informational': 168, 'Low': 33, 'Medium': 8}

- MISP enrichment: disabled

## Findings (grouped)

### [Informational] User Agent Fuzzer

- ZAP risk: Informational
- Confidence: Medium
- Instances: 132
- CWE: 0
- WASC: 0
- Example endpoints:
  - http://10.0.3.15:8081/dvwa/css (param: Header User-Agent, method: GET)
  - http://10.0.3.15:8081/dvwa (param: Header User-Agent, method: GET)
  - http://10.0.3.15:8081/ (param: Header User-Agent, method: GET)
  - http://10.0.3.15:8081/login.php (param: Header User-Agent, method: POST)
  - http://10.0.3.15:8081/dvwa/images (param: Header User-Agent, method: GET)

### [Informational] Cookie Slack Detector

- ZAP risk: Informational
- Confidence: Low
- Instances: 21
- CWE: 205
- WASC: 45
- Example endpoints:
  - http://10.0.3.15:8081/ (param: , method: GET)
  - http://10.0.3.15:8081/dvwa (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/css (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/images (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/css/login.css (param: , method: GET)

### [Potentially Exploitable] Server Leaks Version Information via "Server" HTTP Response Header Field

- ZAP risk: Low
- Confidence: High
- Instances: 10
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/ (param: , method: GET)
  - http://10.0.3.15:8081/login.php (param: , method: GET)
  - http://10.0.3.15:8081/robots.txt (param: , method: GET)
  - http://10.0.3.15:8081/sitemap.xml (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/css/login.css (param: , method: GET)

### [Potentially Exploitable] X-Content-Type-Options Header Missing

- ZAP risk: Low
- Confidence: Medium
- Instances: 5
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: x-content-type-options, method: GET)
  - http://10.0.3.15:8081/robots.txt (param: x-content-type-options, method: GET)
  - http://10.0.3.15:8081/dvwa/css/login.css (param: x-content-type-options, method: GET)
  - http://10.0.3.15:8081/dvwa/images/login_logo.png (param: x-content-type-options, method: GET)
  - http://10.0.3.15:8081/dvwa/images/RandomStorm.png (param: x-content-type-options, method: GET)

### [Potentially Exploitable] Cross-Origin-Resource-Policy Header Missing or Invalid

- ZAP risk: Low
- Confidence: Medium
- Instances: 5
- CWE: 693
- WASC: 14
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: Cross-Origin-Resource-Policy, method: GET)
  - http://10.0.3.15:8081/robots.txt (param: Cross-Origin-Resource-Policy, method: GET)
  - http://10.0.3.15:8081/dvwa/css/login.css (param: Cross-Origin-Resource-Policy, method: GET)
  - http://10.0.3.15:8081/dvwa/images/login_logo.png (param: Cross-Origin-Resource-Policy, method: GET)
  - http://10.0.3.15:8081/dvwa/images/RandomStorm.png (param: Cross-Origin-Resource-Policy, method: GET)

### [Informational] Storable and Cacheable Content

- ZAP risk: Informational
- Confidence: Medium
- Instances: 5
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/robots.txt (param: , method: GET)
  - http://10.0.3.15:8081/sitemap.xml (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/css/login.css (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/images/login_logo.png (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/images/RandomStorm.png (param: , method: GET)

### [Potentially Exploitable] Cookie No HttpOnly Flag

- ZAP risk: Low
- Confidence: Medium
- Instances: 4
- CWE: 1004
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/ (param: PHPSESSID, method: GET)
  - http://10.0.3.15:8081/ (param: security, method: GET)
  - http://10.0.3.15:8081/login.php (param: PHPSESSID, method: GET)
  - http://10.0.3.15:8081/login.php (param: security, method: GET)

### [Potentially Exploitable] Cookie without SameSite Attribute

- ZAP risk: Low
- Confidence: Medium
- Instances: 4
- CWE: 1275
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/ (param: PHPSESSID, method: GET)
  - http://10.0.3.15:8081/ (param: security, method: GET)
  - http://10.0.3.15:8081/login.php (param: PHPSESSID, method: GET)
  - http://10.0.3.15:8081/login.php (param: security, method: GET)

### [Informational] Non-Storable Content

- ZAP risk: Informational
- Confidence: Medium
- Instances: 4
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/ (param: , method: GET)
  - http://10.0.3.15:8081/login.php (param: , method: POST)
  - http://10.0.3.15:8081/vulnerabilities/sqli/ (param: , method: GET)

### [Potentially Exploitable] Directory Browsing

- ZAP risk: Medium
- Confidence: Medium
- Instances: 4
- CWE: 548
- WASC: 48
- Example endpoints:
  - http://10.0.3.15:8081/dvwa/css/ (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/images/ (param: , method: GET)
  - http://10.0.3.15:8081/dvwa/ (param: , method: GET)
  - http://10.0.3.15:8081/vulnerabilities/ (param: , method: GET)
- ExploitDB (searchsploit) hits:
  - Hosting Controller 0.6.1 Hotfix 1.4 - Directory Browsing (/usr/share/exploitdb/exploits/windows/remote/675.txt)
  - Ultimate PHP Board 1.0 final Beta - 'viewtopic.php' Directory Contents Browsing (/usr/share/exploitdb/exploits/php/webapps/22075.txt)

### [Informational] Session Management Response Identified

- ZAP risk: Informational
- Confidence: Medium
- Instances: 2
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://10.0.3.15:8081/ (param: PHPSESSID, method: GET)
  - http://10.0.3.15:8081/login.php (param: PHPSESSID, method: GET)

### [Potentially Exploitable] Content Security Policy (CSP) Header Not Set

- ZAP risk: Medium
- Confidence: High
- Instances: 2
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: , method: GET)
  - http://10.0.3.15:8081/sitemap.xml (param: , method: GET)

### [Potentially Exploitable] Permissions Policy Header Not Set

- ZAP risk: Low
- Confidence: Medium
- Instances: 2
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: , method: GET)
  - http://10.0.3.15:8081/sitemap.xml (param: , method: GET)

### [Informational] Authentication Request Identified

- ZAP risk: Informational
- Confidence: High
- Instances: 2
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: Login, method: POST)

### [Potentially Exploitable] Missing Anti-clickjacking Header

- ZAP risk: Medium
- Confidence: Medium
- Instances: 1
- CWE: 1021
- WASC: 15
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: x-frame-options, method: GET)

### [Informational] Storable but Non-Cacheable Content

- ZAP risk: Informational
- Confidence: Medium
- Instances: 1
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: , method: GET)

### [Potentially Exploitable] Cross-Origin-Embedder-Policy Header Missing or Invalid

- ZAP risk: Low
- Confidence: Medium
- Instances: 1
- CWE: 693
- WASC: 14
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: Cross-Origin-Embedder-Policy, method: GET)

### [Potentially Exploitable] Cross-Origin-Opener-Policy Header Missing or Invalid

- ZAP risk: Low
- Confidence: Medium
- Instances: 1
- CWE: 693
- WASC: 14
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: Cross-Origin-Opener-Policy, method: GET)

### [Potentially Exploitable] In Page Banner Information Leak

- ZAP risk: Low
- Confidence: High
- Instances: 1
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://10.0.3.15:8081/sitemap.xml (param: , method: GET)

### [Informational] Session Management Response Identified

- ZAP risk: Informational
- Confidence: High
- Instances: 1
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://10.0.3.15:8081/ (param: PHPSESSID, method: GET)

### [Potentially Exploitable] Relative Path Confusion

- ZAP risk: Medium
- Confidence: Medium
- Instances: 1
- CWE: 20
- WASC: 20
- Example endpoints:
  - http://10.0.3.15:8081/login.php (param: , method: GET)

