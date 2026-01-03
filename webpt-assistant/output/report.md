# WebPT Assistant Report

Target: http://192.168.56.102/

## Executive summary

```text
Executive summary:
- Total unique issue groups: 32
- Top priorities:
  - [High] Path Traversal (instances: 17)
  - [High] Hash Disclosure - MD5 Crypt (instances: 1)
  - [Medium] Content Security Policy (CSP) Header Not Set (instances: 1016)
  - [Medium] Missing Anti-clickjacking Header (instances: 704)
  - [Medium] Absence of Anti-CSRF Tokens (instances: 182)
  - [Medium] Application Error Disclosure (instances: 54)
  - [Medium] Source Code Disclosure - SQL (instances: 25)
  - [Medium] Directory Browsing (instances: 2)
```

## Scan stats

- Raw alert instances: 10085
- Unique issue groups: 32
- Risk instance counts: {'Low': 5844, 'Informational': 2239, 'Medium': 1984, 'High': 18}

- MISP enrichment: disabled

## Findings (grouped)

### [Low] Insufficient Site Isolation Against Spectre Vulnerability

- Confidence: Medium
- Instances: 2165
- CWE: 693
- WASC: 14
- Example endpoints:
  - http://192.168.56.102/ (param: Cross-Origin-Resource-Policy, method: GET)
  - http://192.168.56.102/ (param: Cross-Origin-Embedder-Policy, method: GET)
  - http://192.168.56.102/ (param: Cross-Origin-Opener-Policy, method: GET)
  - http://192.168.56.102/dav/ (param: Cross-Origin-Resource-Policy, method: GET)
  - http://192.168.56.102/dav/ (param: Cross-Origin-Embedder-Policy, method: GET)

### [Low] Server Leaks Version Information via "Server" HTTP Response Header Field

- Confidence: High
- Instances: 1107
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/ (param: , method: GET)
  - http://192.168.56.102/robots.txt (param: , method: GET)
  - http://192.168.56.102/sitemap.xml (param: , method: GET)
  - http://192.168.56.102/dav/ (param: , method: GET)
  - http://192.168.56.102/twiki/ (param: , method: GET)

### [Informational] Storable and Cacheable Content

- Confidence: Medium
- Instances: 1056
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/ (param: , method: GET)
  - http://192.168.56.102/sitemap.xml (param: , method: GET)
  - http://192.168.56.102/robots.txt (param: , method: GET)
  - http://192.168.56.102/dav/ (param: , method: GET)
  - http://192.168.56.102/twiki/ (param: , method: GET)

### [Low] Permissions Policy Header Not Set

- Confidence: Medium
- Instances: 1021
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://192.168.56.102/ (param: , method: GET)
  - http://192.168.56.102/sitemap.xml (param: , method: GET)
  - http://192.168.56.102/robots.txt (param: , method: GET)
  - http://192.168.56.102/dav/ (param: , method: GET)
  - http://192.168.56.102/twiki/ (param: , method: GET)

### [Medium] Content Security Policy (CSP) Header Not Set

- Confidence: High
- Instances: 1016
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://192.168.56.102/ (param: , method: GET)
  - http://192.168.56.102/sitemap.xml (param: , method: GET)
  - http://192.168.56.102/robots.txt (param: , method: GET)
  - http://192.168.56.102/dav/ (param: , method: GET)
  - http://192.168.56.102/twiki/ (param: , method: GET)

### [Low] X-Content-Type-Options Header Missing

- Confidence: Medium
- Instances: 757
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://192.168.56.102/ (param: x-content-type-options, method: GET)
  - http://192.168.56.102/dav/ (param: x-content-type-options, method: GET)
  - http://192.168.56.102/twiki/ (param: x-content-type-options, method: GET)
  - http://192.168.56.102/twiki/readme.txt (param: x-content-type-options, method: GET)
  - http://192.168.56.102/icons/back.gif (param: x-content-type-options, method: GET)

### [Medium] Missing Anti-clickjacking Header

- Confidence: Medium
- Instances: 704
- CWE: 1021
- WASC: 15
- Example endpoints:
  - http://192.168.56.102/ (param: x-frame-options, method: GET)
  - http://192.168.56.102/dav/ (param: x-frame-options, method: GET)
  - http://192.168.56.102/twiki/ (param: x-frame-options, method: GET)
  - http://192.168.56.102/mutillidae/ (param: x-frame-options, method: GET)
  - http://192.168.56.102/twiki/TWikiHistory.html (param: x-frame-options, method: GET)

### [Informational] Modern Web Application

- Confidence: Medium
- Instances: 689
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/twiki/TWikiHistory.html (param: , method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/Main/WebHome (param: , method: GET)

### [Informational] User Controllable HTML Element Attribute (Potential XSS)

- Confidence: Low
- Instances: 390
- CWE: 20
- WASC: 20
- Example endpoints:
  - http://192.168.56.102/mutillidae/index.php (param: page, method: GET)
  - http://192.168.56.102/mutillidae/ (param: page, method: GET)
  - http://192.168.56.102/phpMyAdmin/index.php (param: lang, method: POST)
  - http://192.168.56.102/phpMyAdmin/index.php (param: token, method: POST)
  - http://192.168.56.102/mutillidae/index.php (param: login-php-submit-button, method: POST)

### [Low] Timestamp Disclosure - Unix

- Confidence: Low
- Instances: 348
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/twiki/bin/view/Main/WebHome (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/Main/WAITFORDELAY0015 (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/Main/TWikiGroups (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/Know/WebHome (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/TWiki/WebHome (param: , method: GET)

### [Low] In Page Banner Information Leak

- Confidence: High
- Instances: 312
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/robots.txt (param: , method: GET)
  - http://192.168.56.102/sitemap.xml (param: , method: GET)
  - http://192.168.56.102/rdiff/TWiki/TWikiHistory (param: , method: GET)
  - http://192.168.56.102/view/TWiki/TWikiHistory (param: , method: GET)
  - http://192.168.56.102/oops/TWiki/TWikiHistory (param: , method: GET)

### [Medium] Absence of Anti-CSRF Tokens

- Confidence: Low
- Instances: 182
- CWE: 352
- WASC: 9
- Example endpoints:
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: , method: GET)
  - http://192.168.56.102/dvwa/login.php (param: , method: GET)
  - http://192.168.56.102/twiki/TWikiDocumentation.html (param: , method: GET)
  - http://192.168.56.102/mutillidae/ (param: , method: GET)

### [Informational] Non-Storable Content

- Confidence: Medium
- Instances: 59
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/dvwa/ (param: , method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/twiki/templates/register.tmpl (param: , method: GET)
  - http://192.168.56.102/dvwa/login.php (param: , method: POST)

### [Low] Information Disclosure - Debug Error Messages

- Confidence: Medium
- Instances: 56
- CWE: 1295
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/TWiki/WebChanges (param: , method: GET)
  - http://192.168.56.102/twiki/bin/attach/Main/WebHome (param: , method: GET)
  - http://192.168.56.102/mutillidae/home/remastersys/remastersys (param: , method: GET)

### [Medium] Application Error Disclosure

- Confidence: Medium
- Instances: 54
- CWE: 550
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/dav/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: POST)
  - http://192.168.56.102/twiki/bin/attach/Main/WebHome (param: , method: GET)

### [Low] Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)

- Confidence: Medium
- Instances: 43
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/ (param: , method: GET)
  - http://192.168.56.102/dvwa/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: , method: GET)

### [Medium] Source Code Disclosure - SQL

- Confidence: Medium
- Instances: 25
- CWE: 540
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/set-up-database.php (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: POST)
  - http://192.168.56.102/twiki/bin/view/TWiki/FileAttachment (param: , method: GET)
- ExploitDB (searchsploit) hits:
  - Yamamah - 'news' SQL Injection / Source Code Disclosure (/usr/share/exploitdb/exploits/php/webapps/13845.txt)

### [Informational] Information Disclosure - Suspicious Comments

- Confidence: Medium
- Instances: 22
- CWE: 615
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: POST)
  - http://192.168.56.102/twiki/bin/rdiff/Main/TWikiVariables (param: , method: GET)
  - http://192.168.56.102/twiki/bin/search/Main/ (param: , method: GET)

### [Low] Cookie without SameSite Attribute

- Confidence: Medium
- Instances: 17
- CWE: 1275
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/dvwa/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/dvwa/ (param: security, method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: phpMyAdmin, method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: pma_lang, method: GET)

### [High] Path Traversal

- Confidence: Medium
- Instances: 17
- CWE: 22
- WASC: 33
- Example endpoints:
  - http://192.168.56.102/twiki/bin/search/TWiki/ (param: search, method: GET)
  - http://192.168.56.102/twiki/bin/search/Sandbox/ (param: search, method: GET)
  - http://192.168.56.102/twiki/bin/search/Main/ (param: search, method: GET)
  - http://192.168.56.102/mutillidae/ (param: page, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: page, method: POST)
- ExploitDB (searchsploit) hits:
  - ABB Cylon Aspect 3.08.02 (ethernetUpdate.php) - Authenticated Path Traversal (/usr/share/exploitdb/exploits/php/hardware/52252.txt)
  - Acuity CMS 2.6.2 - '/admin/file_manager/browse.asp?path' Traversal Arbitrary File Access (/usr/share/exploitdb/exploits/asp/webapps/37223.txt)
  - Advanced Comment System 1.0 - 'ACS_path' Path Traversal (/usr/share/exploitdb/exploits/php/webapps/49343.txt)
  - Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE) (/usr/share/exploitdb/exploits/multiple/webapps/50383.sh)
  - Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE) (/usr/share/exploitdb/exploits/multiple/webapps/50406.sh)

### [Low] Private IP Disclosure

- Confidence: Medium
- Instances: 14
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/index.php (param: , method: GET)
  - http://192.168.56.102/mutillidae/ (param: , method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: , method: POST)
  - http://192.168.56.102/twiki/bin/view/TWiki/TWikiDocumentation (param: , method: GET)
  - http://192.168.56.102/twiki/bin/view/TWiki/TWikiVariables (param: , method: GET)
- ExploitDB (searchsploit) hits:
  - DeluxeBB 1.3 - Private Information Disclosure (/usr/share/exploitdb/exploits/php/webapps/15451.pl)

### [Informational] Information Disclosure - Sensitive Information in URL

- Confidence: Medium
- Instances: 8
- CWE: 598
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/index.php (param: username, method: GET)
  - http://192.168.56.102/phpMyAdmin/phpmyadmin.css.php (param: token, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: password, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: user-info-php-submit-button, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: user-poll-php-submit-button, method: GET)

### [Informational] Session Management Response Identified

- Confidence: Medium
- Instances: 5
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://192.168.56.102/dvwa/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/mutillidae/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/phpMyAdmin/ (param: phpMyAdmin, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: showhints, method: GET)
  - http://192.168.56.102/phpMyAdmin/index.php (param: pmaPass-1, method: POST)

### [Low] Cookie No HttpOnly Flag

- Confidence: Medium
- Instances: 4
- CWE: 1004
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/dvwa/ (param: PHPSESSID, method: GET)
  - http://192.168.56.102/dvwa/ (param: security, method: GET)
  - http://192.168.56.102/mutillidae/index.php (param: showhints, method: GET)

### [Informational] Authentication Request Identified

- Confidence: Low
- Instances: 3
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://192.168.56.102/phpMyAdmin/index.php (param: pma_username, method: POST)
  - http://192.168.56.102/mutillidae/index.php (param: user-info-php-submit-button, method: GET)

### [Medium] Directory Browsing

- Confidence: Medium
- Instances: 2
- CWE: 548
- WASC: 16
- Example endpoints:
  - http://192.168.56.102/dav/ (param: , method: GET)
- ExploitDB (searchsploit) hits:
  - Hosting Controller 0.6.1 Hotfix 1.4 - Directory Browsing (/usr/share/exploitdb/exploits/windows/remote/675.txt)
  - Ultimate PHP Board 1.0 final Beta - 'viewtopic.php' Directory Contents Browsing (/usr/share/exploitdb/exploits/php/webapps/22075.txt)

### [Informational] Information Disclosure - Suspicious Comments

- Confidence: Low
- Instances: 2
- CWE: 615
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/javascript/ddsmoothmenu/ddsmoothmenu.js (param: , method: GET)
  - http://192.168.56.102/mutillidae/javascript/ddsmoothmenu/jquery.min.js (param: , method: GET)

### [Informational] Authentication Request Identified

- Confidence: High
- Instances: 2
- CWE: -1
- WASC: -1
- Example endpoints:
  - http://192.168.56.102/dvwa/login.php (param: Login, method: POST)
  - http://192.168.56.102/mutillidae/index.php (param: login-php-submit-button, method: POST)

### [Informational] User Controllable Charset

- Confidence: Low
- Instances: 2
- CWE: 20
- WASC: 20
- Example endpoints:
  - http://192.168.56.102/phpMyAdmin/index.php (param: convcharset, method: POST)

### [Informational] Storable but Non-Cacheable Content

- Confidence: Medium
- Instances: 1
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/dvwa/login.php (param: , method: GET)

### [Medium] Vulnerable JS Library

- Confidence: Medium
- Instances: 1
- CWE: 1395
- WASC: -1
- Example endpoints:
  - http://192.168.56.102/mutillidae/javascript/ddsmoothmenu/jquery.min.js (param: , method: GET)

### [High] Hash Disclosure - MD5 Crypt

- Confidence: High
- Instances: 1
- CWE: 497
- WASC: 13
- Example endpoints:
  - http://192.168.56.102/mutillidae/index.php (param: , method: POST)

