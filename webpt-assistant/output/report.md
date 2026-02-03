# WebPT Assistant Report

Target: http://34.149.87.45/

## Executive summary

```text
Executive summary:
- Total unique issue groups: 3
- Top priorities:
  - [Medium] Content Security Policy (CSP) Header Not Set (instances: 3)
  - [Low] Permissions Policy Header Not Set (instances: 3)
  - [Informational] Non-Storable Content (instances: 3)
```

## Scan stats

- Raw alert instances: 9
- Unique issue groups: 3
- Risk instance counts: {'Medium': 3, 'Informational': 3, 'Low': 3}

- MISP enrichment: disabled

## Findings (grouped)

### [Medium] Content Security Policy (CSP) Header Not Set

- Confidence: High
- Instances: 3
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://34.149.87.45/ (param: , method: GET)
  - http://34.149.87.45/robots.txt (param: , method: GET)
  - http://34.149.87.45/sitemap.xml (param: , method: GET)

### [Informational] Non-Storable Content

- Confidence: Medium
- Instances: 3
- CWE: 524
- WASC: 13
- Example endpoints:
  - http://34.149.87.45/ (param: , method: GET)
  - http://34.149.87.45/robots.txt (param: , method: GET)
  - http://34.149.87.45/sitemap.xml (param: , method: GET)

### [Low] Permissions Policy Header Not Set

- Confidence: Medium
- Instances: 3
- CWE: 693
- WASC: 15
- Example endpoints:
  - http://34.149.87.45/ (param: , method: GET)
  - http://34.149.87.45/robots.txt (param: , method: GET)
  - http://34.149.87.45/sitemap.xml (param: , method: GET)

