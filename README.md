# JDAM JSON HTTP Fuzzer

A lightweight, high-performance JSON API fuzzer designed for penetration testing. Built on top of [jdam](https://gitlab.com/michenriksen/jdam) by Michael Henriksen for intelligent JSON mutations with advanced vulnerability detection capabilities.

## 🎯 Features

### Core Capabilities
- **Burp Suite Integration** - Import raw HTTP requests directly from Burp
- **Intelligent Fuzzing** - Leverages jdam's mutation engine for realistic payloads
- **Multi-threaded** - Concurrent request handling for faster testing
- **Proxy Support** - Route traffic through Burp Suite for inspection
- **Response Analysis** - Automatic vulnerability pattern detection
- **Anomaly Detection** - Response diffing to identify unusual behaviors
- **Authentication Handling** - Preserves auth headers from Burp requests

### Vulnerability Detection
Automatically detects indicators for:
- SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- NoSQL Injection (MongoDB, BSON)
- XML External Entity (XXE)
- Command Injection
- Path Traversal / LFI
- Server-Side Template Injection (SSTI)
- Information Disclosure (stack traces, debug info)
- Framework Detection (Laravel, Django, Flask, Spring, etc.)

## 📦 Installation

### Prerequisites
```bash
# Python 3.7+
python --version

# Go 1.16+ (for jdam)
go version
```

### Install Dependencies
```bash
# Python packages
pip install requests colorama urllib3

# Install jdam
go install gitlab.com/michenriksen/jdam/cmd/jdam@latest
```

### Verify Installation
```bash
jdam -version
python Fuzzer.py --help
```

## 🚀 Quick Start

### Basic Usage
```bash
# Fuzz a simple JSON endpoint
python Fuzzer.py -u http://api.example.com/login \
  -j '{"username":"admin","password":"test"}' \
  -c 50 -v
```

### Burp Suite Workflow (Recommended)
```bash
# 1. In Burp Suite:
#    - Capture POST request to JSON API
#    - Right-click → "Copy to file" → save as request.txt

# 2. Run fuzzer
python Fuzzer.py -b request.txt -c 100 -v

# 3. With Burp proxy for traffic inspection
python Fuzzer.py -b request.txt \
  -p http://127.0.0.1:8080 \
  -c 100 -t 5 -o results.json
```

## 📖 Usage Examples

### Authentication Testing
```bash
# Auth headers are automatically preserved from Burp requests
python Fuzzer.py -b authenticated_request.txt -c 100 -v

# Or add headers manually
python Fuzzer.py -u https://api.example.com/user \
  -j '{"id":123}' \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "X-API-Key: abc123"
```

### Performance & Stealth
```bash
# Fast fuzzing with 10 concurrent threads
python Fuzzer.py -b request.txt -c 200 -t 10

# Conservative testing (single-threaded, lower count)
python Fuzzer.py -b request.txt -c 20 -t 1
```

### Advanced Fuzzing
```bash
# Use specific mutators (SQL injection focus)
python Fuzzer.py -b request.txt -M sql,nosql -c 50

# Ignore specific fields (IDs, timestamps)
python Fuzzer.py -b request.txt -i id,timestamp,created_at -c 100

# Reproducible fuzzing with seed
python Fuzzer.py -b request.txt -s 12345 -c 50

# Control mutation depth and null probability
python Fuzzer.py -b request.txt \
  --max-depth 5 \
  --nil-chance 0.3 \
  -c 100
```

### Anomaly Detection
```bash
# Enable response diffing to find edge cases
python Fuzzer.py -b request.txt -d -v -c 100

# This compares all responses to a baseline (original JSON)
# and flags responses with >30% difference
```

### Output & Reporting
```bash
# Save findings to JSON file
python Fuzzer.py -b request.txt -c 100 -o results.json

# Limit memory usage for long scans
python Fuzzer.py -b request.txt -c 1000 --max-issues 500
```

## 🔧 Command Reference

### Required Arguments (pick one)
| Flag | Description | Example |
|------|-------------|---------|
| `-u, --url` | Target URL | `-u https://api.example.com/login` |
| `-b, --burp` | Burp Suite request file | `-b request.txt` |

### Input Options
| Flag | Description | Default |
|------|-------------|---------|
| `-j, --json` | JSON string to fuzz | - |
| `-f, --file` | Read JSON from file | - |
| `-m, --method` | HTTP method | `POST` |

### Fuzzing Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `-c, --count` | Number of payloads | `50` |
| `-r, --rounds` | Mutation rounds | `3` |
| `-i, --ignore` | Fields to ignore (comma-separated) | - |
| `-M, --mutators` | Specific jdam mutators | All |
| `-s, --seed` | Seed for reproducibility | Random |
| `--max-depth` | Max nesting depth | Unlimited |
| `--nil-chance` | Null value probability (0.0-1.0) | `0.1` |

### Network Options
| Flag | Description | Example |
|------|-------------|---------|
| `-H, --header` | Custom header (repeatable) | `-H "X-API-Key: abc"` |
| `-p, --proxy` | Proxy URL | `-p http://127.0.0.1:8080` |
| `-k, --insecure` | Disable SSL verification | - |
| `--follow-redirects` | Follow HTTP redirects | Disabled |

### Performance
| Flag | Description | Default |
|------|-------------|---------|
| `-t, --threads` | Concurrent threads | `1` |
| `--max-issues` | Max issues in memory | `1000` |

### Analysis
| Flag | Description |
|------|-------------|
| `-d, --diff` | Enable response diffing |
| `-v, --verbose` | Detailed output |
| `-o, --output` | Save results to file |

## 🎯 Penetration Testing Tips

### 1. Start with Burp Integration
Always use `-b` flag for real engagements:
- Preserves authentication (cookies, tokens)
- Includes custom headers automatically
- Easier request modification

### 2. Use Proxy for Analysis
Route through Burp to:
- Inspect generated payloads
- Monitor server responses
- Repeat interesting requests manually
```bash
python Fuzzer.py -b request.txt -p http://127.0.0.1:8080
```

### 3. Threaded Fuzzing Considerations
- **Start low** (1-5 threads) to avoid rate limiting
- **Monitor target** for 429/503 errors
- **Check WAF** behavior before ramping up

### 4. Field Exclusion
Ignore fields that cause noise:
```bash
# Skip IDs, timestamps, tokens that change per request
python Fuzzer.py -b request.txt -i id,csrf_token,timestamp
```

### 5. Interpreting Results
Focus on:
- **Status 500** - Internal errors (potential injection points)
- **Status 403** - Authorization bypass attempts
- **Slow responses** (>5s) - Time-based injection
- **Large responses** - Data exfiltration potential
- **Error messages** - Framework/DB fingerprinting

### 6. Follow-up Testing
When fuzzer finds something:
1. Review full request/response in Burp
2. Manually craft refined payloads
3. Validate with sqlmap, commix, etc.
4. Document for report

## 📊 Output Format

### Console Output
```
[*] Starting JSON HTTP Fuzzer
[*] Target: https://api.example.com/login
[*] Method: POST
[+] Generated 50 payloads
[*] Starting fuzzing...

[!] INTERESTING RESPONSE [12/50]
    Payload: {"username":"admin' OR '1'='1","password":"test"}
    Status: 500
    Time: 2.34s
    Vuln indicators: Status: 500, Pattern found: sql syntax
    Response preview: {"error":"SQL syntax error near 'admin' OR '1'='1'"}...
```

### JSON Output (`-o results.json`)
```json
{
  "target": "https://api.example.com/login",
  "method": "POST",
  "timestamp": "2026-02-05 14:30:22",
  "payloads_tested": 50,
  "issues_found": 3,
  "config": {
    "count": 50,
    "rounds": 3,
    "threads": 1
  },
  "issues": [
    {
      "payload": "{\"username\":\"admin' OR '1'='1\"}",
      "reasons": ["Status: 500", "Pattern found: sql syntax"],
      "response": {
        "status_code": 500,
        "response_time": 2.34,
        "length": 156,
        "body_preview": "..."
      }
    }
  ]
}
```

## 🔍 Available jdam Mutators

Use `-M` flag to specify specific mutation types:

| Mutator | Description |
|---------|-------------|
| `sql` | SQL injection payloads |
| `nosql` | NoSQL injection (MongoDB) |
| `xss` | Cross-site scripting |
| `cmdi` | Command injection |
| `path` | Path traversal |
| `xxe` | XML external entity |
| `overflow` | Buffer overflow strings |
| `format` | Format string bugs |

Example:
```bash
python Fuzzer.py -b request.txt -M sql,nosql,cmdi -c 100
```

## 🐛 Troubleshooting

### jdam not found
```bash
# Ensure jdam is in PATH
which jdam  # Linux/Mac
where jdam  # Windows

# Re-install if needed
go install gitlab.com/michenriksen/jdam/cmd/jdam@latest
```

### SSL Certificate Errors
```bash
# Use -k flag to disable SSL verification
python Fuzzer.py -u https://example.com -j '{}' -k

# Or use proxy (auto-disables SSL)
python Fuzzer.py -u https://example.com -j '{}' -p http://127.0.0.1:8080
```

### Burp Request Parsing Errors
Ensure request file has:
1. Request line: `POST /api/login HTTP/1.1`
2. Headers (including `Host:`)
3. Empty line
4. JSON body

Example:
```
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer abc123

{"username":"test","password":"test"}
```

### High Memory Usage
```bash
# Limit stored issues
python Fuzzer.py -b request.txt -c 1000 --max-issues 100

# Results still displayed, just not all saved to memory
```

### Timeout Errors
```bash
# Reduce complexity
python Fuzzer.py -b request.txt -r 2 --max-depth 3

# Or simplify JSON structure manually
```

## ⚠️ Legal Disclaimer

This tool is designed for authorized security testing only. Users must:
- Obtain written permission before testing any system
- Comply with applicable laws and regulations
- Use responsibly and ethically

Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

## 🤝 Contributing

Feedback and contributions welcome! Focus areas:
- Additional vulnerability patterns
- Performance optimizations
- Better anomaly detection
- Reporting formats

## 📝 License

This tool is provided as-is for security testing purposes.

## 🔗 References

- [jdam](https://gitlab.com/michenriksen/jdam) - JSON fuzzing mutation engine by Michael Henriksen

## 🙏 Credits

Special thanks to **Michael Henriksen** ([@michenriksen](https://gitlab.com/michenriksen)) for creating [jdam](https://gitlab.com/michenriksen/jdam), the powerful JSON mutation engine that powers this fuzzer.

---

**Author:** Jai  
**Version:** 1.0  
**Last Updated:** 2026-02-03
