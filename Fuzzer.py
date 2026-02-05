#!/usr/bin/env python3
"""
Lightweight JSON HTTP Fuzzer using jdam
Author: Jai
Date: 2026-02-03
"""

import subprocess
import requests
import json
import sys
import argparse
from typing import Dict, List, Optional
import time
import shutil
import re
from colorama import Fore, Style, init
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import difflib

# Initialize colorama
init(autoreset=True)

def parse_burp_request(file_path: str) -> Dict:
    """Parse raw HTTP request from Burp Suite
    
    Raises:
        FileNotFoundError: If request file doesn't exist
        ValueError: If request format is invalid
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    lines = content.split('\n')
    if not lines:
        raise ValueError("Empty request file")
    
    # Parse request line (GET /path HTTP/1.1)
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line}")
    
    method = parts[0]
    path = parts[1]
    
    # Parse headers
    headers = {}
    host = None
    body_start = 0
    
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:  # Empty line indicates end of headers
            body_start = i + 1
            break
        
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
            if key.strip().lower() == 'host':
                host = value.strip()
    
    # Parse body (JSON)
    body = '\n'.join(lines[body_start:]).strip()
    
    # Construct full URL
    if not host:
        raise ValueError("No Host header found in request")
    
    # Improved scheme detection: check port and SSL-related headers
    scheme = 'http'  # Default
    
    # Check if host includes explicit port
    if ':' in host:
        port = host.split(':')[1]
        if port == '443':
            scheme = 'https'
    
    # Check for SSL/TLS indicators in headers
    if any(key.lower() in ['x-forwarded-proto', 'x-forwarded-protocol'] and 
           value.lower() == 'https' 
           for key, value in headers.items()):
        scheme = 'https'
    
    url = f"{scheme}://{host}{path}"
    
    return {
        'method': method,
        'url': url,
        'headers': headers,
        'body': body
    }

def canonicalize_headers(raw_headers: List[tuple], defaults: Dict = None, verbose: bool = False) -> Dict:
    """Canonicalize HTTP headers to Title-Case and detect duplicates
    
    Args:
        raw_headers: List of (key, value) tuples
        defaults: Dict of default headers to start with
        verbose: Print warnings for duplicate headers
    
    Returns:
        Dict with canonicalized header names (Title-Case)
    """
    headers = defaults.copy() if defaults else {}
    seen_lower = {}  # Track lowercase versions to detect duplicates
    
    for key, value in raw_headers:
        # Canonicalize to Title-Case (standard HTTP format)
        canonical_key = '-'.join(word.capitalize() for word in key.split('-'))
        lower_key = key.lower()
        
        # Check for duplicates (case-insensitive)
        if lower_key in seen_lower:
            if verbose:
                print(f"{Fore.YELLOW}[!] Warning: Duplicate header '{key}' (was '{seen_lower[lower_key]}')")
                print(f"{Fore.YELLOW}    Overriding: {headers[seen_lower[lower_key]]} → {value}")
            # Remove old key with different casing
            del headers[seen_lower[lower_key]]
        
        headers[canonical_key] = value
        seen_lower[lower_key] = canonical_key
    
    return headers

class JSONFuzzer:
    def __init__(self, url: str, method: str = "POST", headers: Dict = None, 
                 proxy: str = None, verify_ssl: bool = True, follow_redirects: bool = False,
                 max_issues: int = 1000):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.follow_redirects = follow_redirects
        # Close connection after each request to avoid Burp proxy hanging
        if 'Connection' not in self.headers:
            self.headers['Connection'] = 'close'
        self.session = requests.Session()
        self.max_issues = max_issues
        self.issues_limit_warned = False
        
        # Configure connection pooling and retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Auto-disable SSL verification when proxy is used (like Nuclei)
        if proxy:
            self.verify_ssl = False
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            print(f"{Fore.CYAN}[*] Using proxy: {proxy}")
            print(f"{Fore.YELLOW}[*] SSL verification auto-disabled for proxy")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            self.verify_ssl = verify_ssl
        
        self.found_issues = []
        self.found_issues_lock = threading.Lock()
        
        # Response diffing for anomaly detection
        self.baseline_response = None
        self.diff_threshold = 0.3  # Responses with >30% difference are anomalies
        
        # Vulnerability indicators
        self.vuln_patterns = [
            # SQL Injection indicators
            "error", "exception", "stack trace", "SQL syntax", "mysql", 
            "postgresql", "sqlite", "ora-", "microsoft sql", "odbc",
            "syntax error", "unclosed quotation", "unterminated string",
            
            # NoSQL Injection
            "mongodb", "bson", "objectid", "aggregation",
            
            # Path Traversal / LFI
            "root:", "/etc/passwd", "boot.ini", "win.ini",
            
            # Command Injection
            "sh:", "bash:", "command not found", "permission denied",
            
            # XML/XXE
            "xml parsing", "DOCTYPE", "ENTITY", "xmlrpc",
            
            # Debug/Info Disclosure
            "debug", "trace", "warning", "fatal", "panic",
            "internal server", "at line", "on line",
            
            # Framework specific
            "laravel", "symfony", "django", "flask", "express",
            "tomcat", "spring", "struts", "werkzeug",
            
            # jdam specific markers
            "1764", "0x", "/tmp/jdam", "failed", "fault", "abort"
        ]
    
    def _truncate_response(self, response: Dict, max_body_length: int = 500) -> Dict:
        """Truncate response body to save memory
        
        Args:
            response: Response dict to truncate
            max_body_length: Maximum length of body to keep
        
        Returns:
            New dict with truncated body
        """
        truncated = response.copy()
        if len(truncated["body"]) > max_body_length:
            truncated["body"] = truncated["body"][:max_body_length] + "...[truncated]"
        return truncated
    
    def generate_fuzzed_json(self, base_json: str, count: int = 1, 
                            rounds: int = 3, ignore_fields: str = None,
                            mutators: str = None, seed: int = None,
                            max_depth: int = None, nil_chance: float = None) -> List[str]:
        """Generate fuzzed JSON payloads using jdam
        
        Raises:
            FileNotFoundError: If jdam is not found in PATH
            ValueError: If parameters contain invalid characters or values
        """
        
        # Find jdam in PATH for security (use absolute path)
        jdam_path = shutil.which("jdam")
        if not jdam_path:
            raise FileNotFoundError(
                "jdam not found in PATH. Install it first: "
                "go install gitlab.com/michenriksen/jdam/cmd/jdam@latest"
            )
        
        # Build command with validated parameters
        cmd = [jdam_path, "-count", str(count), "-rounds", str(rounds)]
        
        # Validate and sanitize string inputs to prevent injection
        if ignore_fields:
            # Whitelist: only alphanumeric, underscores, commas, dots
            if not re.match(r'^[a-zA-Z0-9_,\.]+$', ignore_fields):
                raise ValueError(
                    f"Invalid characters in ignore_fields: {ignore_fields!r}. "
                    "Only alphanumeric, underscores, commas, and dots allowed"
                )
            cmd.extend(["-ignore", ignore_fields])
        
        if mutators:
            # Whitelist: only alphanumeric, underscores, commas
            if not re.match(r'^[a-zA-Z0-9_,]+$', mutators):
                raise ValueError(
                    f"Invalid characters in mutators: {mutators!r}. "
                    "Only alphanumeric, underscores, and commas allowed"
                )
            cmd.extend(["-mutators", mutators])
        
        # Numeric parameters - validate and convert
        if seed is not None:
            try:
                seed_int = int(seed)
                cmd.extend(["-seed", str(seed_int)])
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid seed value: {seed!r} - must be an integer") from e
        
        if max_depth is not None:
            try:
                depth_int = int(max_depth)
                if depth_int <= 0:
                    raise ValueError(f"max_depth must be positive, got {depth_int}")
                cmd.extend(["-max-depth", str(depth_int)])
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid max_depth value: {max_depth!r}") from e
        
        if nil_chance is not None:
            try:
                chance_float = float(nil_chance)
                if not (0.0 <= chance_float <= 1.0):
                    raise ValueError(f"nil_chance must be 0.0-1.0, got {chance_float}")
                cmd.extend(["-nil-chance", str(chance_float)])
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid nil_chance value: {nil_chance!r}") from e
        
        # Execute jdam with validated parameters
        try:
            result = subprocess.run(
                cmd,
                input=base_json,
                capture_output=True,
                text=True,
                timeout=10,
                # Security: don't pass through shell
                shell=False
            )
            
            if result.returncode != 0:
                raise RuntimeError(
                    f"jdam failed with exit code {result.returncode}\n"
                    f"stderr: {result.stderr.strip()}"
                )
            
            # Split output into individual JSON objects
            payloads = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            if not payloads:
                raise RuntimeError("jdam produced no output - check your input JSON and parameters")
            
            return payloads
        
        except subprocess.TimeoutExpired as e:
            raise TimeoutError(
                "jdam timeout (>10s) - payload too complex or jdam hung. "
                "Try reducing --rounds or simplifying JSON structure"
            ) from e
    
    def send_request(self, payload: str) -> Dict:
        """Send HTTP request with fuzzed JSON"""
        start_time = time.time()
        
        try:
            if self.method == "POST":
                response = self.session.post(
                    self.url, 
                    data=payload, 
                    headers=self.headers,
                    timeout=10,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects
                )
            elif self.method == "PUT":
                response = self.session.put(
                    self.url, 
                    data=payload, 
                    headers=self.headers,
                    timeout=10,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects
                )
            else:
                response = self.session.request(
                    self.method,
                    self.url,
                    data=payload,
                    headers=self.headers,
                    timeout=10,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects
                )
            
            elapsed_time = time.time() - start_time
            
            return {
                "status_code": response.status_code,
                "response_time": elapsed_time,
                "body": response.text,
                "headers": dict(response.headers),
                "length": len(response.content)
            }
        
        except requests.exceptions.Timeout:
            return {
                "status_code": 0,
                "response_time": 10.0,
                "body": "TIMEOUT",
                "headers": {},
                "length": 0
            }
        except Exception as e:
            return {
                "status_code": 0,
                "response_time": time.time() - start_time,
                "body": f"ERROR: {str(e)}",
                "headers": {},
                "length": 0
            }
    
    def analyze_response(self, payload: str, response: Dict) -> tuple:
        """Check if response indicates a vulnerability
        
        Returns:
            (is_interesting: bool, reasons: list)
        """
        is_interesting = False
        reasons = []
        
        # Check status code
        if response["status_code"] in [500, 403, 400]:
            reasons.append(f"Status: {response['status_code']}")
            is_interesting = True
        
        # Check response time (potential DoS)
        if response["response_time"] > 5.0:
            reasons.append(f"Slow response: {response['response_time']:.2f}s")
            is_interesting = True
        
        # Check for vulnerability patterns
        body_lower = response["body"].lower()
        for pattern in self.vuln_patterns:
            if pattern in body_lower:
                reasons.append(f"Pattern found: {pattern}")
                is_interesting = True
                break
        
        # Check unusually large response
        if response["length"] > 10000:
            reasons.append(f"Large response: {response['length']} bytes")
            is_interesting = True
        
        if is_interesting:
            with self.found_issues_lock:
                # Check if we've hit the limit
                if len(self.found_issues) >= self.max_issues:
                    if not self.issues_limit_warned:
                        print(f"{Fore.YELLOW}[!] Warning: Issue storage limit reached ({self.max_issues})")
                        print(f"{Fore.YELLOW}    Newer issues will not be stored (but still displayed)")
                        self.issues_limit_warned = True
                else:
                    self.found_issues.append({
                        "payload": payload,
                        "response": self._truncate_response(response),
                        "reasons": reasons
                    })
        
        return is_interesting, reasons
    
    def calculate_response_similarity(self, resp1_body: str, resp2_body: str) -> float:
        """Calculate similarity ratio between two response bodies (0.0 to 1.0)"""
        # Handle empty responses: both empty = identical, one empty = different
        if not resp1_body and not resp2_body:
            return 1.0  # Both empty = identical
        if not resp1_body or not resp2_body:
            return 0.0  # One empty, one not = completely different
        
        # Fast path: if strings are identical
        if resp1_body == resp2_body:
            return 1.0
        
        # For large responses (>5KB), use faster heuristics instead of full diff
        max_size = 5000
        if len(resp1_body) > max_size or len(resp2_body) > max_size:
            # Sample-based comparison: compare first/middle/last chunks
            chunk_size = 500
            
            # Extract samples
            r1_start = resp1_body[:chunk_size]
            r1_end = resp1_body[-chunk_size:] if len(resp1_body) > chunk_size else ""
            r2_start = resp2_body[:chunk_size]
            r2_end = resp2_body[-chunk_size:] if len(resp2_body) > chunk_size else ""
            
            # Quick comparison on samples
            start_match = difflib.SequenceMatcher(None, r1_start, r2_start).ratio()
            end_match = difflib.SequenceMatcher(None, r1_end, r2_end).ratio() if r1_end and r2_end else start_match
            
            # Average the sample similarities
            return (start_match + end_match) / 2.0
        
        # For smaller responses, use full comparison with quick_ratio optimization
        matcher = difflib.SequenceMatcher(None, resp1_body, resp2_body)
        # Use quick_ratio as upper bound check, then precise ratio for borderline cases
        quick = matcher.quick_ratio()
        if quick >= 0.7:  # Borderline/high similarity - need precise calculation
            return matcher.ratio()
        return quick  # Clearly different - quick_ratio (upper bound) is sufficient
    
    def detect_anomaly(self, response: Dict, enable_diffing: bool = False) -> tuple:
        """Detect if response is anomalous compared to baseline
        Returns: (is_anomaly: bool, reasons: list)
        """
        if not enable_diffing or self.baseline_response is None:
            return False, []
        
        anomaly_reasons = []
        
        # Compare status codes
        if response["status_code"] != self.baseline_response["status_code"]:
            anomaly_reasons.append(
                f"Status diff: {self.baseline_response['status_code']} → {response['status_code']}"
            )
        
        # Compare response lengths (>50% difference)
        baseline_len = self.baseline_response["length"]
        current_len = response["length"]
        if baseline_len > 0:
            len_diff = abs(current_len - baseline_len) / baseline_len
            if len_diff > 0.5:
                anomaly_reasons.append(
                    f"Length diff: {baseline_len} → {current_len} ({len_diff*100:.1f}%)"
                )
        elif baseline_len == 0 and current_len > 0:
            # Special case: baseline empty but response has content
            anomaly_reasons.append(
                f"Length diff: Empty baseline → {current_len} bytes"
            )
        
        # Compare response times (>3x difference)
        baseline_time = self.baseline_response["response_time"]
        current_time = response["response_time"]
        if baseline_time > 0 and current_time > 0:
            time_ratio = current_time / baseline_time
            if time_ratio > 3.0:
                anomaly_reasons.append(
                    f"Time diff: {baseline_time:.2f}s → {current_time:.2f}s ({time_ratio:.1f}x)"
                )
        
        # Compare response body content
        similarity = self.calculate_response_similarity(
            self.baseline_response["body"], 
            response["body"]
        )
        
        if similarity < (1.0 - self.diff_threshold):
            anomaly_reasons.append(
                f"Content diff: {(1-similarity)*100:.1f}% different from baseline"
            )
        
        return len(anomaly_reasons) > 0, anomaly_reasons
    
    def _process_payload(self, payload: str, index: int, total: int, verbose: bool, enable_diffing: bool = False):
        """Process a single payload (for threading)"""
        if verbose:
            print(f"{Fore.YELLOW}[{index}/{total}] Testing payload...")
            print(f"{Fore.CYAN}    Raw: {payload[:100]}...")
            try:
                json.loads(payload)
                print(f"{Fore.GREEN}    ✓ Valid JSON")
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}    ✗ Invalid JSON: {e}")
        
        response = self.send_request(payload)
        
        # Check for anomalies using diffing
        is_anomaly, anomaly_reasons = self.detect_anomaly(response, enable_diffing)
        
        # Check for vulnerabilities (returns reasons directly - thread-safe)
        is_interesting, vuln_reasons = self.analyze_response(payload, response)
        
        if is_interesting or is_anomaly:
            # Store anomalies in found_issues if not already stored as interesting
            if is_anomaly and not is_interesting:
                with self.found_issues_lock:
                    if len(self.found_issues) < self.max_issues:
                        self.found_issues.append({
                            "payload": payload,
                            "response": self._truncate_response(response),
                            "reasons": anomaly_reasons
                        })
                    elif not self.issues_limit_warned:
                        print(f"{Fore.YELLOW}[!] Warning: Issue storage limit reached ({self.max_issues})")
                        print(f"{Fore.YELLOW}    Newer issues will not be stored (but still displayed)")
                        self.issues_limit_warned = True
            
            color = Fore.RED if is_interesting else Fore.MAGENTA
            tag = "INTERESTING" if is_interesting else "ANOMALY"
            
            print(f"{color}[!] {tag} RESPONSE [{index}/{total}]")
            print(f"{color}    Payload: {payload}")
            print(f"{color}    Status: {response['status_code']}")
            print(f"{color}    Time: {response['response_time']:.2f}s")
            
            if is_interesting:
                print(f"{color}    Vuln indicators: {', '.join(vuln_reasons)}")
            if is_anomaly:
                print(f"{Fore.MAGENTA}    Anomalies: {', '.join(anomaly_reasons)}")
            
            print(f"{color}    Response preview: {response['body'][:200]}...")
            print()
        elif verbose:
            print(f"{Fore.GREEN}    Status: {response['status_code']} | Time: {response['response_time']:.2f}s")
        
        return index
    
    def fuzz(self, base_json: str, count: int = 50, rounds: int = 3, 
             ignore_fields: str = None, verbose: bool = False,
             mutators: str = None, seed: int = None,
             max_depth: int = None, nil_chance: float = None, threads: int = 1,
             enable_diffing: bool = False, output_file: str = None):
        """Main fuzzing function"""
        print(f"{Fore.CYAN}[*] Starting JSON HTTP Fuzzer")
        print(f"{Fore.CYAN}[*] Target: {self.url}")
        print(f"{Fore.CYAN}[*] Method: {self.method}")
        if threads > 1:
            print(f"{Fore.CYAN}[*] Threads: {threads}")
        if enable_diffing:
            print(f"{Fore.CYAN}[*] Response diffing: ENABLED (threshold: {self.diff_threshold*100:.0f}%)")
        print(f"{Fore.CYAN}[*] Generating {count} fuzzed payloads...")
        
        # Generate payloads
        try:
            payloads = self.generate_fuzzed_json(base_json, count, rounds, ignore_fields,
                                                mutators, seed, max_depth, nil_chance)
        except FileNotFoundError as e:
            print(f"{Fore.RED}[!] {e}")
            return
        except ValueError as e:
            print(f"{Fore.RED}[!] Parameter validation error: {e}")
            return
        except TimeoutError as e:
            print(f"{Fore.RED}[!] {e}")
            return
        except RuntimeError as e:
            print(f"{Fore.RED}[!] {e}")
            return
        
        print(f"{Fore.GREEN}[+] Generated {len(payloads)} payloads")
        print(f"{Fore.CYAN}[*] Starting fuzzing...\n")
        
        # Set baseline with original JSON before fuzzing (if diffing enabled)
        if enable_diffing:
            if verbose:
                print(f"{Fore.CYAN}[*] Establishing baseline with original JSON...")
            baseline_resp = self.send_request(base_json)
            self.baseline_response = baseline_resp.copy()
            if verbose:
                print(f"{Fore.GREEN}    ✓ Baseline set: Status {baseline_resp['status_code']}, "
                      f"Length {baseline_resp['length']} bytes, Time {baseline_resp['response_time']:.2f}s\n")
        
        # Test payloads (with or without threading)
        if threads > 1:
            # Multi-threaded execution
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(self._process_payload, payload, i, len(payloads), verbose, enable_diffing): i 
                    for i, payload in enumerate(payloads, 1)
                }
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Fore.RED}[!] Thread error: {e}")
        else:
            # Single-threaded execution
            for i, payload in enumerate(payloads, 1):
                self._process_payload(payload, i, len(payloads), verbose, enable_diffing)
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] Fuzzing Complete")
        print(f"{Fore.CYAN}[*] Total payloads tested: {len(payloads)}")
        print(f"{Fore.RED}[*] Interesting responses found: {len(self.found_issues)}")
        
        if self.found_issues:
            print(f"\n{Fore.YELLOW}[*] Issues Summary:")
            for i, issue in enumerate(self.found_issues, 1):
                print(f"{Fore.YELLOW}  {i}. {', '.join(issue['reasons'])}")
                print(f"{Fore.YELLOW}     Payload: {issue['payload'][:100]}...")
        
        # Save results to file if requested
        if output_file:
            try:
                results = {
                    "target": self.url,
                    "method": self.method,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "payloads_tested": len(payloads),
                    "issues_found": len(self.found_issues),
                    "config": {
                        "count": count,
                        "rounds": rounds,
                        "threads": threads,
                        "diffing_enabled": enable_diffing,
                        "mutators": mutators,
                        "seed": seed
                    },
                    "issues": []
                }
                
                for issue in self.found_issues:
                    results["issues"].append({
                        "payload": issue["payload"],
                        "reasons": issue["reasons"],
                        "response": {
                            "status_code": issue["response"]["status_code"],
                            "response_time": issue["response"]["response_time"],
                            "length": issue["response"]["length"],
                            "body_preview": issue["response"]["body"][:500]
                        }
                    })
                
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                
                print(f"{Fore.GREEN}[+] Results saved to: {output_file}")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to save results: {e}")
        
        print(f"{Fore.CYAN}{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Lightweight JSON HTTP Fuzzer using jdam",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic POST fuzzing
  python3 json_fuzzer.py -u http://api.example.com/login -j '{"user":"admin","pass":"test"}'
  
  # Fuzz from Burp Suite request file through Burp proxy
  python3 json_fuzzer.py -b burp_request.txt -p http://127.0.0.1:8080 -c 100 -v
  
  # Route through Burp proxy for interception
  python3 json_fuzzer.py -u https://api.example.com/login -j '{"user":"test"}' -p http://127.0.0.1:8080
  
  # Use specific mutators (SQL injection only)
  python3 json_fuzzer.py -b burp_request.txt -M sql,nosql -c 50
  
  # Fast fuzzing with 10 threads
  python3 json_fuzzer.py -b burp_request.txt -c 100 -t 10
  
  # Anomaly detection with response diffing
  python3 json_fuzzer.py -b burp_request.txt -c 50 -d -v
  
  # Save results to file
  python3 json_fuzzer.py -b burp_request.txt -c 100 -o results.json
  
  # Reproducible fuzzing with seed
  python3 json_fuzzer.py -b burp_request.txt -s 12345 -c 20
  
  # Fuzz PUT request, ignore ID field
  python3 json_fuzzer.py -u http://api.example.com/user/1 -m PUT -j '{"id":1,"name":"John"}' -i id
  
  # Read from file with verbose output
  python3 json_fuzzer.py -u http://api.example.com/api -f request.json -c 100 -v
  
  # With custom headers
  python3 json_fuzzer.py -u http://api.example.com/api -j '{"query":"test"}' -H "Authorization: Bearer token123"
        """
    )
    
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("-j", "--json", help="Base JSON string to fuzz")
    parser.add_argument("-f", "--file", help="Read base JSON from file")
    parser.add_argument("-b", "--burp", help="Read raw HTTP request from Burp Suite file")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of payloads (default: 50)")
    parser.add_argument("-r", "--rounds", type=int, default=3, help="Fuzzing rounds (default: 3)")
    parser.add_argument("-i", "--ignore", help="Comma-separated fields to ignore")
    parser.add_argument("-M", "--mutators", help="Comma-separated jdam mutators to use")
    parser.add_argument("-s", "--seed", type=int, help="Seed for reproducible fuzzing")
    parser.add_argument("--max-depth", type=int, help="Maximum nesting depth for mutations")
    parser.add_argument("--nil-chance", type=float, help="Probability of null values (0.0-1.0)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (can be used multiple times)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL verification (for Burp proxy)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects (default: disabled)")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for concurrent fuzzing (default: 1)")
    parser.add_argument("-d", "--diff", action="store_true", help="Enable response diffing for anomaly detection")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--max-issues", type=int, default=1000, help="Maximum number of issues to store in memory (default: 1000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Validate numeric arguments
    if args.count <= 0:
        print(f"{Fore.RED}[!] Error: --count must be positive (got {args.count})")
        sys.exit(1)
    if args.count > 10000:
        print(f"{Fore.YELLOW}[!] Warning: Large --count ({args.count}) may take a long time")
    
    if args.rounds <= 0:
        print(f"{Fore.RED}[!] Error: --rounds must be positive (got {args.rounds})")
        sys.exit(1)
    if args.rounds > 10:
        print(f"{Fore.YELLOW}[!] Warning: High --rounds ({args.rounds}) may generate complex payloads")
    
    if args.threads <= 0:
        print(f"{Fore.RED}[!] Error: --threads must be positive (got {args.threads})")
        sys.exit(1)
    if args.threads > 100:
        print(f"{Fore.YELLOW}[!] Warning: Very high thread count ({args.threads}) may overload target")
    
    if args.max_issues <= 0:
        print(f"{Fore.RED}[!] Error: --max-issues must be positive (got {args.max_issues})")
        sys.exit(1)
    
    if args.max_depth is not None:
        if args.max_depth <= 0:
            print(f"{Fore.RED}[!] Error: --max-depth must be positive (got {args.max_depth})")
            sys.exit(1)
        if args.max_depth > 100:
            print(f"{Fore.YELLOW}[!] Warning: Very deep nesting ({args.max_depth}) may cause issues")
    
    if args.nil_chance is not None:
        if not (0.0 <= args.nil_chance <= 1.0):
            print(f"{Fore.RED}[!] Error: --nil-chance must be between 0.0 and 1.0 (got {args.nil_chance})")
            sys.exit(1)
    
    # Handle Burp request file
    if args.burp:
        print(f"{Fore.CYAN}[*] Parsing Burp Suite request file...")
        try:
            burp_data = parse_burp_request(args.burp)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Burp request file not found: {args.burp}")
            sys.exit(1)
        except ValueError as e:
            print(f"{Fore.RED}[!] Error parsing Burp request: {e}")
            sys.exit(1)
        
        base_json = burp_data['body']
        args.url = burp_data['url']
        args.method = burp_data['method']
        
        # Merge Burp headers with command-line headers (command-line takes precedence)
        burp_header_tuples = []
        for key, value in burp_data['headers'].items():
            # Skip some headers that might cause issues
            if key.lower() not in ['host', 'content-length', 'connection']:
                burp_header_tuples.append((key, value))
        
        # Add command-line headers (will override Burp headers if duplicate)
        if args.header:
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    burp_header_tuples.append((key.strip(), value.strip()))
        
        # Canonicalize all headers
        headers = canonicalize_headers(
            burp_header_tuples, 
            defaults={"Content-Type": "application/json"},
            verbose=args.verbose
        )
        
        print(f"{Fore.GREEN}[+] Parsed: {args.method} {args.url}")
        print(f"{Fore.GREEN}[+] Headers: {len(headers)}")
        print(f"{Fore.GREEN}[+] Body: {len(base_json)} bytes\n")
    
    # Get base JSON from other sources
    elif args.json:
        base_json = args.json
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                base_json = f.read().strip()
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}")
            sys.exit(1)
    else:
        print(f"{Fore.RED}[!] Must provide either -j, -f, or -b")
        sys.exit(1)
    
    # Validate URL is provided
    if not args.url:
        print(f"{Fore.RED}[!] URL is required (use -u or -b)")
        sys.exit(1)
    
    # Validate JSON
    try:
        json.loads(base_json)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!] Invalid JSON: {e}")
        sys.exit(1)
    
    # Parse custom headers (if not already set from Burp request)
    if not args.burp:
        header_tuples = []
        if args.header:
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    header_tuples.append((key.strip(), value.strip()))
        
        headers = canonicalize_headers(
            header_tuples,
            defaults={"Content-Type": "application/json"},
            verbose=args.verbose
        )
    
    # Create fuzzer and run
    verify_ssl = not args.insecure
    fuzzer = JSONFuzzer(args.url, args.method, headers, args.proxy, verify_ssl, 
                       args.follow_redirects, args.max_issues)
    fuzzer.fuzz(base_json, args.count, args.rounds, args.ignore, args.verbose,
                args.mutators, args.seed, args.max_depth, args.nil_chance, args.threads,
                args.diff, args.output)


if __name__ == "__main__":
    main()
