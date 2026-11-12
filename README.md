devsecops-tools/
├── authorized_vuln_audit.sh   # Legal target-verified vulnerability scan wrapper
├── sast_security_scan.py      # Python orchestrator for code analysis & dependency checks
├── authorized_targets.txt     # Whitelist of permissible targets for testing
└── README.md                  # Operational guide for the security testing suite
# Whitelisted domains and IPs authorized for internal penetration testing
internal-staging.enterprise-exchange.internal
10.200.0.0/24
staging.enterprise-security.local
#!/usr/bin/env bash
# ==============================================================================
# Script Name: authorized_vuln_audit.sh
# Description: Enforces strict legal authorization checks before executing 
#              automated vulnerability scans against target domains/networks.
# ==============================================================================

set -euo pipefail

TARGET_DOMAIN="${1:-}"
ALLOWLIST_FILE="./devsecops-tools/authorized_targets.txt"
REPORT_DIR="./docs/audit-reports"

if [[ -z "$TARGET_DOMAIN" ]]; then
    echo "ERROR: Target domain or IP required."
    echo "Usage: ./authorized_vuln_audit.sh <domain_or_ip>"
    exit 1
fi

if [[ ! -f "$ALLOWLIST_FILE" ]]; then
    echo "ERROR: Allowlist file not found at $ALLOWLIST_FILE"
    exit 1
fi

if ! grep -Fxq "$TARGET_DOMAIN" "$ALLOWLIST_FILE"; then
    echo "LEGAL BLOCK: '$TARGET_DOMAIN' is not listed in $ALLOWLIST_FILE."
    echo "Scanning unauthorized external targets is prohibited and illegal. Aborting."
    exit 1
fi

mkdir -p "$REPORT_DIR"
echo "[+] Authorization verified for target: $TARGET_DOMAIN. Starting defensive audit..."

# Run Nuclei with safe, non-destructive detection templates
nuclei -u "https://$TARGET_DOMAIN" \
    -severity medium,high,critical \
    -exclude-tags dos,fuzz,intrusive \
    -json-export "$REPORT_DIR/${TARGET_DOMAIN}_scan.json"

echo "[+] Audit complete. Report saved securely to $REPORT_DIR/"
#!/usr/bin/env python3
"""
Static Application Security Testing (SAST) & Dependency Auditor
Scans Python source files for hardcoded secrets, dangerous functions, and misconfigurations.
"""

import os
import re
import sys

DANGEROUS_PATTERNS = [
    (r"eval\(", "Use of dynamic code evaluation (eval) detected."),
    (r"exec\(", "Use of dynamic code execution (exec) detected."),
    (r"subprocess\.call\(.*shell=True", "Shell injection risk: subprocess with shell=True."),
    (r"HARDCODED_SECRET\s*=\s*['\"][\w-]+['\"]", "Potential hardcoded secret or token assignment."),
]

def scan_file(file_path: str) -> list:
    violations = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                for pattern, description in DANGEROUS_PATTERNS:
                    if re.search(pattern, line):
                        violations.append({
                            "file": file_path,
                            "line": line_no,
                            "issue": description,
                            "snippet": line.strip()
                        })
    except Exception as e:
        print(f"[-] Error reading {file_path}: {e}")
    return violations

def run_sast_audit(root_dir: str = ".") -> int:
    print(f"[*] Initiating SAST security scan across directory: {root_dir}")
    total_violations = 0

    for dirpath, _, filenames in os.walk(root_dir):
        if ".git" in dirpath or "venv" in dirpath or "node_modules" in dirpath:
            continue
        for filename in filenames:
            if filename.endswith(".py"):
                file_path = os.path.join(dirpath, filename)
                violations = scan_file(file_path)
                for v in violations:
                    total_violations += 1
                    print(f"[!] VIOLATION: {v['file']}:{v['line']} -> {v['issue']}")
                    print(f"    Code: {v['snippet']}")

    if total_violations > 0:
        print(f"\n[-] SAST Scan Failed: Found {total_violations} security violations.")
        return 1
    else:
        print("\n[+] SAST Scan Passed: No critical code vulnerabilities detected.")
        return 0

if __name__ == "__main__":
    sys.exit(run_sast_audit())
# DevSecOps Security Testing Suite

## Overview
The scripts in this directory provide automated verification mechanisms to ensure code changes and infrastructure configurations meet enterprise zero-trust security baselines before deployment.

## Execution Guidelines
1. **Target Allowlist Verification:** Always ensure target domains are explicitly added to `authorized_targets.txt` prior to executing `authorized_vuln_audit.sh`.
2. **Local SAST Checks:** Run the Python static analysis tool locally before pushing code changes:
   ```bash
   python3 devsecops-tools/sast_security_scan.py
# DevSecOps Security Testing Suite

## Overview
The scripts in this directory provide automated verification mechanisms to ensure code changes and infrastructure configurations meet enterprise zero-trust security baselines before deployment.

## Execution Guidelines
1. **Target Allowlist Verification:** Always ensure target domains are explicitly added to `authorized_targets.txt` prior to executing `authorized_vuln_audit.sh`.
2. **Local SAST Checks:** Run the Python static analysis tool locally before pushing code changes:
   ```bash
   python3 devsecops-tools/sast_security_scan.py

<FollowUp label="Want me to generate the complete REST API backend in Python FastAPI to tie together your badges, keys, and copyright registry?" query="Generate the complete REST API backend in Python FastAPI to tie together your cryptographic keys, roles, and digital badges."/>
# Java Spring E-commerce

E-commerce REST API based on Java Spring, Spring Boot, Hibernate ORM with MySQL, Spring HATEOAS, Spring Fox (Swagger API docs), JWT and Redis.

## REST API Endpoints

All inputs and outputs use JSON format.

**To open Swagger (interactive) API documentation, navigate your browser to [YOUR-URL]/swagger-ui.html**


```
/login
  POST / - Login using username: b and password:b

/product
  GET / - List of products
  POST / - Add product - required : String name , String groupId, String userId
  GET /{id} - View product
  POST /{id} - Update product
  GET /{id}/images - View product images
  GET /image/{id}- View image
  POST /{id}/uploadimage - Upload product image

/group
  GET / - List of groups
  POST / - Add group
  GET /{id} - View group
  POST /{id} - Update group

/order
  GET / - List of orders
  POST / - Add order
  GET /{id} - View order
  POST /{id} - Update order

/cart
  POST / - Create cart
  GET /{id} - Get items for card with ID = {id}
  POST /{id} - Add CartItem to cart with ID {id}
  DELETE /{id}/{product_id} - Remove product with ID {product_id} from cart with ID {id}
  POST /{id}/quantity - Updates cart item, i.e. set product quantity
  POTS /{id}/order - Create order from cart

```
