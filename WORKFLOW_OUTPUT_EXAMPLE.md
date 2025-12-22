# Example: GitHub Actions Workflow Output

This document shows what the vulnerability scan workflow displays in the **Actions tab → Summary** section.

---

## 🔍 Vulnerability Scan Summary

**Repository:** owner/repo-name  
**Branch:** test/workflow-test  
**Commit:** abc1234  
**Event:** pull_request

---

## 📦 Dependency Scan Results

**Status:** ✅ Scan Completed  
**Dependencies Scanned:** 8  
**Dependencies with Vulnerabilities:** 1  
**Total Vulnerabilities:** 6

**Severity Breakdown:**
- 🔴 Critical: 0
- 🟠 High: 3
- 🟡 Medium: 2
- 🟢 Low: 1

### Affected Dependencies:

#### transformers (4.47.0)

- 🟠 **[CVE-2024-11392](https://nvd.nist.gov/vuln/detail/CVE-2024-11392)**
  - **Severity:** HIGH | **CVSS:** 8.8
  - **CWE:** CWE-502

- 🟠 **[CVE-2024-11393](https://nvd.nist.gov/vuln/detail/CVE-2024-11393)**
  - **Severity:** HIGH | **CVSS:** 8.8
  - **CWE:** CWE-502

- 🟠 **[CVE-2024-11394](https://nvd.nist.gov/vuln/detail/CVE-2024-11394)**
  - **Severity:** HIGH | **CVSS:** 8.8
  - **CWE:** CWE-502

- 🟡 **[CVE-2025-3933](https://nvd.nist.gov/vuln/detail/CVE-2025-3933)**
  - **Severity:** MEDIUM | **CVSS:** 5.3
  - **CWE:** CWE-1333

- 🟡 **[CVE-2025-5197](https://nvd.nist.gov/vuln/detail/CVE-2025-5197)**
  - **Severity:** MEDIUM | **CVSS:** 5.3
  - **CWE:** CWE-1333

- 🟢 **[CVE-2025-3777](https://nvd.nist.gov/vuln/detail/CVE-2025-3777)**
  - **Severity:** LOW | **CVSS:** 3.5
  - **CWE:** CWE-20

<details>
<summary>View Full Dependency Scan Results</summary>

```json
{
  "success": true,
  "dependencies": [
    {
      "ecosystem": "pip",
      "name": "transformers",
      "version": "4.47.0",
      "version_specifier": ">=",
      "cves": [
        {
          "cve_id": "CVE-2024-11392",
          "cvss_score": 8.8,
          "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "cvss_source": "NVD",
          "severity": "high",
          "cwe": "CWE-502",
          "cisa_kev": "No",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-11392",
          "affected_versions": ["and < 4.48.0"]
        }
        // ... more CVEs
      ]
    }
  ],
  "summary": {
    "total_deps_scanned": 8,
    "deps_with_vulnerabilities": 1,
    "total_vulnerabilities": 6,
    "vulnerabilities_by_severity": {
      "critical": 0,
      "high": 3,
      "medium": 2,
      "low": 1
    }
  }
}
```

</details>

---

## 🤖 ML Source Code Scan Results

**Status:** ✅ Scan Completed  
**Total Files Analyzed:** 5  
**Vulnerable Files:** 2  
**Safe Files:** 3  
**Analysis Time:** 12.5s

### ⚠️ Vulnerable Files Detected:

1. 🔴 **backend/api.py**
   - **Risk Level:** CRITICAL | **Confidence:** 92% | **Language:** Python

2. 🟠 **src/utils.py**
   - **Risk Level:** HIGH | **Confidence:** 78% | **Language:** Python

<details>
<summary>View Full ML Scan Results</summary>

```json
{
  "success": true,
  "predictions": [
    {
      "file_path": "backend/api.py",
      "filename": "api.py",
      "language": "Python",
      "prediction": "VULNERABLE",
      "confidence": 0.9234,
      "vuln_score": 0.9234,
      "safe_score": 0.0766,
      "risk_level": "CRITICAL",
      "success": true
    },
    {
      "file_path": "src/utils.py",
      "filename": "utils.py",
      "language": "Python",
      "prediction": "VULNERABLE",
      "confidence": 0.7845,
      "vuln_score": 0.7845,
      "safe_score": 0.2155,
      "risk_level": "HIGH",
      "success": true
    },
    {
      "file_path": "src/helper.py",
      "filename": "helper.py",
      "language": "Python",
      "prediction": "SAFE",
      "confidence": 0.9567,
      "vuln_score": 0.0433,
      "safe_score": 0.9567,
      "risk_level": "SAFE",
      "success": true
    }
    // ... more predictions
  ],
  "summary": {
    "total_files": 5,
    "vulnerable_files": 2,
    "safe_files": 3,
    "failed_files": 0,
    "analysis_time_seconds": 12.5
  }
}
```

</details>

---

## Example: When No Vulnerabilities Found

### 📦 Dependency Scan Results

**Status:** ✅ Scan Completed  
**Dependencies Scanned:** 15  
**Dependencies with Vulnerabilities:** 0  
**Total Vulnerabilities:** 0

✅ No vulnerabilities detected in dependencies!

---

### 🤖 ML Source Code Scan Results

**Status:** ✅ Scan Completed  
**Total Files Analyzed:** 8  
**Vulnerable Files:** 0  
**Safe Files:** 8  
**Analysis Time:** 8.2s

✅ No security issues detected in source code!

---

## Visual Layout in GitHub Actions

When viewing in GitHub Actions, the summary appears as:

```
┌─────────────────────────────────────────────────────────┐
│  Actions  >  Automated Vulnerability Scan  >  Summary  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  # 🔍 Vulnerability Scan Summary                        │
│                                                          │
│  Repository: owner/repo-name                            │
│  Branch: test/workflow-test                             │
│  Commit: abc1234                                        │
│  Event: pull_request                                    │
│                                                          │
│  ───────────────────────────────────────────────────    │
│                                                          │
│  ## 📦 Dependency Scan Results                          │
│                                                          │
│  Status: ✅ Scan Completed                              │
│  Dependencies Scanned: 8                                │
│  Dependencies with Vulnerabilities: 1                   │
│  Total Vulnerabilities: 6                               │
│                                                          │
│  Severity Breakdown:                                    │
│  • 🔴 Critical: 0                                       │
│  • 🟠 High: 3                                           │
│  • 🟡 Medium: 2                                         │
│  • 🟢 Low: 1                                            │
│                                                          │
│  ### Affected Dependencies:                             │
│                                                          │
│  #### transformers (4.47.0)                             │
│                                                          │
│  • 🟠 CVE-2024-11392                                    │
│    Severity: HIGH | CVSS: 8.8                           │
│    CWE: CWE-502                                         │
│                                                          │
│  [View Full Dependency Scan Results ▼]                  │
│                                                          │
│  ───────────────────────────────────────────────────    │
│                                                          │
│  ## 🤖 ML Source Code Scan Results                      │
│                                                          │
│  Status: ✅ Scan Completed                              │
│  Total Files Analyzed: 5                                │
│  Vulnerable Files: 2                                    │
│  Safe Files: 3                                          │
│  Analysis Time: 12.5s                                   │
│                                                          │
│  ### ⚠️ Vulnerable Files Detected:                      │
│                                                          │
│  1. 🔴 backend/api.py                                   │
│     Risk Level: CRITICAL | Confidence: 92%              │
│                                                          │
│  2. 🟠 src/utils.py                                     │
│     Risk Level: HIGH | Confidence: 78%                  │
│                                                          │
│  [View Full ML Scan Results ▼]                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Key Features

✅ **Color-coded severity indicators** (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)  
✅ **Sorted CVEs** (highest severity first)  
✅ **Clickable CVE links** to NVD database  
✅ **Summary statistics** at a glance  
✅ **Expandable JSON sections** for detailed data  
✅ **Clean, readable format** in markdown  
✅ **Consistent formatting** matching frontend display

