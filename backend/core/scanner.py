#!/usr/bin/env python3
"""
Vulnerability Scanner - Backend API Version
- Designed for web backend integration
- No CLI arguments, no console output
- Returns structured data for API responses
- Supports URLs: Git repos, ZIP archives, and direct files
- Includes CISA KEV and CWE data
"""

import json
import os
import time
import re
import csv
import tempfile
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import quote_plus, urlparse

try:
    import requests
    from packaging.version import Version, InvalidVersion
except ImportError:
    import subprocess
    subprocess.check_call([os.sys.executable, "-m", "pip", "install", "requests", "packaging"])
    import requests
    from packaging.version import Version, InvalidVersion

# ============= CONFIGURATION =============
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Load NVD API key from environment variable
# Get API key from: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Rate limit: 5 requests per 30 seconds without API key, 50 with API key
RATE_LIMIT = 50 if NVD_API_KEY else 5

# ============= URL HANDLER =============
def is_url(path):
    """Check if path is a URL"""
    try:
        result = urlparse(path)
        return result.scheme in ('http', 'https')
    except:
        return False

def is_git_repo(url):
    """Check if URL is a Git repository"""
    return url.endswith('.git') or 'github.com' in url or 'gitlab.com' in url or 'bitbucket.org' in url

def download_git_repo(url, temp_dir):
    """Clone a Git repository"""
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', url, temp_dir],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            return temp_dir
        else:
            return None
    except:
        return None

def download_zip_archive(url, temp_dir):
    """Download and extract ZIP archive"""
    try:
        response = requests.get(url, timeout=120, stream=True)
        response.raise_for_status()
        
        zip_path = Path(temp_dir) / "archive.zip"
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        zip_path.unlink()
        
        extracted_items = list(Path(temp_dir).iterdir())
        if len(extracted_items) == 1 and extracted_items[0].is_dir():
            return str(extracted_items[0])
        
        return temp_dir
    except:
        return None

def download_file(url, temp_dir):
    """Download a single dependency file"""
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        filename = Path(urlparse(url).path).name
        if not filename or filename == '':
            if 'package.json' in url:
                filename = 'package.json'
            elif 'requirements.txt' in url:
                filename = 'requirements.txt'
            elif 'pom.xml' in url:
                filename = 'pom.xml'
            else:
                filename = 'dependency_file'
        
        file_path = Path(temp_dir) / filename
        file_path.write_bytes(response.content)
        
        return temp_dir
    except:
        return None

def fetch_from_url(url):
    """
    Fetch repository or file from URL
    Returns: (path_to_scan, temp_dir_to_cleanup)
    """
    temp_dir = tempfile.mkdtemp(prefix='vuln_scan_')
    
    try:
        if is_git_repo(url):
            result = download_git_repo(url, temp_dir)
        elif url.endswith('.zip') or 'archive' in url.lower():
            result = download_zip_archive(url, temp_dir)
        else:
            result = download_file(url, temp_dir)
        
        if result:
            return result, temp_dir
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None, None
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None

# ============= RATE LIMITER =============
call_times = []

def wait_for_rate_limit():
    """Enforce NVD API rate limits"""
    global call_times
    now = time.time()
    call_times = [t for t in call_times if now - t < 30]
    
    if len(call_times) >= RATE_LIMIT:
        sleep_time = 30 - (now - call_times[0]) + 1
        if sleep_time > 0:
            time.sleep(sleep_time)
    
    call_times.append(now)

# ============= NVD CLIENT =============
def query_nvd(keyword):
    """Query NVD API with keyword search"""
    wait_for_rate_limit()
    
    url = f"{NVD_BASE}?keywordSearch={quote_plus(keyword)}&resultsPerPage=100"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {"vulnerabilities": []}

# ============= CVE VALIDATION =============
def validate_cve_relevance(cve_data, package_name, ecosystem=None):
    """
    Strict validation - package name must appear in CVE CPE configurations
    Only uses CPE matching to avoid false positives from description text
    """
    package_lower = package_name.lower().split(":")[-1]
    
    # Check CPE configurations (structured data - most reliable)
    configs = cve_data.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_str = cpe_match.get("criteria", "")
                parts = cpe_str.split(":")
                
                # CPE format: cpe:2.3:part:vendor:product:version:...
                if len(parts) >= 5:
                    product = parts[4].lower()
                    
                    # Exact match on product name
                    if product == package_lower:
                        return True
                    
                    # For scoped packages (e.g., @angular/core -> angular)
                    if "/" in package_name:
                        scope_product = package_name.split("/")[0].lstrip("@").lower()
                        if product == scope_product:
                            return True
    
    # If no CPE match found, reject the CVE
    # (removed description-based matching to avoid false positives)
    return False

def check_version_vulnerable(cve_data, version):
    """
    Check if specific version is vulnerable
    Returns: True (vulnerable), False (safe), None (no version data)
    """
    if not version:
        return None
    
    configs = cve_data.get("configurations", [])
    has_version_info = False
    is_vulnerable = False
    
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue
                
                start_inc = cpe_match.get("versionStartIncluding")
                start_exc = cpe_match.get("versionStartExcluding")
                end_inc = cpe_match.get("versionEndIncluding")
                end_exc = cpe_match.get("versionEndExcluding")
                
                if any([start_inc, start_exc, end_inc, end_exc]):
                    has_version_info = True
                    
                    try:
                        v = Version(version)
                        in_range = True
                        
                        if start_inc and v < Version(start_inc):
                            in_range = False
                        if start_exc and v <= Version(start_exc):
                            in_range = False
                        if end_inc and v > Version(end_inc):
                            in_range = False
                        if end_exc and v >= Version(end_exc):
                            in_range = False
                        
                        if in_range:
                            is_vulnerable = True
                            break
                    except InvalidVersion:
                        pass
            
            if is_vulnerable:
                break
        if is_vulnerable:
            break
    
    return is_vulnerable if has_version_info else None

def get_severity(cvss_score):
    """Convert CVSS score to severity level"""
    if not cvss_score:
        return "unknown"
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
    except Exception:
        pass
    return "unknown"

def extract_version_info(cve_data):
    """Extract affected version ranges"""
    version_ranges = []
    configs = cve_data.get("configurations", [])
    
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    start_inc = cpe_match.get("versionStartIncluding")
                    start_exc = cpe_match.get("versionStartExcluding")
                    end_inc = cpe_match.get("versionEndIncluding")
                    end_exc = cpe_match.get("versionEndExcluding")
                    
                    if any([start_inc, start_exc, end_inc, end_exc]):
                        range_str = ""
                        if start_inc:
                            range_str += f">= {start_inc}"
                        elif start_exc:
                            range_str += f"> {start_exc}"
                        
                        if end_inc:
                            range_str += f" and <= {end_inc}"
                        elif end_exc:
                            range_str += f" and < {end_exc}"
                        
                        if range_str:
                            version_ranges.append(range_str.strip())
    
    return version_ranges if version_ranges else None

def extract_cwe_ids(cve_data):
    """Extract CWE IDs from CVE data, removing duplicates"""
    cwe_set = set()
    weaknesses = cve_data.get("weaknesses", [])
    
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_value = desc.get("value", "")
            if cwe_value.startswith("CWE-"):
                cwe_set.add(cwe_value)
    
    cwe_list = sorted(list(cwe_set))  # Sort for consistent ordering
    return ", ".join(cwe_list) if cwe_list else "N/A"

def check_cisa_kev(cve_data):
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog"""
    return "Yes" if cve_data.get("cisaExploitAdd") else "No"

# ============= VULNERABILITY SCANNER =============
def find_vulnerabilities(dep):
    """Search for vulnerabilities - only returns confirmed vulnerable CVEs"""
    name = dep["name"]
    version = dep["version"]
    ecosystem = dep.get("ecosystem", "")
    keyword = name.split(":")[-1]
    
    data = query_nvd(keyword)
    
    results = []
    
    for vuln in data.get("vulnerabilities", [])[:50]:
        cve_data = vuln.get("cve", {})
        
        if not validate_cve_relevance(cve_data, name, ecosystem):
            continue
        
        cve_id = cve_data.get("id", "")
        
        # Extract CVSS score - prioritize NVD assessment over CNA
        metrics = cve_data.get("metrics", {})
        cvss = None
        cvss_vector = None
        cvss_source = None
        
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                primary_score = None
                secondary_score = None
                
                for metric in metrics[key]:
                    metric_type = metric.get("type", "").lower()
                    source = metric.get("source", "")
                    cvss_data = metric.get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    vector = cvss_data.get("vectorString")
                    
                    if score is not None:
                        if metric_type == "primary":
                            if primary_score is None:
                                primary_score = (score, vector, "NVD")
                        else:
                            if secondary_score is None:
                                secondary_score = (score, vector, source)
                
                if primary_score:
                    cvss, cvss_vector, cvss_source = primary_score
                    break
                elif secondary_score:
                    cvss, cvss_vector, cvss_source = secondary_score
                    break
        
        vulnerable = check_version_vulnerable(cve_data, version)
        
        # Only include confirmed vulnerable CVEs
        if vulnerable is True:
            version_ranges = extract_version_info(cve_data)
            cwe_ids = extract_cwe_ids(cve_data)
            kev_status = check_cisa_kev(cve_data)
            
            cve_result = {
                "cve_id": cve_id,
                "cvss_score": cvss,
                "cvss_vector": cvss_vector,
                "cvss_source": cvss_source,
                "severity": get_severity(cvss),
                "cwe": cwe_ids,
                "cisa_kev": kev_status,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "affected_versions": version_ranges
            }
            
            results.append(cve_result)
    
    return results

# ============= FILE PARSERS =============
def parse_package_json(path):
    """Parse npm package.json"""
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        deps = []
        for section in ["dependencies", "devDependencies"]:
            for name, ver in data.get(section, {}).items():
                clean_ver = ver.lstrip("^~>=<v ")
                deps.append({
                    "ecosystem": "npm",
                    "name": name,
                    "version": clean_ver
                })
        return deps
    except Exception:
        return []

def parse_requirements_txt(path):
    """Parse Python requirements.txt - supports ==, >=, >, <=, <, ~= version specifiers"""
    try:
        deps = []
        for line in Path(path).read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # Match package with version specifier: ==, >=, >, <=, <, ~=
                m = re.match(r'([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|>|<=|<|~=)\s*([0-9\.]+)', line)
                if m:
                    package_name = m.group(1)
                    version_spec = m.group(2)
                    version = m.group(3)
                    
                    # For vulnerability scanning, we use the specified version
                    # For >= we scan the minimum version (conservative approach)
                    deps.append({
                        "ecosystem": "pip",
                        "name": package_name,
                        "version": version,
                        "version_specifier": version_spec
                    })
        return deps
    except Exception:
        return []

def parse_pom_xml(path):
    """Parse Maven pom.xml"""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(Path(path).read_text(encoding='utf-8'))
        deps = []
        for dep in root.findall('.//{http://maven.apache.org/POM/4.0.0}dependency'):
            group = dep.find('{http://maven.apache.org/POM/4.0.0}groupId')
            artifact = dep.find('{http://maven.apache.org/POM/4.0.0}artifactId')
            version = dep.find('{http://maven.apache.org/POM/4.0.0}version')
            
            if artifact is not None:
                name = f"{group.text}:{artifact.text}" if group is not None else artifact.text
                ver = version.text if version is not None and not version.text.startswith("${") else ""
                deps.append({
                    "ecosystem": "maven",
                    "name": name,
                    "version": ver
                })
        return deps
    except Exception:
        return []

# ============= SOURCE CODE FILE EXTRACTOR =============
def find_dependency_files(repo_path):
    """
    Recursively search for dependency manifest files in repository
    
    Args:
        repo_path: Path to repository root
        
    Returns:
        List of tuples: (file_path, file_type) where file_type is 'package.json', 'requirements.txt', or 'pom.xml'
    """
    repo_path = Path(repo_path)
    manifest_files = []
    
    # Directories to skip (common non-source directories)
    skip_dirs = {
        'node_modules', 'venv', 'env', '.git', '.svn', 
        'build', 'dist', 'target', '__pycache__', '.pytest_cache',
        'site-packages', 'vendor', '.idea', '.vscode'
    }
    
    # Search for package.json (npm/Node.js)
    for file_path in repo_path.rglob('package.json'):
        # Skip if in excluded directory
        if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
            continue
        if file_path.is_file():
            manifest_files.append((file_path, 'package.json'))
    
    # Search for requirements.txt (Python/pip)
    for file_path in repo_path.rglob('requirements.txt'):
        if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
            continue
        if file_path.is_file():
            manifest_files.append((file_path, 'requirements.txt'))
    
    # Search for pom.xml (Java/Maven)
    for file_path in repo_path.rglob('pom.xml'):
        if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
            continue
        if file_path.is_file():
            manifest_files.append((file_path, 'pom.xml'))
    
    return manifest_files

def extract_source_files(repo_path, include_content=True, max_file_size=500_000):
    """
    Extract all source code files from repository for ML analysis
    
    Args:
        repo_path: Path to scanned repository
        include_content: If True, include file contents in response (default: True)
        max_file_size: Maximum file size in bytes to include content (default: 500KB)
        
    Returns:
        List of source file dictionaries with metadata and optional content
    """
    source_extensions = {
        '.py': 'Python',
        '.java': 'Java',
        '.c': 'C',
        '.cpp': 'C++',
        '.cc': 'C++',
        '.cxx': 'C++',
        '.h': 'C/C++ Header',
        '.hpp': 'C++ Header'
    }
    
    source_files = []
    repo_path = Path(repo_path)
    
    # Directories to skip (common non-source directories)
    skip_dirs = {
        'node_modules', 'venv', 'env', '.git', '.svn', 
        'build', 'dist', 'target', '__pycache__', '.pytest_cache',
        'site-packages', 'vendor', '.idea', '.vscode'
    }
    
    try:
        # Walk through all files in repository
        for file_path in repo_path.rglob('*'):
            # Skip directories we don't want to scan
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue
                
            if file_path.is_file():
                ext = file_path.suffix.lower()
                if ext in source_extensions:
                    try:
                        # Calculate file metadata
                        relative_path = file_path.relative_to(repo_path)
                        file_size = file_path.stat().st_size
                        
                        # Skip very large files (> 1MB for extraction)
                        if file_size > 1_000_000:
                            continue
                        
                        # Read file content and count lines
                        file_content = None
                        lines = 0
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content_lines = f.readlines()
                                lines = len(content_lines)
                                
                                # Only include content if requested and file is not too large
                                if include_content and file_size <= max_file_size:
                                    file_content = ''.join(content_lines)
                        except Exception as e:
                            # If we can't read the file, skip it
                            continue
                        
                        file_info = {
                            'filename': file_path.name,
                            'path': str(relative_path).replace('\\', '/'),  # Normalize path separators
                            'full_path': str(file_path),
                            'language': source_extensions[ext],
                            'extension': ext,
                            'size_bytes': file_size,
                            'lines_of_code': lines
                        }
                        
                        # Add content if available
                        if file_content is not None:
                            file_info['content'] = file_content
                        else:
                            file_info['content'] = None  # File too large or couldn't read
                        
                        source_files.append(file_info)
                    except Exception as e:
                        # Skip files that can't be read
                        continue
    except Exception as e:
        # If anything fails, return empty list
        pass
    
    return source_files

# ============= OUTPUT EXPORTERS =============
def export_to_csv(result, output_file):
    """Export results to CSV with proper number formatting"""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Ecosystem', 'Package', 'Version', 'CVE ID', 'CVSS Score',
            'CVSS Source', 'Severity', 'CWE', 'CISA KEV', 'Affected Versions', 'URL'
        ])
        
        for dep in result['dependencies']:
            if dep.get('cves'):
                for cve in dep['cves']:
                    cvss_score = cve.get('cvss_score')
                    if cvss_score is not None:
                        cvss_display = str(cvss_score)
                    else:
                        cvss_display = ''
                    
                    writer.writerow([
                        dep['ecosystem'],
                        dep['name'],
                        dep['version'],
                        cve['cve_id'],
                        cvss_display,
                        cve.get('cvss_source', ''),
                        cve.get('severity', ''),
                        cve.get('cwe', 'N/A'),
                        cve.get('cisa_kev', 'No'),
                        '; '.join(cve.get('affected_versions', []) or ['N/A']),
                        cve.get('url', '')
                    ])

# ============= MAIN SCANNER API =============
def scan_dependencies(repo_path, output_format='json', output_file=None, progress_callback=None):
    """
    Main scanner function for backend integration
    
    Args:
        repo_path: Local path or URL to scan
        output_format: 'json', 'csv', or 'both'
        output_file: Optional output file path
        progress_callback: Optional callback function(stage, percentage, message)
    
    Returns:
        dict: Scan results with structure:
        {
            "success": bool,
            "error": str (if success=False),
            "scanned_at": ISO timestamp,
            "repo_path": str,
            "scan_duration_seconds": float,
            "dependencies": [...],  # Only vulnerable dependencies
            "summary": {
                "total_deps_scanned": int,
                "deps_with_vulnerabilities": int,
                "total_vulnerabilities": int,
                "vulnerabilities_by_severity": {...}
            }
        }
    """
    temp_dir_to_cleanup = None
    start_time = time.time()
    
    try:
        # Progress: Initializing
        if progress_callback:
            progress_callback("initializing", 0, "Initializing security scan...")
        
        # Check if input is a URL
        if is_url(repo_path):
            if progress_callback:
                progress_callback("fetching", 5, "Downloading repository...")
            
            scan_path, temp_dir_to_cleanup = fetch_from_url(repo_path)
            if not scan_path:
                return {
                    "success": False,
                    "error": "Failed to fetch from URL"
                }
            repo_path = scan_path
        
        repo_path = Path(repo_path)
        if not repo_path.exists():
            return {
                "success": False,
                "error": f"Path not found: {repo_path}"
            }
        
        # Progress: Parsing dependency files (recursive search)
        if progress_callback:
            progress_callback("parsing", 10, "Searching for dependency files (recursive)...")
        
        # Recursively find all dependency manifest files
        manifest_files = find_dependency_files(repo_path)
        
        # Parse dependency files
        all_deps = []
        
        for file_path, file_type in manifest_files:
            try:
                if file_type == 'package.json':
                    deps = parse_package_json(file_path)
                    all_deps.extend(deps)
                elif file_type == 'requirements.txt':
                    deps = parse_requirements_txt(file_path)
                    all_deps.extend(deps)
                elif file_type == 'pom.xml':
                    deps = parse_pom_xml(file_path)
                    all_deps.extend(deps)
            except Exception as e:
                # Skip files that can't be parsed
                continue
        
        # Scan dependencies if found
        vulnerable_deps = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_cves = 0
        
        if all_deps:
            # Progress: Scanning dependencies
            if progress_callback:
                progress_callback("scanning", 20, f"Scanning {len(all_deps)} dependencies...")
            
            # Scan each dependency with progress updates
            total_deps = len(all_deps)
            for i, dep in enumerate(all_deps):
                if progress_callback:
                    # Progress from 20% to 70% during dependency scanning
                    current_percentage = 20 + int((i / total_deps) * 50)
                    progress_callback("scanning", current_percentage, f"Scanning {dep['name']} ({i+1}/{total_deps})...")
                
                dep["cves"] = find_vulnerabilities(dep)
            
            # Filter dependencies - only include those with vulnerabilities
            vulnerable_deps = [dep for dep in all_deps if dep.get("cves")]
            
            # Calculate vulnerability statistics
            for dep in vulnerable_deps:
                for cve in dep.get("cves", []):
                    severity = cve.get("severity", "unknown")
                    if severity != "unknown":
                        severity_counts[severity] += 1
                    total_cves += 1
        
        # Progress: Extract source code files for ML analysis (independent of dependencies)
        if progress_callback:
            if all_deps:
                progress_callback("extracting", 75, "Extracting source code files for ML analysis...")
            else:
                progress_callback("extracting", 50, "Extracting source code files for ML analysis...")
        
        # Progress: Finalizing
        if progress_callback:
            if all_deps:
                progress_callback("finalizing", 95, "Analyzing results...")
            else:
                progress_callback("finalizing", 90, "Analyzing results...")
            time.sleep(0.5)
        
        source_files = extract_source_files(repo_path, include_content=True)
        
        # Group files by language and count files with content
        files_by_language = {}
        files_with_content = 0
        for file in source_files:
            lang = file['language']
            if lang not in files_by_language:
                files_by_language[lang] = []
            files_by_language[lang].append(file)
            
            # Count files that have content included
            if file.get('content') is not None:
                files_with_content += 1
        
        scan_duration = time.time() - start_time
        
        # Check if we found anything
        has_dependencies = len(all_deps) > 0
        has_source_code = len(source_files) > 0
        
        # Build warning messages if needed
        warnings = []
        if not has_dependencies and not has_source_code:
            # Neither found - this is an error case
            return {
                "success": False,
                "error": (
                    "No dependency files (package.json, requirements.txt, or pom.xml) "
                    "and no source code files (.py, .java, .c, .cpp) found in repository.\n\n"
                    "This repository doesn't appear to be a supported project type."
                )
            }
        elif not has_dependencies:
            warnings.append("No dependency files found. Source code extracted for ML analysis only.")
        elif not has_source_code:
            warnings.append("No source code files found. Dependency scanning completed only.")
        
        # Progress: Complete
        if progress_callback:
            progress_callback("complete", 100, "Scan completed successfully!")
        
        # Build result
        result = {
            "success": True,
            "scanned_at": datetime.now().isoformat(),
            "repo_path": str(repo_path.absolute()),
            "scan_duration_seconds": round(scan_duration, 2),
            "dependencies": vulnerable_deps,  # Only vulnerable dependencies
            "source_files": source_files,  # Source code files for ML analysis
            "source_files_summary": {
                "total_files": len(source_files),
                "files_with_content": files_with_content,  # Number of files with content included
                "by_language": {
                    lang: len(files) 
                    for lang, files in files_by_language.items()
                },
                "total_lines_of_code": sum(f['lines_of_code'] for f in source_files)
            },
            "summary": {
                "total_deps_scanned": len(all_deps),
                "deps_with_vulnerabilities": len(vulnerable_deps),
                "total_vulnerabilities": total_cves,
                "vulnerabilities_by_severity": severity_counts
            }
        }
        
        # Add warnings if any
        if warnings:
            result["warnings"] = warnings
        
        # Export to file if requested
        if output_file:
            if output_format == 'csv' or output_format == 'both':
                csv_file = output_file if output_file.endswith('.csv') else f"{output_file}.csv"
                export_to_csv(result, csv_file)
            
            if output_format == 'json' or output_format == 'both':
                json_file = output_file if output_file.endswith('.json') else f"{output_file}.json"
                Path(json_file).write_text(json.dumps(result, indent=2), encoding='utf-8')
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
        
    finally:
        # Cleanup temporary directory
        if temp_dir_to_cleanup:
            try:
                shutil.rmtree(temp_dir_to_cleanup, ignore_errors=True)
            except:
                pass
