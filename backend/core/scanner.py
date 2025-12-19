from pathlib import Path
from typing import Optional, List, Dict

def scan_dependencies(repo_path: Optional[str] = None, files: Optional[List[Dict]] = None) -> dict:
    """
    Unified dependency scanner interface.
    Can scan from:
      - repo_path (URL or local path)
      - files: list of dicts with 'path' and 'content'
    """
    try:
        if files is not None:
            # Scan from uploaded files
            # Each file is {'path': str, 'content': str}
            dependencies = []
            for f in files:
                # Simulate scan: just return filename as a dependency example
                dependencies.append({
                    "name": Path(f['path']).stem,
                    "version": "1.0.0",
                    "ecosystem": "unknown",
                    "cves": []
                })
            summary = {
                "total_deps_scanned": len(dependencies),
                "total_vulnerabilities": 0,
                "deps_with_vulnerabilities": 0,
                "vulnerabilities_by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
            return {"success": True, "dependencies": dependencies, "summary": summary}

        elif repo_path is not None:
            # Scan from URL/ZIP/local repo
            # Placeholder logic: replace with real scan
            dependencies = [
                {"name": "example-lib", "version": "1.0.0", "ecosystem": "python", "cves": []}
            ]
            summary = {
                "total_deps_scanned": len(dependencies),
                "total_vulnerabilities": 0,
                "deps_with_vulnerabilities": 0,
                "vulnerabilities_by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
            return {"success": True, "dependencies": dependencies, "summary": summary}

        else:
            return {"success": False, "error": "No input provided"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def find_dependency_files(base_path: str):
    """
    Scan a directory for known dependency manifest files.
    Returns a list of (path, type) tuples.
    """
    result = []
    base = Path(base_path)
    for pattern in ["package.json", "requirements.txt", "pom.xml"]:
        for file in base.rglob(pattern):
            result.append((file, pattern))
    return result


def extract_source_files(base_path: str, include_content: bool = False):
    """
    Extract source files for ML analysis
    """
    result = []
    base = Path(base_path)
    for ext in [".py", ".java", ".c", ".cpp"]:
        for file in base.rglob(f"*{ext}"):
            file_info = {"path": str(file.relative_to(base)), "language": ext[1:], "lines_of_code": 0}
            if include_content:
                try:
                    file_info["content"] = file.read_text(encoding="utf-8")
                    file_info["lines_of_code"] = len(file_info["content"].splitlines())
                except Exception:
                    file_info["content"] = ""
            result.append(file_info)
    return result
