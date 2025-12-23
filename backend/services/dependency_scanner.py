#!/usr/bin/env python3
"""
Dependency Scanner Service
Scans dependency files for CVEs using NVD API
Runs on port 8001
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
from pathlib import Path
import tempfile
import shutil

# Import scanner functions
from backend.core.scanner import (
    parse_package_json,
    parse_requirements_txt,
    parse_pom_xml,
    find_vulnerabilities
)

app = FastAPI(
    title="Dependency Scanner Service",
    description="Scans dependency files for vulnerabilities",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DependencyFile(BaseModel):
    path: str
    content: str

class ScanRequest(BaseModel):
    files: List[DependencyFile]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "dependency-scanner"}

@app.post("/scan-dependencies")
async def scan_dependencies_endpoint(request: ScanRequest):
    """
    Scan dependency files for vulnerabilities
    
    Args:
        request: List of dependency files with content
        
    Returns:
        Scan results with dependencies and CVEs
    """
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Create temporary directory to save files
    temp_dir = tempfile.mkdtemp(prefix='dep_scan_')
    
    try:
        all_deps = []
        
        # Process each dependency file
        for file in request.files:
            file_path = Path(temp_dir) / Path(file.path).name
            
            # Save file content
            file_path.write_text(file.content, encoding='utf-8')
            
            # Parse based on file type
            filename_lower = file.path.lower()
            
            try:
                if filename_lower.endswith('package.json'):
                    deps = parse_package_json(file_path)
                    all_deps.extend(deps)
                elif filename_lower.endswith('requirements.txt'):
                    deps = parse_requirements_txt(file_path)
                    all_deps.extend(deps)
                elif filename_lower.endswith('pom.xml'):
                    deps = parse_pom_xml(file_path)
                    all_deps.extend(deps)
            except Exception as e:
                # Skip files that can't be parsed
                continue
        
        if not all_deps:
            return {
                "success": True,
                "dependencies": [],
                "vulnerabilities": [],
                "summary": {
                    "total_deps_scanned": 0,
                    "deps_with_vulnerabilities": 0,
                    "total_vulnerabilities": 0,
                    "vulnerabilities_by_severity": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }
                }
            }
        
        # Scan each dependency for vulnerabilities
        for dep in all_deps:
            dep["cves"] = find_vulnerabilities(dep)
        
        # Filter dependencies - only include those with vulnerabilities
        vulnerable_deps = [dep for dep in all_deps if dep.get("cves")]
        
        # Calculate statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_cves = 0
        
        for dep in vulnerable_deps:
            for cve in dep.get("cves", []):
                severity = cve.get("severity", "unknown")
                if severity != "unknown":
                    severity_counts[severity] += 1
                total_cves += 1
        
        # Build result
        result = {
            "success": True,
            "dependencies": vulnerable_deps,
            "summary": {
                "total_deps_scanned": len(all_deps),
                "deps_with_vulnerabilities": len(vulnerable_deps),
                "total_vulnerabilities": total_cves,
                "vulnerabilities_by_severity": severity_counts
            }
        }
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

