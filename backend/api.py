#!/usr/bin/env python3
"""
FastAPI wrapper exposing the vulnerability scanner as a web service.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional
from urllib.parse import urlparse
import tempfile
import shutil
from pathlib import Path
import asyncio
import json
import zipfile
import requests
import os

from backend.core.scanner import scan_dependencies, find_dependency_files, extract_source_files, parse_package_json, parse_requirements_txt, parse_pom_xml, find_vulnerabilities
from backend.integrations.github_webhook import GitHubWebhookHandler
from backend.services.email_service import send_feedback_email
from backend.core.ml_service import get_analyzer

app = FastAPI(
    title="Vulnerability Scanner API",
    description="Main API orchestrator for vulnerability scanning services.",
    version="1.0.0",
)

# Service URLs
DEPENDENCY_SCANNER_URL = "http://localhost:8001"
ML_ANALYSIS_URL = "http://localhost:8002"

def call_dependency_scanner(dependency_files: list) -> dict:
    """
    Call Dependency Scanner Service to scan dependency files
    
    Args:
        dependency_files: List of dicts with 'path' and 'content'
        
    Returns:
        Scan results from dependency scanner service
    """
    try:
        response = requests.post(
            f"{DEPENDENCY_SCANNER_URL}/scan-dependencies",
            json={"files": dependency_files},
            timeout=300  # 5 minute timeout
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Dependency Scanner Service is not available. Please start it on port 8001."
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="Dependency Scanner Service timeout"
        )
    except requests.exceptions.HTTPError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Dependency Scanner Service error: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calling Dependency Scanner Service: {str(e)}"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="HTTP(S) URL to a repository, archive, or dependency file.")

    @validator("repo_url")
    def validate_repo_url(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("repo_url must not be empty.")

        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("repo_url must be an HTTP or HTTPS URL.")
        if not parsed.netloc:
            raise ValueError("repo_url must contain a valid host.")

        return value


@app.get("/")
def root():
    """Root endpoint with API information"""
    return {
        "name": "Vulnerability Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "/": "API information (this endpoint)",
            "/health": "Health check",
            "/scan": "POST - Scan repository for vulnerabilities (URL)",
            "/scan-upload": "POST - Scan uploaded dependency files",
            "/github/scan-dependencies": "POST - GitHub Actions endpoint for dependency scanning",
            "/github/scan-ml": "POST - GitHub Actions endpoint for ML source code scanning",
            "/ml/predict": "POST - ML-powered vulnerability prediction for source code",
            "/ml/feedback": "POST - Submit feedback for ML predictions",
            "/ws/scan": "WebSocket - Real-time scan progress",
            "/docs": "Interactive API documentation",
        }
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "vulnerability-scanner"}


@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time scan progress updates
    
    Client sends: {"repo_url": "..."}
    Server sends: 
        - {"type": "progress", "stage": "...", "percentage": N, "message": "..."}
        - {"type": "complete", "data": {...scan results...}}
        - {"type": "error", "message": "..."}
    """
    await websocket.accept()
    
    try:
        # Receive scan request
        data = await websocket.receive_text()
        request_data = json.loads(data)
        
        repo_url = request_data.get("repo_url", "")
        
        if not repo_url:
            await websocket.send_json({
                "type": "error",
                "message": "repo_url is required"
            })
            await websocket.close()
            return
        
        # Validate URL
        parsed = urlparse(repo_url)
        if parsed.scheme not in {"http", "https"}:
            await websocket.send_json({
                "type": "error",
                "message": "repo_url must be an HTTP or HTTPS URL"
            })
            await websocket.close()
            return
        
        # Define progress callback
        async def send_progress(stage: str, percentage: int, message: str):
            try:
                await websocket.send_json({
                    "type": "progress",
                    "stage": stage,
                    "percentage": percentage,
                    "message": message
                })
            except Exception as e:
                print(f"Error sending progress: {e}")
        
        # Run scan in thread pool (since scan_dependencies is blocking)
        loop = asyncio.get_event_loop()
        
        def run_scan():
            # Create a synchronous wrapper for the async progress callback
            def sync_progress_callback(stage, percentage, message):
                # Schedule the async callback in the event loop
                asyncio.run_coroutine_threadsafe(
                    send_progress(stage, percentage, message),
                    loop
                )
            
            # Use scan_dependencies for file discovery and source extraction
            # It will handle dependency scanning internally (for now, keeping compatibility)
            # TODO: Refactor to use dependency scanner service
            return scan_dependencies(
                repo_path=repo_url,
                progress_callback=sync_progress_callback
            )
        
        # Execute scan in thread pool
        result = await loop.run_in_executor(None, run_scan)
        
        # Send final result
        if result.get("success"):
            await websocket.send_json({
                "type": "complete",
                "data": result
            })
        else:
            await websocket.send_json({
                "type": "error",
                "message": result.get("error", "Scan failed")
            })
        
    except WebSocketDisconnect:
        print("Client disconnected from WebSocket")
    except json.JSONDecodeError:
        await websocket.send_json({
            "type": "error",
            "message": "Invalid JSON in request"
        })
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass


@app.websocket("/ws/scan-upload")
async def websocket_scan_upload_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time upload scan progress
    
    Note: WebSocket file upload is more complex. For now, this is a placeholder.
    Clients should use the REST endpoint for uploads and WebSocket for URL scans.
    """
    await websocket.accept()
    await websocket.send_json({
        "type": "error",
        "message": "File upload via WebSocket not yet implemented. Use /scan-upload REST endpoint."
    })
    await websocket.close()


@app.post("/scan")
def scan_endpoint(payload: ScanRequest):
    """
    Scan a repository for dependency vulnerabilities
    
    Args:
        payload: JSON with repo_url (Git repo, ZIP, or manifest file)
        
    Returns:
        Scan results with dependencies and their CVEs
    """
    result = scan_dependencies(
        repo_path=payload.repo_url
    )

    if not result.get("success"):
        error_message = result.get("error", "An unknown error occurred during scanning.")
        raise HTTPException(status_code=400, detail=error_message)

    return result


@app.post("/scan-upload")
async def scan_upload_endpoint(
    files: list[UploadFile] = File(...)
):
    """
    Scan uploaded file(s) for vulnerabilities
    
    Args:
        files: List of uploaded files (can be single file or multiple files)
        
    Returns:
        Scan results with dependencies and their CVEs
        For ZIP files: Also includes source code files for ML analysis
        For multiple files: Combined results from all files
    """
    # Handle both single file and multiple files (FastAPI sends single file as list with one element)
    if not files or len(files) == 0:
        raise HTTPException(
            status_code=400,
            detail="No files provided. Please upload at least one file."
        )
    
    file_list = files
    
    # Validate: Only one ZIP file allowed, and cannot mix ZIP with other files
    zip_files = [f for f in file_list if f.filename.lower().endswith('.zip')]
    if len(zip_files) > 1:
        raise HTTPException(
            status_code=400,
            detail="Only one ZIP file can be uploaded at a time."
        )
    if len(zip_files) == 1 and len(file_list) > 1:
        raise HTTPException(
            status_code=400,
            detail="Cannot upload ZIP file with other files. Upload ZIP separately or upload multiple source code files without ZIP."
        )
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix='vuln_scan_upload_')
    
    try:
        # Process first file to determine if it's a ZIP
        first_file = file_list[0]
        first_filename_lower = first_file.filename.lower()
        
        if first_filename_lower.endswith('.zip'):
            # ========== ZIP FILE HANDLING (Single ZIP only) ==========
            if len(file_list) > 1:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot upload ZIP file with other files."
                )
            
            # Read ZIP file content
            content = await first_file.read()
            
            # Check file size (100MB limit)
            MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
            if len(content) > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail=f"File too large. Maximum size is 100MB. Your file: {len(content) / (1024*1024):.1f}MB"
                )
            # ========== ZIP FILE HANDLING ==========
            
            # Save ZIP file
            zip_path = Path(temp_dir) / first_file.filename
            zip_path.write_bytes(content)
            
            # Validate ZIP file
            if not zipfile.is_zipfile(zip_path):
                raise HTTPException(
                    status_code=400,
                    detail="File is not a valid ZIP archive"
                )
            
            # Extract ZIP with security checks
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # Security: Check for ZIP bombs and path traversal
                    total_size = 0
                    for info in zip_ref.filelist:
                        # Check for path traversal attempts
                        if info.filename.startswith('/') or '..' in info.filename:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Unsafe path in ZIP file: {info.filename}"
                            )
                        total_size += info.file_size
                    
                    # Check extracted size (500MB limit)
                    MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500MB
                    if total_size > MAX_EXTRACTED_SIZE:
                        raise HTTPException(
                            status_code=400,
                            detail=f"ZIP extracts to {total_size / (1024*1024):.1f}MB. Maximum is 500MB."
                        )
                    
                    # Extract files
                    zip_ref.extractall(temp_dir)
            
            except zipfile.BadZipFile:
                raise HTTPException(
                    status_code=400,
                    detail="Corrupted ZIP file. Please upload a valid ZIP archive."
                )
            
            # Remove ZIP file (keep extracted contents)
            zip_path.unlink()
            
            # Handle case where ZIP contains single root folder
            extracted_items = list(Path(temp_dir).iterdir())
            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                # ZIP structure: repo.zip → repo/ → files
                scan_path = str(extracted_items[0])
            else:
                # ZIP structure: repo.zip → files (no root folder)
                scan_path = temp_dir
            
            # Find dependency files and source code files
            manifest_files = find_dependency_files(scan_path)
            source_files = extract_source_files(scan_path, include_content=True)
            
            # Prepare dependency files for Dependency Scanner Service
            dependency_files_for_service = []
            for file_path, file_type in manifest_files:
                try:
                    content = Path(file_path).read_text(encoding='utf-8')
                    dependency_files_for_service.append({
                        "path": str(file_path.relative_to(scan_path)),
                        "content": content
                    })
                except Exception:
                    continue
            
            # Call Dependency Scanner Service if dependency files found
            dep_result = None
            if dependency_files_for_service:
                try:
                    dep_result = call_dependency_scanner(dependency_files_for_service)
                except HTTPException:
                    raise
                except Exception as e:
                    # If dependency scanner fails, continue without dependencies
                    dep_result = {
                        "success": True,
                        "dependencies": [],
                        "summary": {
                            "total_deps_scanned": 0,
                            "deps_with_vulnerabilities": 0,
                            "total_vulnerabilities": 0,
                            "vulnerabilities_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                        }
                    }
            
            # Build result combining dependency scan and source code extraction
            if dep_result and dep_result.get("success"):
                result = {
                    "success": True,
                    "scanned_at": None,
                    "repo_path": f"Uploaded: {first_file.filename}",
                    "scan_duration_seconds": 0,
                    "dependencies": dep_result.get("dependencies", []),
                    "source_files": source_files,
                    "source_files_summary": {
                        "total_files": len(source_files),
                        "files_with_content": sum(1 for f in source_files if f.get("content")),
                        "by_language": {},
                        "total_lines_of_code": sum(f.get("lines_of_code", 0) for f in source_files)
                    },
                    "summary": dep_result.get("summary", {})
                }
                
                # Calculate source files summary
                files_by_language = {}
                for file in source_files:
                    lang = file.get("language", "Unknown")
                    files_by_language[lang] = files_by_language.get(lang, 0) + 1
                result["source_files_summary"]["by_language"] = files_by_language
            else:
                # No dependencies, only source code
                result = {
                    "success": True,
                    "scanned_at": None,
                    "repo_path": f"Uploaded: {first_file.filename}",
                    "scan_duration_seconds": 0,
                    "dependencies": [],
                    "source_files": source_files,
                    "source_files_summary": {
                        "total_files": len(source_files),
                        "files_with_content": sum(1 for f in source_files if f.get("content")),
                        "by_language": {},
                        "total_lines_of_code": sum(f.get("lines_of_code", 0) for f in source_files)
                    },
                    "summary": {
                        "total_deps_scanned": 0,
                        "deps_with_vulnerabilities": 0,
                        "total_vulnerabilities": 0,
                        "vulnerabilities_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    },
                    "warnings": ["No dependency files found. Source code extracted for ML analysis only."] if source_files else []
                }
                
                # Calculate source files summary
                files_by_language = {}
                for file in source_files:
                    lang = file.get("language", "Unknown")
                    files_by_language[lang] = files_by_language.get(lang, 0) + 1
                result["source_files_summary"]["by_language"] = files_by_language
            
            return result
            
        else:
            # ========== MULTIPLE FILES HANDLING ==========
            
            # Validate all files
            dependency_files = ["package.json", "requirements.txt", "pom.xml"]
            source_extensions = ['.py', '.java', '.c', '.cpp']  # Java, Python, C, C++ only
            
            total_size = 0
            MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB per file
            MAX_TOTAL_SIZE = 100 * 1024 * 1024  # 100MB total for all files
            
            uploaded_filenames = []
            
            for uploaded_file in file_list:
                filename_lower = uploaded_file.filename.lower()
                
                # Validate file type
                is_dependency_file = uploaded_file.filename in dependency_files
                is_source_file = any(filename_lower.endswith(ext) for ext in source_extensions)
                
                if not is_dependency_file and not is_source_file:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Invalid file type: {uploaded_file.filename}. Upload:\n"
                            f"• Dependency files: {', '.join(dependency_files)}\n"
                            f"• Source code files: {', '.join(source_extensions)}\n"
                            f"• ZIP archive: .zip"
                        )
                    )
                
                # Read and save file
                content = await uploaded_file.read()
                
                # Check individual file size
                if len(content) > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File {uploaded_file.filename} is too large. Maximum size is 100MB per file."
                    )
                
                total_size += len(content)
                
                # Check total size
                if total_size > MAX_TOTAL_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Total size of all files ({total_size / (1024*1024):.1f}MB) exceeds maximum (100MB)."
                    )
                
                # Save file to temp directory
                file_path = Path(temp_dir) / uploaded_file.filename
                file_path.write_bytes(content)
                uploaded_filenames.append(uploaded_file.filename)
            
            # Find dependency files and source code files
            manifest_files = find_dependency_files(temp_dir)
            source_files = extract_source_files(temp_dir, include_content=True)
            
            # Prepare dependency files for Dependency Scanner Service
            dependency_files_for_service = []
            for file_path, file_type in manifest_files:
                try:
                    content = Path(file_path).read_text(encoding='utf-8')
                    dependency_files_for_service.append({
                        "path": str(file_path.relative_to(temp_dir)),
                        "content": content
                    })
                except Exception:
                    continue
            
            # Call Dependency Scanner Service if dependency files found
            dep_result = None
            if dependency_files_for_service:
                try:
                    dep_result = call_dependency_scanner(dependency_files_for_service)
                except HTTPException:
                    raise
                except Exception as e:
                    # If dependency scanner fails, continue without dependencies
                    dep_result = {
                        "success": True,
                        "dependencies": [],
                        "summary": {
                            "total_deps_scanned": 0,
                            "deps_with_vulnerabilities": 0,
                            "total_vulnerabilities": 0,
                            "vulnerabilities_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                        }
                    }
            
            # Build result combining dependency scan and source code extraction
            if dep_result and dep_result.get("success"):
                result = {
                    "success": True,
                    "scanned_at": None,  # Will be set by scanner if needed
                    "repo_path": f"Uploaded: {uploaded_filenames[0]}" if len(uploaded_filenames) == 1 else f"Uploaded: {len(uploaded_filenames)} files ({', '.join(uploaded_filenames[:3])}{'...' if len(uploaded_filenames) > 3 else ''})",
                    "scan_duration_seconds": 0,  # Could track this
                    "dependencies": dep_result.get("dependencies", []),
                    "source_files": source_files,
                    "source_files_summary": {
                        "total_files": len(source_files),
                        "files_with_content": sum(1 for f in source_files if f.get("content")),
                        "by_language": {},
                        "total_lines_of_code": sum(f.get("lines_of_code", 0) for f in source_files)
                    },
                    "summary": dep_result.get("summary", {})
                }
                
                # Calculate source files summary
                files_by_language = {}
                for file in source_files:
                    lang = file.get("language", "Unknown")
                    files_by_language[lang] = files_by_language.get(lang, 0) + 1
                result["source_files_summary"]["by_language"] = files_by_language
            else:
                # No dependencies, only source code
                result = {
                    "success": True,
                    "scanned_at": None,
                    "repo_path": f"Uploaded: {uploaded_filenames[0]}" if len(uploaded_filenames) == 1 else f"Uploaded: {len(uploaded_filenames)} files ({', '.join(uploaded_filenames[:3])}{'...' if len(uploaded_filenames) > 3 else ''})",
                    "scan_duration_seconds": 0,
                    "dependencies": [],
                    "source_files": source_files,
                    "source_files_summary": {
                        "total_files": len(source_files),
                        "files_with_content": sum(1 for f in source_files if f.get("content")),
                        "by_language": {},
                        "total_lines_of_code": sum(f.get("lines_of_code", 0) for f in source_files)
                    },
                    "summary": {
                        "total_deps_scanned": 0,
                        "deps_with_vulnerabilities": 0,
                        "total_vulnerabilities": 0,
                        "vulnerabilities_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    },
                    "warnings": ["No dependency files found. Source code extracted for ML analysis only."] if source_files else []
                }
                
                # Calculate source files summary
                files_by_language = {}
                for file in source_files:
                    lang = file.get("language", "Unknown")
                    files_by_language[lang] = files_by_language.get(lang, 0) + 1
                result["source_files_summary"]["by_language"] = files_by_language
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing upload: {str(e)}")
    finally:
        # Cleanup temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/ml/predict")
async def ml_predict_endpoint(payload: dict):
    """
    ML-powered vulnerability prediction endpoint
    
    Analyzes source code files using RoBERTa (CodeBERT) model to detect vulnerabilities
    
    Request Body:
    {
        "files": [
            {
                "path": "src/app.py",
                "filename": "app.py",
                "language": "Python",
                "content": "def login()...",
                "lines_of_code": 150
            }
        ]
    }
    
    Response:
    {
        "success": true,
        "predictions": [
            {
                "file_path": "src/app.py",
                "filename": "app.py",
                "language": "Python",
                "prediction": "VULNERABLE" | "SAFE",
                "confidence": 0.85,
                "vuln_score": 0.85,
                "safe_score": 0.15,
                "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
                "success": true
            }
        ],
        "summary": {
            "total_files": 5,
            "vulnerable_files": 2,
            "safe_files": 3,
            "failed_files": 0,
            "analysis_time_seconds": 1.5
        }
    }
    
    Requires: torch, transformers (install with: pip install -r requirements.txt)
    """
    try:
        
        files = payload.get("files", [])
        
        # Validation
        if not files:
            raise HTTPException(status_code=400, detail="No files provided for analysis")
        
        if not isinstance(files, list):
            raise HTTPException(status_code=400, detail="'files' must be a list")
        
        if len(files) > 30:
            raise HTTPException(
                status_code=400,
                detail=f"Maximum 30 files per request. You provided {len(files)} files."
            )
        
        # Check all files have required fields
        for i, file in enumerate(files):
            if not isinstance(file, dict):
                raise HTTPException(status_code=400, detail=f"File {i} must be a dictionary")
            
            if "content" not in file:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file.get('path', f'#{i}')} is missing 'content' field"
                )
            
            if not file.get("content") or not file["content"].strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file.get('path', f'#{i}')} has empty content"
                )
        
        # Call ML Analysis Service
        try:
            # Prepare files for ML service
            files_for_ml = []
            for file in files:
                files_for_ml.append({
                    "path": file.get("path"),
                    "filename": file.get("filename"),
                    "language": file.get("language"),
                    "content": file.get("content"),
                    "lines_of_code": file.get("lines_of_code", 0)
                })
            
            response = requests.post(
                f"{ML_ANALYSIS_URL}/predict",
                json={"files": files_for_ml},
                timeout=300  # 5 minute timeout
            )
            response.raise_for_status()
            ml_result = response.json()
            
            # Return ML results directly
            return ml_result
            
        except requests.exceptions.ConnectionError:
            raise HTTPException(
                status_code=503,
                detail="ML Analysis Service is not available. Please start it on port 8002."
            )
        except requests.exceptions.Timeout:
            raise HTTPException(
                status_code=504,
                detail="ML Analysis Service timeout"
            )
        except requests.exceptions.HTTPError as e:
            error_detail = "Unknown error"
            try:
                error_detail = e.response.json().get("detail", str(e))
            except:
                error_detail = e.response.text if hasattr(e, 'response') else str(e)
            raise HTTPException(
                status_code=e.response.status_code if hasattr(e, 'response') else 500,
                detail=f"ML Analysis Service error: {error_detail}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Error calling ML Analysis Service: {str(e)}"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML analysis failed: {str(e)}"
        )


# ============= GITHUB ACTIONS ENDPOINTS =============

@app.post("/github/scan-dependencies")
async def github_scan_dependencies_endpoint(payload: dict = Body(...)):
    """
    GitHub Actions endpoint for dependency scanning
    
    Called by GitHub Actions workflow when dependency files are changed
    
    Request Body:
    {
        "files": [
            {"path": "package.json", "content": "..."},
            ...
        ],
        "repository": "owner/repo",
        "commit_sha": "abc123...",
        "pr_number": 123 (optional, for PR events),
        "event_type": "push" or "pull_request"
    }
    """
    try:
        # Validate payload
        files = payload.get("files", [])
        repository = payload.get("repository")
        commit_sha = payload.get("commit_sha")
        pr_number = payload.get("pr_number")
        event_type = payload.get("event_type", "push")
        
        if not files:
            return {"success": False, "error": "No files provided"}
        
        if not repository or not commit_sha:
            return {"success": False, "error": "repository and commit_sha are required"}
        
        # Scan dependencies directly (no separate service needed)
        try:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix='github_dep_scan_')
            all_deps = []
            
            # Process each dependency file
            for file_data in files:
                file_path_str = file_data.get("path", file_data.get("filename", "unknown"))
                file_content = file_data.get("content", "")
                
                # Create temporary file
                file_path = Path(temp_dir) / Path(file_path_str).name
                file_path.write_text(file_content, encoding='utf-8')
                
                # Parse based on file type
                filename_lower = file_path_str.lower()
                
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
                dep_result = {
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
            else:
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
                dep_result = {
                    "success": True,
                    "dependencies": vulnerable_deps,
                    "vulnerabilities": [cve for dep in vulnerable_deps for cve in dep.get("cves", [])],
                    "summary": {
                        "total_deps_scanned": len(all_deps),
                        "deps_with_vulnerabilities": len(vulnerable_deps),
                        "total_vulnerabilities": total_cves,
                        "vulnerabilities_by_severity": severity_counts
                    }
                }
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        except Exception as e:
            return {"success": False, "error": f"Dependency scan failed: {str(e)}"}
        
        # Post results to GitHub
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            try:
                handler = GitHubWebhookHandler(github_token)
                comment = handler.format_dependency_results(dep_result)
                
                if pr_number and event_type == "pull_request":
                    # Post as PR comment
                    handler.post_pr_comment(repository, pr_number, comment)
                else:
                    # Post as commit comment
                    handler.post_commit_comment(repository, commit_sha, comment)
            except Exception as e:
                print(f"Warning: Failed to post results to GitHub: {e}")
                # Continue even if GitHub posting fails
        
        return dep_result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub dependency scan failed: {str(e)}"
        )


@app.post("/github/scan-ml")
async def github_scan_ml_endpoint(payload: dict = Body(...)):
    """
    GitHub Actions endpoint for ML analysis
    
    Called by GitHub Actions workflow when source code files are changed
    
    Request Body:
    {
        "files": [
            {
                "path": "src/app.py",
                "filename": "app.py",
                "language": "Python",
                "content": "...",
                "lines_of_code": 50
            },
            ...
        ],
        "repository": "owner/repo",
        "commit_sha": "abc123...",
        "pr_number": 123 (optional, for PR events),
        "event_type": "push" or "pull_request"
    }
    """
    try:
        # Validate payload
        files = payload.get("files", [])
        repository = payload.get("repository")
        commit_sha = payload.get("commit_sha")
        pr_number = payload.get("pr_number")
        event_type = payload.get("event_type", "push")
        
        if not files:
            return {"success": False, "error": "No files provided"}
        
        if len(files) > 30:
            return {"success": False, "error": "Maximum 30 files per request"}
        
        if not repository or not commit_sha:
            return {"success": False, "error": "repository and commit_sha are required"}
        
        # Validate files have content
        for i, file in enumerate(files):
            if not file.get("content") or not file.get("content", "").strip():
                return {
                    "success": False,
                    "error": f"File {file.get('path', f'#{i}')} has no content"
                }
        
        # Call ML Analysis directly (no separate service needed)
        try:
            import time
            files_for_ml = []
            for file in files:
                files_for_ml.append({
                    "path": file.get("path"),
                    "filename": file.get("filename"),
                    "language": file.get("language"),
                    "content": file.get("content"),
                    "lines_of_code": file.get("lines_of_code", 0)
                })
            
            # Get analyzer (singleton, cached after first load)
            try:
                analyzer = get_analyzer()
            except FileNotFoundError as e:
                return {
                    "success": False,
                    "error": f"ML model not found: {str(e)}"
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": f"ML service error: {str(e)}"
                }
            
            # Run batch prediction
            start_time = time.time()
            try:
                predictions = analyzer.predict_batch(files_for_ml)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"ML prediction failed: {str(e)}"
                }
            
            prediction_time = time.time() - start_time
            
            # Format results similar to ML service response
            ml_result = {
                "success": True,
                "predictions": predictions,
                "summary": {
                    "total_files": len(files_for_ml),
                    "files_with_issues": len([p for p in predictions if p.get("has_vulnerability", False)]),
                    "prediction_time_seconds": round(prediction_time, 2)
                },
                "issues": [p for p in predictions if p.get("has_vulnerability", False)],
                "vulnerabilities": [p for p in predictions if p.get("has_vulnerability", False)]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"ML scan failed: {str(e)}"
            }
        
        # Post results to GitHub
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            try:
                handler = GitHubWebhookHandler(github_token)
                comment = handler.format_ml_results(ml_result)
                
                if pr_number and event_type == "pull_request":
                    # Post as PR comment
                    handler.post_pr_comment(repository, pr_number, comment)
                else:
                    # Post as commit comment
                    handler.post_commit_comment(repository, commit_sha, comment)
            except Exception as e:
                print(f"Warning: Failed to post results to GitHub: {e}")
                # Continue even if GitHub posting fails
        
        return ml_result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub ML scan failed: {str(e)}"
        )


@app.post("/ml/feedback")
async def ml_feedback_endpoint(payload: dict):
    """
    Submit user feedback for ML predictions
    
    Sends feedback via email to improve the ML model
    
    Request Body:
    {
        "predictions": [
            {
                "filename": "app.py",
                "prediction": "VULNERABLE",
                "confidence": 0.89,
                "user_rating": "correct" | "incorrect" | "unsure" | null
            }
        ],
        "general_comment": "Optional comment...",
        "timestamp": "2025-12-13T..."
    }
    
    Response:
    {
        "success": true,
        "message": "Feedback received successfully"
    }
    """
    try:
        # Validate payload
        predictions = payload.get("predictions", [])
        general_comment = payload.get("general_comment", "")
        timestamp = payload.get("timestamp", "")
        
        if not predictions and not general_comment:
            raise HTTPException(
                status_code=400,
                detail="Feedback must include at least one rating or a comment"
            )
        
        # Send email with feedback
        try:
            send_feedback_email(
                predictions=predictions,
                general_comment=general_comment,
                timestamp=timestamp
            )
        except Exception as e:
            # Log error but don't fail the request
            print(f"Warning: Failed to send feedback email: {e}")
            # Still return success to user
        
        return {
            "success": True,
            "message": "Feedback received successfully. Thank you for helping improve the model!"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process feedback: {str(e)}"
        )

