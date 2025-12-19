#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional
from urllib.parse import urlparse
import tempfile, shutil, zipfile
from pathlib import Path
import asyncio, json

from backend.core.scanner import scan_dependencies, find_dependency_files, extract_source_files
from backend.services.email_service import send_feedback_email
from backend.integrations.github_webhook import GitHubWebhookHandler
from backend.core.ml_service import get_analyzer

app = FastAPI(
    title="Vulnerability Scanner API",
    description="Main API orchestrator for vulnerability scanning services.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- MODELS -------------------
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

# ------------------- HELPERS -------------------
def call_dependency_scanner(files: Optional[list] = None, repo_path: Optional[str] = None) -> dict:
    try:
        return scan_dependencies(repo_path=repo_path, files=files)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dependency scan failed: {str(e)}")

# ------------------- ENDPOINTS -------------------
@app.get("/")
def root():
    return {
        "name": "Vulnerability Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "/": "API information",
            "/health": "Health check",
            "/scan": "POST - Scan repository for vulnerabilities (URL)",
            "/scan-upload": "POST - Scan uploaded dependency files",
            "/ml/predict": "POST - ML-powered vulnerability prediction for source code",
            "/ml/feedback": "POST - Submit feedback for ML predictions",
            "/ws/scan": "WebSocket - Real-time scan progress",
            "/docs": "Interactive API documentation",
        }
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "vulnerability-scanner"}

# ------------------- SCAN -------------------
@app.post("/scan")
def scan_endpoint(payload: ScanRequest):
    result = call_dependency_scanner(repo_path=payload.repo_url)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Unknown scan error"))
    return result

@app.post("/scan-upload")
async def scan_upload_endpoint(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    temp_dir = tempfile.mkdtemp(prefix="vuln_scan_upload_")
    try:
        uploaded_filenames = []

        # Save uploaded files
        for f in files:
            content = await f.read()
            path = Path(temp_dir) / f.filename
            path.write_bytes(content)
            uploaded_filenames.append(f.filename)

        # Extract ZIP if uploaded
        first_file = files[0]
        if first_file.filename.lower().endswith(".zip"):
            zip_path = Path(temp_dir) / first_file.filename
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            zip_path.unlink()

        # Gather dependency and source files
        manifest_files = find_dependency_files(temp_dir)
        source_files = extract_source_files(temp_dir, include_content=True)

        dep_files_for_service = []
        for file_path, _ in manifest_files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                dep_files_for_service.append({"path": str(file_path.relative_to(temp_dir)), "content": content})
            except Exception:
                continue

        dep_result = call_dependency_scanner(files=dep_files_for_service) if dep_files_for_service else {"success": True, "dependencies": [], "summary": {}}

        return {
            "success": True,
            "repo_path": f"Uploaded: {', '.join(uploaded_filenames)}",
            "dependencies": dep_result.get("dependencies", []),
            "source_files": source_files,
            "source_files_summary": {
                "total_files": len(source_files),
                "files_with_content": sum(1 for f in source_files if f.get("content")),
                "by_language": {f.get("language", "Unknown"): sum(1 for f2 in source_files if f2.get("language") == f.get("language")) for f in source_files},
                "total_lines_of_code": sum(f.get("lines_of_code", 0) for f in source_files)
            },
            "summary": dep_result.get("summary", {}),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ------------------- ML -------------------
@app.post("/ml/predict")
async def ml_predict_endpoint(payload: dict):
    files = payload.get("files")
    
    # Accept single file (dict) or list of files
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    if isinstance(files, dict):
        files = [files]
    elif not isinstance(files, list):
        raise HTTPException(status_code=400, detail="Invalid files format")

    if len(files) > 30:
        raise HTTPException(status_code=400, detail="Maximum 30 files per request")

    # Ensure content is string and strip properly
    for f in files:
        content = f.get("content")
        if isinstance(content, list):
            # Join list of lines into a single string
            f["content"] = "\n".join(str(line) for line in content)
        elif content is None:
            f["content"] = ""

    try:
        analyzer = get_analyzer()
        predictions = analyzer.predict_batch(files)
        
        # Calculate summary
        vulnerable_count = sum(
            1 for p in predictions
            if p.get("success") and p.get("prediction") == "VULNERABLE"
        )
        safe_count = sum(
            1 for p in predictions
            if p.get("success") and p.get("prediction") == "SAFE"
        )
        failed_count = sum(1 for p in predictions if not p.get("success"))
        
        return {
            "success": True,
            "predictions": predictions,
            "summary": {
                "total_files": len(files),
                "vulnerable_files": vulnerable_count,
                "safe_files": safe_count,
                "failed_files": failed_count
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(e)}")


@app.post("/ml/feedback")
async def ml_feedback_endpoint(payload: dict):
    try:
        send_feedback_email(
            predictions=payload.get("predictions", []),
            general_comment=payload.get("general_comment", ""),
            timestamp=payload.get("timestamp", "")
        )
        return {"success": True, "message": "Feedback received successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feedback failed: {str(e)}")

# ------------------- WEBSOCKET -------------------
@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_text()
        request_data = json.loads(data)
        repo_url = request_data.get("repo_url")
        if not repo_url:
            await websocket.send_json({"type": "error", "message": "repo_url required"})
            await websocket.close()
            return

        loop = asyncio.get_event_loop()
        def run_scan():
            return scan_dependencies(repo_path=repo_url)
        result = await loop.run_in_executor(None, run_scan)

        if result.get("success"):
            await websocket.send_json({"type": "complete", "data": result})
        else:
            await websocket.send_json({"type": "error", "message": result.get("error", "Scan failed")})
    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
    finally:
        await websocket.close()
