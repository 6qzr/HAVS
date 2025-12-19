#!/usr/bin/env python3
"""
ML Analysis Service
Provides ML-powered vulnerability detection for source code
Runs on port 8002
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Union
import time

# Import ML service
from backend.core.ml_service import get_analyzer

app = FastAPI(
    title="ML Analysis Service",
    description="ML-powered vulnerability detection for source code",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SourceFile(BaseModel):
    path: str
    filename: str
    language: str
    content: str
    lines_of_code: Optional[int] = 0

class PredictRequest(BaseModel):
    files: Union[SourceFile, List[SourceFile]]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Try to get analyzer to check if model is available
        analyzer = get_analyzer()
        return {
            "status": "healthy",
            "service": "ml-analysis",
            "model_loaded": True
        }
    except Exception as e:
        return {
            "status": "degraded",
            "service": "ml-analysis",
            "model_loaded": False,
            "error": str(e)
        }

@app.post("/predict")
async def predict_endpoint(request: PredictRequest):
    """
    Predict vulnerabilities in source code files
    
    Args:
        request: Single file (SourceFile) or list of source code files with content
        
    Returns:
        ML prediction results with confidence scores
    """
    # Accept single file or list of files
    files = request.files
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Convert single file to list for uniform processing
    if isinstance(files, SourceFile):
        files = [files]
    
    if len(files) > 30:
        raise HTTPException(
            status_code=400,
            detail="Maximum 30 files per request"
        )
    
    # Validate files have content
    for file in files:
        # Ensure content is a string (handle case where it might be a list)
        content = file.content
        if isinstance(content, list):
            content = "\n".join(str(line) for line in content)
            file.content = content
        elif not isinstance(content, str):
            content = str(content) if content is not None else ""
            file.content = content
        
        if not content or not content.strip():
            raise HTTPException(
                status_code=400,
                detail=f"File {file.path} has no content"
            )
    
    # Get analyzer (singleton, cached after first load)
    try:
        analyzer = get_analyzer()
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML model not found: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML service error: {str(e)}"
        )
    
    # Prepare files for batch prediction
    files_to_analyze = []
    for file in files:
        files_to_analyze.append({
            "path": file.path,
            "filename": file.filename,
            "language": file.language,
            "content": file.content,
            "lines_of_code": file.lines_of_code
        })
    
    # Run batch prediction
    start_time = time.time()
    try:
        predictions = analyzer.predict_batch(files_to_analyze)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML prediction failed: {str(e)}"
        )
    
    analysis_time = time.time() - start_time
    
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
            "failed_files": failed_count,
            "analysis_time_seconds": round(analysis_time, 2)
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

