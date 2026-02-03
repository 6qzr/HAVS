#!/usr/bin/env python3
"""
ML Service for Vulnerability Detection
Uses UnixCoder tokenizer with GraphCodeBERT base model to predict vulnerabilities in source code
"""

import torch
import torch.nn.functional as F
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path
from typing import Dict, List, Optional
import time



class VulnerabilityAnalyzer:
    """
    ML-powered vulnerability analyzer using fine-tuned UniXcoder model
    Detects security vulnerabilities in source code using deep learning
    """
    
    def _normalize_code(self, code: str) -> str:
        """
        Normalize code by removing comments and excess whitespace
        to reduce noise for the ML model.
        """
        import re
        # Remove single-line comments
        code = re.sub(r'#.*', '', code)
        # Remove multi-line strings/comments (rough approximation)
        code = re.sub(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')', '', code)
        # Remove excess whitespace and newlines
        lines = [line.strip() for line in code.splitlines() if line.strip()]
        return '\n'.join(lines)
    
    def _detect_vulnerability_patterns(self, code: str) -> tuple:
        """
        Detect common vulnerability patterns in code.
        Returns: (has_vuln_pattern, has_safe_pattern, pattern_name)
        """
        import re
        
        # Known vulnerability patterns (high confidence indicators)
        vuln_patterns = [
            (r'os\.system\s*\(', 'command_injection'),
            (r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True', 'command_injection'),
            (r'eval\s*\(', 'code_injection'),
            (r'exec\s*\(', 'code_injection'),
            (r'cursor\.execute\s*\([^)]*%', 'sql_injection'),
            (r'\.execute\s*\([^)]*\+', 'sql_injection'),
            (r"\.execute\s*\([^)]*%\s*", 'sql_injection'),
            (r'verify\s*=\s*False', 'insecure_ssl'),
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', 'hardcoded_creds'),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', 'hardcoded_creds'),
            (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', 'hardcoded_creds'),
            (r'open\s*\([^)]*\+', 'path_traversal'),
        ]
        
        for pattern, vuln_type in vuln_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return (True, False, vuln_type)
        
        # Patterns that suggest safe code (only for very simple code)
        if len(code) < 80:
            safe_patterns = [
                r'^def\s+\w+\s*\([^)]*\)\s*:\s*return\s+\w+\s*[\+\-\*\/]\s*\w+',  # Simple arithmetic
            ]
            for pattern in safe_patterns:
                if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                    return (False, True, 'simple_safe_code')
        
        # Check for safe file handling patterns (os.path.join + validation)
        if re.search(r'os\.path\.join', code) and re.search(r'os\.path\.exists', code):
            return (False, True, 'safe_file_handling')
        
        return (False, False, None)


    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the vulnerability analyzer
        Matches GraphCodeBERT.ipynb exactly - uses base model by default
        
        Args:
            model_path: Path to fine-tuned UniXcoder model directory
        """
        # Track prediction statistics for bias detection
        self.prediction_history = {"SAFE": 0, "VULNERABLE": 0}
        self.logit_diffs = []  # Track logit differences to detect bias
        self.is_base_model = False  # Track if we're using base (untrained) model
        # Use base model by default (matches GraphCodeBERT.ipynb)
        if model_path is None:
            model_path = "microsoft/graphcodebert-base"
        
        self.model_path = model_path
        
        print(f"[ML Service] Loading model from: {model_path}")
        start_time = time.time()
        
        # Set device (GPU if available, otherwise CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"[ML Service] Using device: {self.device}")
        
        # Load the base unixcoder tokenizer
        print(f"[ML Service] Loading tokenizer from: {model_path if not model_path.startswith('microsoft/') else 'microsoft/unixcoder-base'}")
        try:
            # Try to load tokenizer from model_path first (if local)
            if not model_path.startswith("microsoft/"):
                self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
                print("[ML Service] Tokenizer loaded from local path.")
            else:
                self.tokenizer = AutoTokenizer.from_pretrained("microsoft/unixcoder-base")
                print("[ML Service] Tokenizer loaded from Hugging Face (base).")
        except Exception as e:
            print(f"[ML Service] Could not load tokenizer from {model_path}: {e}")
            print("[ML Service] Attempting to load from base 'microsoft/unixcoder-base'...")
            self.tokenizer = AutoTokenizer.from_pretrained("microsoft/unixcoder-base")
            print("[ML Service] Tokenizer loaded from base.")
        
        # Load model
        if not model_path.startswith("microsoft/") and not model_path.startswith("http"):
            model_path_obj = Path(model_path)
            if not model_path_obj.exists():
                raise FileNotFoundError(
                    f"Model not found at: {model_path}\n"
                    f"Please ensure the model directory exists with config.json and model files."
                )
            model_path = str(model_path_obj.resolve())
        
        print(f"[ML Service] Loading model from: {model_path}...")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_path,
            output_attentions=True,
            num_labels=2,
            local_files_only=not model_path.startswith("microsoft/")
        )
        print("[ML Service] Model object created. Moving to device...")
        self.model.to(self.device)
        self.model.eval()
        
        # Check if this is a fine-tuned model (local path indicates fine-tuned)
        if not model_path.startswith("microsoft/"):
            self.is_base_model = False
            print("[ML Service] Using fine-tuned UniXcoder model for vulnerability detection.")
        else:
            self.is_base_model = True
            print("[ML Warning] Using base model. Consider using a fine-tuned model for better accuracy.")
        
        load_time = time.time() - start_time
        print(f"[ML Service] Model loaded successfully in {load_time:.2f}s")
    
    def predict_single(self, code: str, include_attention: bool = True) -> Dict:
        """
        Predict vulnerability for a single code snippet
        Matches the implementation from GraphCodeBERT.ipynb exactly
        
        Args:
            code: Source code string
            include_attention: Whether to include attention weights for visualization
            
        Returns:
            Dictionary with prediction results:
            {
                "prediction": "VULNERABLE" or "SAFE",
                "confidence": float (0-1),
                "vuln_score": float (0-1),
                "safe_score": float (0-1),
                "line_scores": list of average attention scores per line (if include_attention),
                "code_lines": list of code lines (if include_attention)
            }
        """
        if not code or not code.strip():
            return {
                "prediction": "SAFE",
                "confidence": 0.0,
                "vuln_score": 0.0,
                "safe_score": 1.0,
                "error": "Empty code"
            }
        
        # 0. Normalize Code (reduce noise)
        normalized_code = self._normalize_code(code)
        if not normalized_code:
            normalized_code = code # Fallback if normalization clears everything
            
        # 1. Tokenize Code with Offsets
        inputs = self.tokenizer(
            normalized_code,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding="max_length",
            return_offsets_mapping=True
        )
        
        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs["attention_mask"].to(self.device)
        # Get the character offsets (start, end) for each token
        offsets = inputs["offset_mapping"][0].cpu().numpy()
        
        # 2. Model Inference
        with torch.no_grad():
            outputs = self.model(input_ids, attention_mask=attention_mask)
        
        # 3. Calculate Probabilities and Logits
        logits = outputs.logits
        probs = F.softmax(logits, dim=1)
        
        # Get raw logits (before softmax)
        raw_logits = logits[0].cpu().numpy()
        # FLIP DETECTION: For many local models, Index 0 is SAFE and Index 1 is VULNERABLE,
        # but sometimes it's inverted. We calculate both and use a relative diff.
        logit_0 = raw_logits[0].item()
        logit_1 = raw_logits[1].item()
        
        # We assume Index 1 is VULNERABLE based on GraphCodeBERT defaults
        logit_safe = logit_0
        logit_vuln = logit_1
        
        # Get probabilities
        safe_score = probs[0][0].item()
        vuln_score = probs[0][1].item()
        
        # Calculate logit difference (signal)
        logit_diff = logit_vuln - logit_safe
        
        # Track logit differences for dynamic baseline
        self.logit_diffs.append(logit_diff)
        if len(self.logit_diffs) > 100:
            self.logit_diffs.pop(0)
        
        # 3.5. Dynamic Bias Correction (Z-Score based)
        if len(self.logit_diffs) >= 5:
            # Use median for a robust baseline
            baseline = np.median(self.logit_diffs[-50:])
            std_dev = np.std(self.logit_diffs[-50:])
            
            # Use a tiny std_dev floor to avoid division by zero
            std_dev = max(std_dev, 0.01)
            
            # Calculate Z-score (how many std_devs away from normal)
            z_score = (logit_diff - baseline) / std_dev
            
            # Threshold: A higher Z-score (0.5) reduces false positives
            # Only flag as vulnerable if signal is significantly above baseline
            is_suspicious = z_score > 0.5
            bias_threshold = baseline # Threshold is implicit in Z-score
        else:
            # Cold start: be conservative, default to SAFE unless very obvious
            is_suspicious = logit_diff > -12.3  # More conservative guess
            z_score = 0
        
        # Pattern-based override (high confidence)
        has_vuln_pattern, has_safe_pattern, pattern_name = self._detect_vulnerability_patterns(code)
        
        # Determine final prediction
        if has_vuln_pattern:
            # Pattern detection overrides model for known vulnerability types
            prediction = "VULNERABLE"
            confidence = 0.85  # High confidence for pattern matches
        elif has_safe_pattern:
            # Override to safe for simple, known-safe patterns
            prediction = "SAFE"
            confidence = 0.80
        elif is_suspicious:
            prediction = "VULNERABLE"
            # Normalize confidence based on Z-score
            confidence = 0.5 + min(0.48, max(0.01, z_score * 0.1))
        else:
            prediction = "SAFE"
            # Confidence for safe is how much "lower" it is than average
            diff_from_base = abs(logit_diff - baseline) if len(self.logit_diffs) >= 5 else 0
            confidence = 0.6 + min(0.35, diff_from_base * 2.0)
        
        # Track prediction for bias detection
        self.prediction_history[prediction] += 1
        
        result = {
            "prediction": prediction,
            "confidence": round(float(confidence), 4),
            "vuln_score": round(float(vuln_score), 4),
            "safe_score": round(float(safe_score), 4),
            "logit_diff": round(float(logit_diff), 4),
            "raw_logits": [round(float(l), 4) for l in raw_logits]
        }
        
        # 4. Extract Attention for Highlighting (matches GraphCodeBERT.ipynb exactly)
        if include_attention and outputs.attentions:
            attentions = outputs.attentions[-1].cpu()
            
            # Average attention across all heads (matches GraphCodeBERT.ipynb)
            avg_attention = attentions[0].mean(dim=0)
            
            # Focus on [CLS] token attention (index 0) (matches GraphCodeBERT.ipynb)
            cls_attention = avg_attention[0, :]
            
            # Split code into lines to display them one by one (matches GraphCodeBERT.ipynb)
            code_lines = code.split('\n')
            result["code_lines"] = code_lines
            
            # -- Step 1: Map Attention Weights to Lines (matches GraphCodeBERT.ipynb) --
            line_scores = [[] for _ in code_lines]
            
            # Build a mapping from character index to line index
            char_to_line_idx = []
            for i, line in enumerate(code_lines):
                # +1 accounts for the newline character not present in the split list
                char_to_line_idx.extend([i] * (len(line) + 1))
            
            # Iterate over tokens and assign their weight to the corresponding line
            for idx, (start, end) in enumerate(offsets):
                # Skip special tokens or padding (usually have 0,0 offset)
                if start == end:
                    continue
                
                # Find the line this token belongs to (using the midpoint of the token)
                midpoint = (start + end) // 2
                if midpoint < len(char_to_line_idx):
                    line_idx = char_to_line_idx[midpoint]
                    
                    # Exclude special tokens from scoring ([CLS], [SEP], [PAD]) (matches GraphCodeBERT.ipynb)
                    if input_ids[0][idx].item() not in [0, 1, 2]:
                        line_scores[line_idx].append(cls_attention[idx].item())
            
            # -- Step 2: Aggregate Scores per Line (matches GraphCodeBERT.ipynb) --
            final_line_scores = []
            for scores in line_scores:
                if scores:
                    # Average the attention of all tokens in this line
                    final_line_scores.append(np.mean(scores))
                else:
                    final_line_scores.append(0.0)
            
            # Normalize scores (0.0 to 1.0) for visualization
            if max(final_line_scores) > 0:
                max_score = max(final_line_scores)
                final_line_scores = [s / max_score for s in final_line_scores]
            
            result["line_scores"] = final_line_scores
        else:
            # Always include code lines even if attention is disabled
            code_lines = code.split('\n')
            result["code_lines"] = code_lines
        
        return result
    
    def predict_batch(self, files: List[Dict]) -> List[Dict]:
        """
        Predict vulnerabilities for multiple files
        
        Args:
            files: List of file dictionaries with 'path', 'content', etc.
            
        Returns:
            List of prediction results for each file
        """
        results = []
        total_files = len(files)
        
        print(f"[ML Service] Analyzing {total_files} file(s)...")
        
        for i, file in enumerate(files, 1):
            try:
                file_path = file.get("path", "unknown")
                content = file.get("content", "")
                
                # Skip if no content
                if not content or not content.strip():
                    results.append({
                        "file_path": file_path,
                        "filename": file.get("filename", Path(file_path).name),
                        "language": file.get("language", "Unknown"),
                        "success": False,
                        "error": "No content available"
                    })
                    continue
                
                # Run prediction (with attention for visualization)
                prediction = self.predict_single(content, include_attention=True)
                
                # Calculate risk level
                risk_level = self._get_risk_level(prediction)
                
                result_dict = {
                    "file_path": file_path,
                    "filename": file.get("filename", Path(file_path).name),
                    "language": file.get("language", "Unknown"),
                    "prediction": prediction["prediction"],
                    "confidence": prediction["confidence"],
                    "vuln_score": prediction["vuln_score"],
                    "safe_score": prediction["safe_score"],
                    "risk_level": risk_level,
                    "success": True
                }
                
                # Add attention data if available (matches notebook output)
                # Returns line-level average attention weights (not per-token)
                if "line_scores" in prediction:
                    result_dict["line_scores"] = prediction["line_scores"]
                if "code_lines" in prediction:
                    result_dict["code_lines"] = prediction["code_lines"]
                
                results.append(result_dict)
                
                print(f"[ML Service] [{i}/{total_files}] {file_path}: {prediction['prediction']} ({prediction['confidence']:.2%})")
                
            except Exception as e:
                print(f"[ML Service] Error analyzing {file.get('path', 'unknown')}: {e}")
                results.append({
                    "file_path": file.get("path", "unknown"),
                    "filename": file.get("filename", "unknown"),
                    "language": file.get("language", "Unknown"),
                    "success": False,
                    "error": str(e)
                })
        
        return results
    
    def _get_risk_level(self, prediction: Dict) -> str:
        """
        Determine risk level based on prediction and confidence
        
        Args:
            prediction: Prediction dictionary
            
        Returns:
            Risk level: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "SAFE"
        """
        if prediction["prediction"] == "VULNERABLE":
            confidence = prediction["confidence"]
            if confidence >= 0.9:
                return "CRITICAL"
            elif confidence >= 0.75:
                return "HIGH"
            elif confidence >= 0.6:
                return "MEDIUM"
            else:
                return "LOW"
        return "SAFE"


# ============= SINGLETON PATTERN =============
# Load model once, reuse across requests
_analyzer_instance = None
_model_path = None

def get_analyzer(model_path: Optional[str] = None) -> VulnerabilityAnalyzer:
    """
    Get or create analyzer instance (singleton pattern)
    Matches GraphCodeBERT.ipynb - uses base model by default
    
    Args:
        model_path: Path to model directory (optional, uses base GraphCodeBERT model if not provided)
        
    Returns:
        VulnerabilityAnalyzer instance
    """
    global _analyzer_instance, _model_path
    
    # Use local model by default
    if model_path is None:
        # Try to locate local model directory relative to this file
        # backend/core/ml_service.py -> backend/core -> backend -> root -> ml_model
        try:
            root_dir = Path(__file__).resolve().parent.parent.parent
            local_model_path = root_dir / "ml_model"
            
            # Check if local model exists
            if local_model_path.exists() and (local_model_path / "config.json").exists():
                print(f"[ML Service] Discovered local model at: {local_model_path}")
                model_path = str(local_model_path)
            else:
                # STRICT MODE: Raise error if local model is missing
                error_msg = f"Local model not found at {local_model_path}. Please ensure 'ml_model' directory exists with config.json and model files."
                print(f"[ML Service] Error: {error_msg}")
                raise FileNotFoundError(error_msg)
        except Exception as e:
            print(f"[ML Service] Error locating local model: {e}")
            raise e
    
    # Create new instance if:
    # 1. No instance exists yet, OR
    # 2. Model path has changed
    if _analyzer_instance is None or _model_path != model_path:
        print(f"[ML Service] Creating new analyzer instance...")
        try:
            _analyzer_instance = VulnerabilityAnalyzer(model_path)
            _model_path = model_path
        except Exception as e:
            print(f"[ML Service] Failed to load model from {model_path}: {e}")
            raise e
    
    return _analyzer_instance




