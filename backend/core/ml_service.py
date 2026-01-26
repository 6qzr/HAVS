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
    ML-powered vulnerability analyzer using UnixCoder tokenizer
    Matches the implementation from GraphCodeBERT.ipynb exactly
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the vulnerability analyzer
        Matches GraphCodeBERT.ipynb exactly - uses base model by default
        
        Args:
            model_path: Path to model (optional, uses base GraphCodeBERT model if not provided)
        """
        # Track prediction statistics for bias detection
        self.prediction_history = {"SAFE": 0, "VULNERABLE": 0}
        self.logit_diffs = []  # Track logit differences to detect bias
        self.is_base_model = False  # Track if we're using base (untrained) model
        # Use base model by default (matches GraphCodeBERT.ipynb)
        if model_path is None:
            model_path = "microsoft/graphcodebert-base"
        
        print(f"[ML Service] Loading model from: {model_path}")
        start_time = time.time()
        
        # Set device (GPU if available, otherwise CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"[ML Service] Using device: {self.device}")
        
        # Load the base unixcoder tokenizer (matches GraphCodeBERT.ipynb exactly)
        print("[ML Service] Loading tokenizer...")
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/unixcoder-base")
        
        # Load model (matches GraphCodeBERT.ipynb exactly)
        # If model_path is a local path, check if it exists
        if not model_path.startswith("microsoft/") and not model_path.startswith("http"):
            model_path_obj = Path(model_path)
            if not model_path_obj.exists():
                raise FileNotFoundError(
                    f"Model not found at: {model_path}\n"
                    f"Please ensure the model directory exists with config.json and model files."
                )
            model_path = str(model_path_obj.resolve())
        
        print("[ML Service] Loading model...")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_path,
            output_attentions=True,
            num_labels=2
        )
        self.model.to(self.device)
        self.model.eval()
        
        # Warn if using base model (not fine-tuned)
        if model_path == "microsoft/graphcodebert-base":
            self.is_base_model = True
            print("[ML Warning] Using base model without fine-tuning. Predictions may be unreliable.")
            print("[ML Warning] Consider using a fine-tuned model for better accuracy.")
            print("[ML Warning] Applying aggressive bias correction for base model.")
        
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
        
        # 1. Tokenize Code with Offsets (matches GraphCodeBERT.ipynb exactly)
        # We need offsets to map tokens back to specific lines of code
        inputs = self.tokenizer(
            code,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding="max_length",
            return_offsets_mapping=True  # Critical for mapping tokens to lines
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
        
        # Get raw logits (before softmax) - more informative for untrained models
        raw_logits = logits[0].cpu().numpy()
        logit_safe = raw_logits[0].item()  # Index 0 = SAFE
        logit_vuln = raw_logits[1].item()  # Index 1 = VULNERABLE
        
        # Get probabilities
        safe_score = probs[0][0].item()  # Index 0 = SAFE
        vuln_score = probs[0][1].item()  # Index 1 = VULNERABLE
        
        # Debug: Print raw logits and probabilities to diagnose issues
        print(f"[ML Debug] Raw logits: safe={logit_safe:.4f}, vuln={logit_vuln:.4f}")
        print(f"[ML Debug] Probabilities: safe={safe_score:.4f}, vuln={vuln_score:.4f}")
        
        # Calculate logit difference (more stable than probability difference)
        logit_diff = logit_vuln - logit_safe
        
        # Track logit differences for bias detection
        self.logit_diffs.append(logit_diff)
        if len(self.logit_diffs) > 100:  # Keep only recent history
            self.logit_diffs.pop(0)
        
        # Detect bias: if logit_diff is consistently negative, model is biased toward SAFE
        # Calculate average logit difference to detect systematic bias
        avg_logit_diff = np.mean(self.logit_diffs) if self.logit_diffs else 0.0
        
        # For base models (not fine-tuned), use aggressive bias correction
        # Base models often have randomly initialized classification heads that are biased
        # Use a negative threshold to compensate for bias toward SAFE
        if self.is_base_model:
            # Base model: use more aggressive negative threshold
            if len(self.logit_diffs) > 5:
                # After a few predictions, use adaptive threshold based on observed bias
                if avg_logit_diff < -0.3:
                    print(f"[ML Warning] Detected strong bias toward SAFE (avg_logit_diff={avg_logit_diff:.4f}). Applying aggressive correction.")
                    # Use a threshold that compensates for the bias - make it more negative
                    bias_threshold = avg_logit_diff * 0.7  # More aggressive correction
                elif avg_logit_diff < -0.1:
                    bias_threshold = -0.3  # Moderate bias correction
                else:
                    bias_threshold = -0.2  # Default negative threshold for base models
            else:
                # For first few predictions, use a more aggressive negative threshold
                # This helps when the model is biased from the start
                bias_threshold = -0.25
        else:
            # Fine-tuned model: use standard threshold
            bias_threshold = 0.0
        
        # If logits are very close, the model is uncertain
        if abs(logit_diff) < 0.05:
            print(f"[ML Warning] Model outputs are very close (logit_diff={logit_diff:.4f}). Model may not be fine-tuned.")
            # When very uncertain, use probability-based decision with lower threshold
            if vuln_score > 0.4:  # Lower threshold for VULNERABLE
                prediction = "VULNERABLE"
                confidence = vuln_score
            else:
                prediction = "SAFE"
                confidence = safe_score
        else:
            # Use logit difference for prediction (more robust than probabilities)
            # Apply bias correction threshold - more negative threshold = more likely to predict VULNERABLE
            if logit_diff > bias_threshold:
                prediction = "VULNERABLE"
                confidence = vuln_score
            else:
                prediction = "SAFE"
                confidence = safe_score
        
        # Track prediction for bias detection
        self.prediction_history[prediction] += 1
        
        result = {
            "prediction": prediction,
            "confidence": round(float(confidence), 4),
            "vuln_score": round(float(vuln_score), 4),
            "safe_score": round(float(safe_score), 4)
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
    
    # Use base model by default (matches GraphCodeBERT.ipynb)
    if model_path is None:
        model_path = "microsoft/graphcodebert-base"
    
    # Create new instance if:
    # 1. No instance exists yet, OR
    # 2. Model path has changed
    if _analyzer_instance is None or _model_path != model_path:
        print(f"[ML Service] Creating new analyzer instance...")
        _analyzer_instance = VulnerabilityAnalyzer(model_path)
        _model_path = model_path
    
    return _analyzer_instance


# ============= QUICK TEST FUNCTION =============
def test_analyzer():
    """Quick test function for debugging"""
    test_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    result = db.execute(query)
    return result
"""
    
    analyzer = get_analyzer()
    result = analyzer.predict_single(test_code)
    
    print("\n" + "="*60)
    print("Test Result:")
    print(f"  Prediction: {result['prediction']}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Risk Level: {analyzer._get_risk_level(result)}")
    print("="*60)
    
    return result


if __name__ == "__main__":
    # Run test if executed directly
    print("Running ML Service Test...")
    test_analyzer()

