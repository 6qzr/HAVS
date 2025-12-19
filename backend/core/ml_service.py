#!/usr/bin/env python3
"""
ML Service for Vulnerability Detection
Uses RoBERTa (CodeBERT) model to predict vulnerabilities in source code
"""

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path
from typing import Dict, List, Optional
import time


class VulnerabilityAnalyzer:
    """
    ML-powered vulnerability analyzer using RoBERTa model
    """
    
    def __init__(self, model_path: str):
        """
        Initialize the vulnerability analyzer
        
        Args:
            model_path: Path to the trained model directory
        """
        print(f"[ML Service] Loading model from: {model_path}")
        start_time = time.time()
        
        # Check if model exists
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found at: {model_path}")
        
        # Set device (GPU if available, otherwise CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"[ML Service] Using device: {self.device}")
        
        # Load tokenizer (CodeBERT base)
        print("[ML Service] Loading tokenizer...")
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        
        # Load trained model
        print("[ML Service] Loading trained model...")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            str(model_path),
            num_labels=2,
            output_attentions=True,  # Enable attention for code highlighting
            output_hidden_states=False
        )
        self.model.to(self.device)
        self.model.eval()  # Set to evaluation mode
        
        load_time = time.time() - start_time
        print(f"[ML Service] Model loaded successfully in {load_time:.2f}s")
    
    def predict_single(self, code: str, include_attention: bool = True) -> Dict:
        """
        Predict vulnerability for a single code snippet
        
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
                "tokens": list of tokens (if include_attention),
                "attention_weights": list of attention scores (if include_attention)
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
        
        # 1. Tokenize code
        inputs = self.tokenizer(
            code,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding="max_length"
        )
        
        # 2. Move to device
        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs["attention_mask"].to(self.device)
        
        # 3. Run inference
        with torch.no_grad():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
        
        # 4. Calculate probabilities
        logits = outputs.logits
        probs = F.softmax(logits, dim=1)
        
        # 5. Extract scores
        safe_score = probs[0][0].item()
        vuln_score = probs[0][1].item()
        
        # 6. Determine prediction
        prediction = "VULNERABLE" if vuln_score > safe_score else "SAFE"
        confidence = vuln_score if prediction == "VULNERABLE" else safe_score
        
        result = {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "vuln_score": round(vuln_score, 4),
            "safe_score": round(safe_score, 4)
        }
        
        # 7. Extract attention weights for visualization (if requested)
        if include_attention and outputs.attentions:
            # Get attention from the last layer (most relevant for final decision)
            # Shape: (batch_size, num_heads, seq_len, seq_len)
            attentions = outputs.attentions[-1].cpu()
            
            # Average attention across all heads
            # Shape: (seq_len, seq_len)
            avg_attention = attentions[0].mean(dim=0)
            
            # Get attention weights from [CLS] token (index 0) to all other tokens
            # This tells us which tokens the model focused on to make its decision
            cls_attention = avg_attention[0, :]
            
            # Convert input_ids to tokens for display
            tokens = self.tokenizer.convert_ids_to_tokens(input_ids[0].cpu())
            
            # Normalize attention weights (0-1 scale)
            attention_weights = cls_attention.tolist()
            
            # Add to result
            result["tokens"] = tokens
            result["attention_weights"] = attention_weights
        
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
                
                # Add attention data if available
                if "tokens" in prediction and "attention_weights" in prediction:
                    result_dict["tokens"] = prediction["tokens"]
                    result_dict["attention_weights"] = prediction["attention_weights"]
                
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
    
    Args:
        model_path: Path to model directory (optional, uses default if not provided)
        
    Returns:
        VulnerabilityAnalyzer instance
    """
    global _analyzer_instance, _model_path
    
    # Use default path if not provided
    if model_path is None:
        default_path = Path(__file__).parent.parent.parent / "ml_models" / "Model2_Transfer_OOD"
        model_path = str(default_path)
    
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

