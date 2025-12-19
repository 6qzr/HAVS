#!/usr/bin/env python3
"""
GitHub Webhook Handler
Handles GitHub webhook events and posts results back to GitHub
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime

class GitHubWebhookHandler:
    """Handle GitHub webhook events and post results"""
    
    def __init__(self, github_token: str):
        """
        Initialize GitHub webhook handler
        
        Args:
            github_token: GitHub personal access token with repo permissions
        """
        self.github_token = github_token
        self.github_api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def post_pr_comment(self, repo: str, pr_number: int, comment: str) -> bool:
        """
        Post a comment on a pull request
        
        Args:
            repo: Repository in format "owner/repo"
            pr_number: Pull request number
            comment: Comment text (supports markdown)
            
        Returns:
            True if successful, False otherwise
        """
        url = f"{self.github_api_base}/repos/{repo}/issues/{pr_number}/comments"
        
        data = {
            "body": comment
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error posting PR comment: {e}")
            return False
    
    def post_commit_comment(self, repo: str, commit_sha: str, comment: str, path: Optional[str] = None, line: Optional[int] = None) -> bool:
        """
        Post a comment on a commit
        
        Args:
            repo: Repository in format "owner/repo"
            commit_sha: Commit SHA
            comment: Comment text
            path: Optional file path
            line: Optional line number
            
        Returns:
            True if successful, False otherwise
        """
        url = f"{self.github_api_base}/repos/{repo}/commits/{commit_sha}/comments"
        
        data = {
            "body": comment
        }
        
        if path:
            data["path"] = path
        if line:
            data["line"] = line
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error posting commit comment: {e}")
            return False
    
    def create_check_run(self, repo: str, commit_sha: str, name: str, status: str, conclusion: Optional[str] = None, output: Optional[Dict] = None) -> bool:
        """
        Create a GitHub check run
        
        Args:
            repo: Repository in format "owner/repo"
            commit_sha: Commit SHA
            name: Check run name
            status: "queued", "in_progress", or "completed"
            conclusion: "success", "failure", "neutral", "cancelled", or "skipped" (if status is "completed")
            output: Optional output dict with "title" and "summary"
            
        Returns:
            True if successful, False otherwise
        """
        url = f"{self.github_api_base}/repos/{repo}/check-runs"
        
        data = {
            "name": name,
            "head_sha": commit_sha,
            "status": status
        }
        
        if status == "completed":
            if conclusion:
                data["conclusion"] = conclusion
            else:
                data["conclusion"] = "success"
        
        if output:
            data["output"] = output
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Error creating check run: {e}")
            return False
    
    def format_dependency_results(self, scan_result: Dict) -> str:
        """Format dependency scan results as markdown"""
        if not scan_result.get("success"):
            return f"## ❌ Dependency Scan Failed\n\n{scan_result.get('error', 'Unknown error')}"
        
        summary = scan_result.get("summary", {})
        deps_scanned = summary.get("total_deps_scanned", 0)
        deps_vulnerable = summary.get("deps_with_vulnerabilities", 0)
        total_vulns = summary.get("total_vulnerabilities", 0)
        
        severity = summary.get("vulnerabilities_by_severity", {})
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)
        medium = severity.get("medium", 0)
        low = severity.get("low", 0)
        
        markdown = f"""## 🔍 Dependency Vulnerability Scan Results

### Summary
- **Total Dependencies Scanned:** {deps_scanned}
- **Vulnerable Dependencies:** {deps_vulnerable}
- **Total Vulnerabilities:** {total_vulns}

### Severity Breakdown
- 🔴 **Critical:** {critical}
- 🟠 **High:** {high}
- 🟡 **Medium:** {medium}
- 🟢 **Low:** {low}

"""
        
        if deps_vulnerable > 0:
            markdown += "### ⚠️ Vulnerable Dependencies\n\n"
            dependencies = scan_result.get("dependencies", [])
            for dep in dependencies[:10]:  # Show top 10
                dep_name = dep.get("name", "Unknown")
                dep_version = dep.get("version", "Unknown")
                cve_count = len(dep.get("cves", []))
                markdown += f"- **{dep_name}** v{dep_version}: {cve_count} CVE(s)\n"
            
            if len(dependencies) > 10:
                markdown += f"\n*... and {len(dependencies) - 10} more*\n"
        else:
            markdown += "### ✅ No Vulnerabilities Found\n\nAll dependencies are secure!\n"
        
        markdown += f"\n---\n*Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return markdown
    
    def format_ml_results(self, ml_result: Dict) -> str:
        """Format ML prediction results as markdown"""
        if not ml_result.get("success"):
            return f"## ❌ ML Analysis Failed\n\n{ml_result.get('error', 'Unknown error')}"
        
        summary = ml_result.get("summary", {})
        total_files = summary.get("total_files", 0)
        vulnerable_files = summary.get("vulnerable_files", 0)
        safe_files = summary.get("safe_files", 0)
        analysis_time = summary.get("analysis_time_seconds", 0)
        
        markdown = f"""## 🤖 ML Vulnerability Analysis Results

### Summary
- **Total Files Analyzed:** {total_files}
- **⚠️ Vulnerable Files:** {vulnerable_files}
- **✅ Safe Files:** {safe_files}
- **Analysis Time:** {analysis_time}s

"""
        
        if vulnerable_files > 0:
            markdown += "### ⚠️ Vulnerable Files Detected\n\n"
            predictions = ml_result.get("predictions", [])
            vulnerable_preds = [p for p in predictions if p.get("success") and p.get("prediction") == "VULNERABLE"]
            
            for pred in vulnerable_preds[:10]:  # Show top 10
                file_path = pred.get("file", "Unknown")
                risk_level = pred.get("risk_level", "UNKNOWN")
                confidence = pred.get("confidence", 0)
                confidence_pct = int(confidence * 100)
                
                risk_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(risk_level, "⚪")
                
                markdown += f"- {risk_emoji} **{file_path}** - {risk_level} (Confidence: {confidence_pct}%)\n"
            
            if len(vulnerable_preds) > 10:
                markdown += f"\n*... and {len(vulnerable_preds) - 10} more*\n"
        else:
            markdown += "### ✅ No Vulnerabilities Detected\n\nAll source code files appear to be secure!\n"
        
        markdown += f"\n---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        
        return markdown

