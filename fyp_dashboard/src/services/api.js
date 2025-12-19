/**
 * API Service for Backend Integration
 * Handles all communication with the FastAPI backend
 */

// Automatically switch URL based on environment
const API_BASE_URL =
  process.env.NODE_ENV === 'development'
    ? 'http://127.0.0.1:8000'        // local dev
    : 'https://havs.onrender.com';    // deployed backend

class APIService {
  async startScan(repoUrl) {
    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Scan failed');
      }

      return await response.json();
    } catch (error) {
      console.error('Scan error:', error);
      throw error;
    }
  }

  async startScanWithProgress(repoUrl, onProgress = null) {
    return new Promise((resolve, reject) => {
      const wsUrl = API_BASE_URL.replace('http://', 'ws://').replace('https://', 'wss://');
      const ws = new WebSocket(`${wsUrl}/ws/scan`);

      const connectionTimeout = setTimeout(() => {
        ws.close();
        reject(new Error('WebSocket connection timeout'));
      }, 5000);

      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        ws.send(JSON.stringify({ repo_url: repoUrl }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'progress' && onProgress) {
            onProgress(data.percentage, data.message, data.stage);
          } else if (data.type === 'complete') {
            ws.close();
            resolve(data.data);
          } else if (data.type === 'error') {
            ws.close();
            reject(new Error(data.message || 'Scan failed'));
          }
        } catch (error) {
          console.error('WebSocket parsing error:', error);
        }
      };

      ws.onerror = (error) => reject(new Error('WebSocket connection error'));

      ws.onclose = (event) => {
        if (!event.wasClean) console.warn('WebSocket closed unexpectedly');
      };
    });
  }

  async uploadScan(files) {
    try {
      const formData = new FormData();
      const fileArray = Array.isArray(files) ? files : [files];
      fileArray.forEach(file => formData.append('files', file));

      const response = await fetch(`${API_BASE_URL}/scan-upload`, { method: 'POST', body: formData });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Upload scan failed');
      }
      return await response.json();
    } catch (error) {
      console.error('Upload scan error:', error);
      throw error;
    }
  }

  async checkHealth() {
    const response = await fetch(`${API_BASE_URL}/health`);
    return await response.json();
  }

  async getApiInfo() {
    const response = await fetch(`${API_BASE_URL}/`);
    return await response.json();
  }

  async predictVulnerabilities(files) {
    try {
      const response = await fetch(`${API_BASE_URL}/ml/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files })
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'ML prediction failed');
      }
      return await response.json();
    } catch (error) {
      console.error('ML prediction error:', error);
      throw error;
    }
  }

  async submitFeedback(feedbackData) {
    try {
      const response = await fetch(`${API_BASE_URL}/ml/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(feedbackData)
      });
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to submit feedback');
      }
      return await response.json();
    } catch (error) {
      console.error('Feedback submission error:', error);
      throw error;
    }
  }

  transformScanResults(backendData) {
    if (!backendData.success) throw new Error(backendData.error || 'Scan failed');

    const dependencies = backendData.dependencies?.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      vulnerabilityCount: dep.cves?.length || 0,
      hasVulnerabilities: dep.cves?.length > 0,
      cves: dep.cves?.map(cve => ({ ...cve, cisaKev: cve.cisa_kev === 'Yes' })) || []
    })) || [];

    const vulnerabilities = [];
    let cisaKevCount = 0;

    dependencies.forEach(dep => {
      dep.cves?.forEach(cve => {
        const isCisaKev = cve.cisa_kev === 'Yes';
        if (isCisaKev) cisaKevCount++;
        vulnerabilities.push({
          id: cve.cve_id,
          title: cve.cve_id,
          severity: cve.severity,
          cvssScore: cve.cvss_score,
          package: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          affectedVersions: cve.affected_versions,
          url: cve.url,
          cwe: cve.cwe || 'N/A',
          cisaKev: isCisaKev,
          status: 'Confirmed'
        });
      });
    });

    const severity = backendData.summary?.vulnerabilities_by_severity || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    return {
      scanId: `scan_${Date.now()}`,
      timestamp: backendData.scanned_at,
      duration: backendData.scan_duration_seconds,
      repoPath: backendData.repo_path,
      summary: {
        totalDependencies: backendData.summary?.total_deps_scanned || 0,
        totalVulnerabilities: backendData.summary?.total_vulnerabilities || 0,
        vulnerableDependencies: backendData.summary?.deps_with_vulnerabilities || 0,
        criticalCount: severity.critical,
        highCount: severity.high,
        mediumCount: severity.medium,
        lowCount: severity.low,
        cisaKevCount
      },
      dependencies,
      vulnerabilities,
      sourceFiles: backendData.source_files || [],
      sourceFilesSummary: backendData.source_files_summary || {
        total_files: 0,
        by_language: {},
        total_lines_of_code: 0
      }
    };
  }
}

export default new APIService();
