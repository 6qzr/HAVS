/**
 * API Service for Backend Integration
 * Handles all communication with the FastAPI backend
 */

const API_BASE_URL = 'http://localhost:8000'

class APIService {
  /**
   * Start a new security scan (REST API - no progress updates)
   * @param {string} repoUrl - GitHub repository URL
   * @returns {Promise<Object>} Scan results
   */
  async startScan(repoUrl) {
    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repo_url: repoUrl
        })
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.detail || 'Scan failed')
      }

      return await response.json()
    } catch (error) {
      console.error('Scan error:', error)
      throw error
    }
  }

  /**
   * Start a new security scan with real-time progress updates via WebSocket
   * @param {string} repoUrl - GitHub repository URL
   * @param {Function} onProgress - Callback for progress updates (percentage, message, stage)
   * @returns {Promise<Object>} Scan results
   */
  async startScanWithProgress(repoUrl, onProgress = null) {
    return new Promise((resolve, reject) => {
      // Create WebSocket connection
      const wsUrl = API_BASE_URL.replace('http://', 'ws://').replace('https://', 'wss://')
      const ws = new WebSocket(`${wsUrl}/ws/scan`)

      // Set timeout for connection
      const connectionTimeout = setTimeout(() => {
        ws.close()
        reject(new Error('WebSocket connection timeout'))
      }, 5000)

      ws.onopen = () => {
        clearTimeout(connectionTimeout)
        console.log('WebSocket connected')

        // Send scan request
        ws.send(JSON.stringify({
          repo_url: repoUrl
        }))
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)

          if (data.type === 'progress') {
            // Call progress callback
            if (onProgress) {
              onProgress(data.percentage, data.message, data.stage)
            }
          } else if (data.type === 'complete') {
            // Scan completed successfully
            ws.close()
            resolve(data.data)
          } else if (data.type === 'error') {
            // Scan failed
            ws.close()
            reject(new Error(data.message || 'Scan failed'))
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        reject(new Error('WebSocket connection error'))
      }

      ws.onclose = (event) => {
        if (!event.wasClean) {
          console.warn('WebSocket closed unexpectedly')
        }
      }
    })
  }

  /**
   * Start a new security scan from uploaded file(s)
   * @param {File|File[]} files - Uploaded file(s) - Can be single file or array of files
   * @returns {Promise<Object>} Scan results
   */
  async uploadScan(files) {
    try {
      const formData = new FormData()

      // Handle both single file and multiple files
      const fileArray = Array.isArray(files) ? files : [files]

      // Append all files
      fileArray.forEach((file, index) => {
        formData.append('files', file)  // Use 'files' (plural) for multiple files
      })

      const response = await fetch(`${API_BASE_URL}/scan-upload`, {
        method: 'POST',
        body: formData
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.detail || 'Upload scan failed')
      }

      return await response.json()
    } catch (error) {
      console.error('Upload scan error:', error)
      throw error
    }
  }

  /**
   * Check API health status
   * @returns {Promise<Object>} Health status
   */
  async checkHealth() {
    try {
      const response = await fetch(`${API_BASE_URL}/health`)
      return await response.json()
    } catch (error) {
      console.error('Health check error:', error)
      throw error
    }
  }

  /**
   * Get API information
   * @returns {Promise<Object>} API info
   */
  async getApiInfo() {
    try {
      const response = await fetch(`${API_BASE_URL}/`)
      return await response.json()
    } catch (error) {
      console.error('API info error:', error)
      throw error
    }
  }

  /**
   * ML vulnerability prediction for source code files
   * @param {Array} files - Array of file objects with content
   * @returns {Promise<Object>} Prediction results
   */
  async predictVulnerabilities(files) {
    try {
      const response = await fetch(`${API_BASE_URL}/ml/predict`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ files })
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.detail || 'ML prediction failed')
      }

      return await response.json()
    } catch (error) {
      console.error('ML prediction error:', error)
      throw error
    }
  }

  /**
   * Submit ML feedback
   * @param {Object} feedbackData - Feedback data from user
   * @returns {Promise<Object>} Submission confirmation
   */
  async submitFeedback(feedbackData) {
    try {
      const response = await fetch(`${API_BASE_URL}/ml/feedback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(feedbackData)
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.detail || 'Failed to submit feedback')
      }

      return await response.json()
    } catch (error) {
      console.error('Feedback submission error:', error)
      throw error
    }
  }

  /**
   * Transform backend response to frontend format
   * @param {Object} backendData - Raw backend response
   * @returns {Object} Formatted data for frontend
   */
  transformScanResults(backendData) {
    if (!backendData.success) {
      throw new Error(backendData.error || 'Scan failed')
    }

    // Transform dependencies to include vulnerability counts and add cisaKev to CVEs
    const dependencies = backendData.dependencies.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      vulnerabilityCount: dep.cves ? dep.cves.length : 0,
      hasVulnerabilities: dep.cves && dep.cves.length > 0,
      cves: dep.cves ? dep.cves.map(cve => ({
        ...cve,
        cisaKev: cve.cisa_kev === 'Yes'  // Add cisaKev boolean field to each CVE
      })) : []
    }))

    // Group vulnerabilities by severity and extract CWE + CISA KEV data
    const vulnerabilities = []
    let cisaKevCount = 0

    backendData.dependencies.forEach(dep => {
      if (dep.cves && dep.cves.length > 0) {
        dep.cves.forEach(cve => {
          const isCisaKev = cve.cisa_kev === 'Yes'
          if (isCisaKev) {
            cisaKevCount++
          }

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
            cwe: cve.cwe || 'N/A',              // NEW: CWE IDs
            cisaKev: isCisaKev,                 // NEW: CISA KEV status (boolean)
            status: 'Confirmed'                 // All CVEs from new backend are confirmed
          })
        })
      }
    })

    return {
      scanId: `scan_${Date.now()}`,
      timestamp: backendData.scanned_at,
      duration: backendData.scan_duration_seconds,
      repoPath: backendData.repo_path,
      summary: {
        totalDependencies: backendData.summary.total_deps_scanned,
        totalVulnerabilities: backendData.summary.total_vulnerabilities,
        vulnerableDependencies: backendData.summary.deps_with_vulnerabilities,
        criticalCount: backendData.summary.vulnerabilities_by_severity.critical,
        highCount: backendData.summary.vulnerabilities_by_severity.high,
        mediumCount: backendData.summary.vulnerabilities_by_severity.medium,
        lowCount: backendData.summary.vulnerabilities_by_severity.low,
        cisaKevCount: cisaKevCount  // NEW: Count of CISA KEV vulnerabilities
      },
      dependencies,
      vulnerabilities,
      // NEW: Source code files for ML analysis
      sourceFiles: backendData.source_files || [],
      sourceFilesSummary: backendData.source_files_summary || {
        total_files: 0,
        by_language: {},
        total_lines_of_code: 0
      }
    }
  }
}

export default new APIService()

