import { useState, useEffect, useCallback, useRef } from 'react'
import { ShieldIcon, GitHubIcon, UploadIcon } from '../shared/Icons'
import logoImage from '../../assets/logo.png'
import APIService from '../../services/api'

// Scan Card Component
const ScanCard = ({ onScanComplete }) => {
  const [githubUrl, setGithubUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanCompleted, setScanCompleted] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [uploadedFiles, setUploadedFiles] = useState([])
  const [isDragOver, setIsDragOver] = useState(false)
  const [scanStatus, setScanStatus] = useState('')
  const [scanDuration, setScanDuration] = useState(0)
  const [hasDependencies, setHasDependencies] = useState(false)
  const [hasSourceFiles, setHasSourceFiles] = useState(false)
  const handleScanRef = useRef(null)

  // Load previous scan state from sessionStorage on mount
  useEffect(() => {
    const savedScanState = sessionStorage.getItem('lastScanState')
    if (savedScanState) {
      try {
        const state = JSON.parse(savedScanState)
        setGithubUrl(state.githubUrl || '')
        setScanCompleted(state.scanCompleted || false)
        setScanProgress(state.scanProgress || 0)
        setScanStatus(state.scanStatus || '')
        setScanDuration(state.scanDuration || 0)
        // Note: uploadedFiles are not persisted as they are File objects
      } catch (error) {
        console.error('Error loading scan state:', error)
      }
    }
    
    // Restore scan type from last scan results
    const lastScanResults = sessionStorage.getItem('lastScanResults')
    if (lastScanResults) {
      try {
        const results = JSON.parse(lastScanResults)
        const hasDeps = results.dependencies && results.dependencies.length > 0
        const hasSource = results.sourceFiles && results.sourceFiles.length > 0
        setHasDependencies(hasDeps)
        setHasSourceFiles(hasSource)
      } catch (error) {
        console.error('Error loading scan results:', error)
      }
    }
  }, [])

  // Save scan state to sessionStorage whenever it changes
  useEffect(() => {
    if (githubUrl || scanCompleted) {
      const stateToSave = {
        githubUrl,
        scanCompleted,
        scanProgress,
        scanStatus,
        scanDuration
      }
      sessionStorage.setItem('lastScanState', JSON.stringify(stateToSave))
    }
  }, [githubUrl, scanCompleted, scanProgress, scanStatus, scanDuration])

  // Handle Enter key to trigger scan again when scan is completed
  useEffect(() => {
    const handleKeyPress = (e) => {
      if (e.key === 'Enter' && scanCompleted && !isScanning) {
        // Trigger scan with current inputs using ref to avoid dependency issues
        if (handleScanRef.current) {
          handleScanRef.current()
        }
      }
    }

    if (scanCompleted) {
      window.addEventListener('keydown', handleKeyPress)
      return () => {
        window.removeEventListener('keydown', handleKeyPress)
      }
    }
  }, [scanCompleted, isScanning])

  const validateGitHubUrl = (url) => {
    const githubRegex = /^https:\/\/github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9._-]+(\.git)?$/
    return githubRegex.test(url)
  }

  const handleFileUpload = (files) => {
    const fileArray = Array.from(files)
    const validFiles = fileArray.filter(file => {
      const fileName = file.name.toLowerCase()
      // Accept dependency files
      if (fileName === 'package.json' ||
          fileName === 'requirements.txt' ||
          fileName === 'pom.xml' ||
          fileName.endsWith('.zip')) {
        return true
      }
      // Accept source code files for ML analysis (Java, Python, C, C++ only)
      const sourceExtensions = ['.py', '.java', '.c', '.cpp']
      return sourceExtensions.some(ext => fileName.endsWith(ext))
    })
    
    if (validFiles.length === 0) {
      alert('Please upload:\n' +
            '• Dependency files: package.json, requirements.txt, pom.xml\n' +
            '• Source code files: .py, .java, .c, .cpp\n' +
            '• ZIP archive: .zip')
      return
    }
    
    // Allow multiple files (but only one ZIP file)
    const zipFiles = validFiles.filter(f => f.name.toLowerCase().endsWith('.zip'))
    if (zipFiles.length > 0 && validFiles.length > 1) {
      alert('Cannot upload ZIP file with other files. Please upload ZIP file separately or upload multiple source code files without ZIP.')
      return
    }
    
    // Store all valid files
    setUploadedFiles(validFiles)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragOver(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    setIsDragOver(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragOver(false)
    const files = e.dataTransfer.files
    handleFileUpload(files)
  }

  const handleFileInput = (e) => {
    const files = e.target.files
    handleFileUpload(files)
  }

  const removeFile = (index) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleScan = async () => {
    if (!githubUrl.trim() && uploadedFiles.length === 0) {
      alert('Please enter a GitHub repository URL or upload files')
      return
    }
    
    if (githubUrl.trim() && !validateGitHubUrl(githubUrl)) {
      alert('Please enter a valid GitHub repository URL')
      return
    }

    setIsScanning(true)
    setScanCompleted(false)
    setScanProgress(0)
    setScanStatus('Initializing scan...')
    
    const startTime = Date.now()
    
    try {
      // Determine if this is a URL scan or file upload
      const isFileUpload = uploadedFiles.length > 0 && !githubUrl.trim()
      
      let result
      
      if (isFileUpload) {
        // File uploads use REST API (no real-time progress yet)
        // Simulate progress for file uploads
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
            if (prev >= 90) return prev
            return prev + 10
        })
      }, 1000)

        // Upload all files (supports single or multiple files)
        result = await APIService.uploadScan(uploadedFiles)
        clearInterval(progressInterval)
      } else {
        // URL scans use WebSocket for REAL progress updates
        result = await APIService.startScanWithProgress(
          githubUrl,
          (percentage, message, stage) => {
            // Real-time progress updates from backend!
            setScanProgress(percentage)
            setScanStatus(message)
            console.log(`[${stage}] ${percentage}%: ${message}`)
          }
        )
      }
      
      // Calculate scan duration
      const endTime = Date.now()
      const duration = ((endTime - startTime) / 1000).toFixed(1)
      setScanDuration(duration)
      
      // Transform and store results
      const transformedResults = APIService.transformScanResults(result)
      
      // Determine what was scanned based on results
      const hasDeps = transformedResults.dependencies && transformedResults.dependencies.length > 0
      const hasSource = transformedResults.sourceFiles && transformedResults.sourceFiles.length > 0
      setHasDependencies(hasDeps)
      setHasSourceFiles(hasSource)
      
      // Store in sessionStorage for Dashboard to access
      sessionStorage.setItem('lastScanResults', JSON.stringify(transformedResults))
      sessionStorage.setItem('lastScanUrl', isFileUpload ? `Uploaded: ${uploadedFiles[0].name}` : githubUrl)
      
      // Complete progress
      setScanProgress(100)
      setScanStatus('Scan completed successfully!')
      setIsScanning(false)
      setScanCompleted(true)
      
      // Don't auto-navigate - let user choose
      
    } catch (error) {
      console.error('Scan error:', error)
      setScanStatus(`Error: ${error.message}`)
      setIsScanning(false)
      setScanCompleted(false)
      setScanProgress(0)
      alert(`Scan failed: ${error.message}\n\nPlease make sure the backend is running and the repository URL is valid.`)
    }
  }

  // Update ref with latest handleScan function
  useEffect(() => {
    handleScanRef.current = handleScan
  }, [githubUrl, uploadedFiles])
  
  const handleViewResults = () => {
    onScanComplete('Dashboard')
  }
  
  const handleViewMLResults = () => {
    onScanComplete('ML Predictions')
  }
  
  const handleScanAnother = useCallback(() => {
    // Just start a new scan with the same inputs
    handleScan()
  }, [githubUrl, uploadedFiles])

  return (
    <div className="scan-card">
      <div className="scan-header">
        <h2>Start Security Scan</h2>
        <p>Enter a GitHub repository URL or upload package files for comprehensive security analysis</p>
      </div>

      <div className="scan-form">
        <div className="input-group">
          <label>GitHub Repository URL</label>
          <div className="input-container">
            <div className="input-icon">
              <GitHubIcon />
            </div>
            <input
              type="text"
              placeholder="https://github.com/username/repository"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !isScanning && !scanCompleted) {
                  handleScan()
                }
              }}
              disabled={isScanning}
            />
          </div>
        </div>

        <div className="separator">
          <span>OR</span>
        </div>

        <div className="input-group">
          <label>Upload Package Files</label>
          <div 
            className={`upload-area ${isDragOver ? 'drag-over' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => document.getElementById('file-input').click()}
          >
            <input
              id="file-input"
              type="file"
              accept=".json,.txt,.xml,.zip,.py,.java,.c,.cpp"
              multiple
              onChange={handleFileInput}
              style={{ display: 'none' }}
              disabled={isScanning}
            />
            <div className="upload-icon">
              <UploadIcon />
            </div>
            <p className="upload-text">Click to upload or drag and drop</p>
            <p className="upload-subtext">ZIP archive, dependency files, or source code (.py, .java, .c, .cpp)</p>
          </div>
          
          {uploadedFiles.length > 0 && (
            <div className="uploaded-files">
              <h4>Uploaded Files:</h4>
              {uploadedFiles.map((file, index) => (
                <div key={index} className="file-item">
                  <span className="file-name">{file.name}</span>
                  <button 
                    className="remove-file-btn"
                    onClick={(e) => {
                      e.stopPropagation()
                      removeFile(index)
                    }}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {!scanCompleted && (
          <button 
            className="scan-button" 
            onClick={handleScan}
            disabled={isScanning}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
        )}

        {(isScanning || scanCompleted) && (
          <div className="progress-container">
            <div className="progress-message">
              {scanStatus}
            </div>
            
            <div className="progress-bar">
              <div 
                className="progress-fill"
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <span className="progress-text">{scanProgress}%</span>
            
            {scanCompleted && scanDuration > 0 && (
              <div className="scan-duration">
                Completed in {scanDuration}s
              </div>
            )}
          </div>
        )}
        
        {scanCompleted && (
          <div className="scan-actions">
            <button 
              className="scan-another-button" 
              onClick={handleScanAnother}
            >
              Scan Another Repository
            </button>
            {hasDependencies && (
              <button 
                className="view-results-button" 
                onClick={handleViewResults}
              >
                View Dependencies
              </button>
            )}
            {hasSourceFiles && (
              <button 
                className="view-results-button" 
                onClick={handleViewMLResults}
              >
                View ML Analysis
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ScanRepository Page Component
const ScanRepository = ({ onScanComplete }) => {
  return (
    <div className="page-content">
      <div className="page-header">
        <div className="header-logo">
          <img src={logoImage} alt="VulnScanner Logo" className="header-logo-image" />
        </div>
        <h1>Vulnerability Scanner</h1>
        <p>Comprehensive security analysis for your GitHub repositories.<br />
        Detect vulnerabilities, scan dependencies, and identify code issues with ML-powered insights.</p>
      </div>
      <ScanCard onScanComplete={onScanComplete} />
      <div className="feature-cards">
        <div className="feature-card">
          <h3>CVE Detection</h3>
          <p>Identify known vulnerabilities from CVE and NVD databases</p>
        </div>
        <div className="feature-card">
          <h3>ML Analysis</h3>
          <p>AI-powered source code analysis for security vulnerability detection</p>
        </div>
        <div className="feature-card">
          <h3>Detailed Reports</h3>
          <p>Get comprehensive insights and actionable security recommendations</p>
        </div>
      </div>
    </div>
  )
}

export default ScanRepository
