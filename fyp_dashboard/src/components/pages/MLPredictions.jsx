import { useState, useEffect } from 'react'
import APIService from '../../services/api'
import { BrainIcon } from '../shared/Icons'

// ML Predictions Page Component
const MLPredictions = () => {
  const [scanResults, setScanResults] = useState(null)
  const [selectedFiles, setSelectedFiles] = useState([])
  const [filterLanguage, setFilterLanguage] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectAll, setSelectAll] = useState(false)
  
  // ML Analysis state
  const [mlResults, setMlResults] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  
  // Feedback state
  const [feedback, setFeedback] = useState({})
  const [feedbackComment, setFeedbackComment] = useState('')
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false)

  useEffect(() => {
    // Load last scan results from sessionStorage
    const results = sessionStorage.getItem('lastScanResults')
    if (results) {
      setScanResults(JSON.parse(results))
    }
  }, [])

  // No scan results available
  if (!scanResults) {
    return (
      <div className="page-content">
        <div className="page-header">
          <div className="header-logo">
            <BrainIcon />
          </div>
          <h1>ML Predictions</h1>
          <p>AI-powered vulnerability prediction for source code</p>
        </div>
        <div className="no-data-message">
          <h3>No scan data available</h3>
          <p>Run a repository scan first to extract source code files for ML analysis</p>
        </div>
      </div>
    )
  }

  const { sourceFiles = [], sourceFilesSummary = {} } = scanResults

  // No source files found
  if (!sourceFiles || sourceFiles.length === 0) {
    return (
      <div className="page-content">
        <div className="page-header">
          <div className="header-logo">
            <BrainIcon />
          </div>
          <h1>ML Predictions</h1>
          <p>AI-powered vulnerability prediction for source code</p>
        </div>
        <div className="no-data-message">
          <h3>No source code files found</h3>
          <p>The scanned repository doesn't contain Python, Java, C, or C++ files</p>
          <p className="supported-languages">
            <strong>Supported languages:</strong> Python (.py), Java (.java), C (.c), C++ (.cpp, .cc, .cxx, .h, .hpp)
          </p>
        </div>
      </div>
    )
  }

  // Filter files by language and search term
  const getFilteredFiles = () => {
    let filtered = sourceFiles

    // Filter by language
    if (filterLanguage !== 'all') {
      filtered = filtered.filter(f => f.language === filterLanguage)
    }

    // Filter by search term (filename or path)
    if (searchTerm.trim()) {
      const search = searchTerm.toLowerCase()
      filtered = filtered.filter(f => 
        f.filename.toLowerCase().includes(search) ||
        f.path.toLowerCase().includes(search)
      )
    }

    return filtered
  }

  const filteredFiles = getFilteredFiles()

  // Handle individual file selection
  const handleFileSelect = (filePath) => {
    setSelectedFiles(prev => 
      prev.includes(filePath)
        ? prev.filter(p => p !== filePath)
        : [...prev, filePath]
    )
  }

  // Handle select all filtered files
  const handleSelectAll = () => {
    if (selectAll) {
      // Deselect all filtered files
      const filteredPaths = filteredFiles.map(f => f.full_path)
      setSelectedFiles(prev => prev.filter(p => !filteredPaths.includes(p)))
      setSelectAll(false)
    } else {
      // Select all filtered files
      const filteredPaths = filteredFiles.map(f => f.full_path)
      setSelectedFiles(prev => [...new Set([...prev, ...filteredPaths])])
      setSelectAll(true)
    }
  }

  // Handle clear selection
  const handleClearSelection = () => {
    setSelectedFiles([])
    setSelectAll(false)
  }

  // Handle analyze with ML model
  const handleAnalyzeSelected = async () => {
    if (selectedFiles.length === 0) {
      alert('Please select at least one file to analyze')
      return
    }

    // Check limit
    if (selectedFiles.length > 30) {
      alert('Please select up to 30 files at a time for optimal performance.\n\nYou selected: ' + selectedFiles.length + ' files')
      return
    }

    // Get selected file objects with content
    const selectedFileObjects = sourceFiles.filter(f => 
      selectedFiles.includes(f.full_path)
    )

    // Check if files have content
    const filesWithContent = selectedFileObjects.filter(f => f.content !== null && f.content !== undefined)
    
    if (filesWithContent.length === 0) {
    alert(
        'None of the selected files have content available.\n\n' +
        'This usually means the files are larger than 500KB.\n\n' +
        'Please select smaller files for analysis.'
      )
      return
    }

    // Show warning if some files don't have content
    if (filesWithContent.length < selectedFileObjects.length) {
      const missingCount = selectedFileObjects.length - filesWithContent.length
      const proceed = confirm(
        `${missingCount} file(s) are too large and will be skipped.\n\n` +
        `Analyze ${filesWithContent.length} file(s) with content available?`
      )
      if (!proceed) return
    }

    setIsAnalyzing(true)
    setError(null)
    setMlResults(null)
    // Reset feedback when starting new analysis
    setFeedback({})
    setFeedbackComment('')
    setFeedbackSubmitted(false)

    try {
      // Prepare files for ML analysis
      const filesToAnalyze = filesWithContent.map(f => ({
        path: f.path,
        filename: f.filename,
        language: f.language,
        content: f.content,
        lines_of_code: f.lines_of_code
      }))

      console.log(`[ML Analysis] Sending ${filesToAnalyze.length} files to ML service...`)

      // Call ML API
      const result = await APIService.predictVulnerabilities(filesToAnalyze)

      console.log('[ML Analysis] Results received:', result)

      // Store results (will automatically display below)
      setMlResults(result)

    } catch (error) {
      console.error('[ML Analysis] Error:', error)
      setError(error.message)
      
      let errorMsg = 'ML Analysis Failed\n\n'
      
      if (error.message.includes('ML service not available') || error.message.includes('No module named')) {
        errorMsg += 'ML dependencies are not installed.\n\n'
        errorMsg += 'To enable ML predictions, install dependencies:\n'
        errorMsg += 'pip install -r requirements.txt\n\n'
        errorMsg += 'Then restart the backend server.'
      } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        errorMsg += 'Cannot connect to backend.\n\n'
        errorMsg += 'Make sure the backend is running:\n'
        errorMsg += 'uvicorn api:app --reload'
      } else {
        errorMsg += 'Error: ' + error.message
      }
      
      alert(errorMsg)
    } finally {
      setIsAnalyzing(false)
    }
  }

  // Handle individual file feedback
  const handleFileFeedback = (filename, rating) => {
    setFeedback(prev => ({
      ...prev,
      [filename]: rating
    }))
  }

  // Handle feedback submission
  const handleSubmitFeedback = async () => {
    if (Object.keys(feedback).length === 0 && !feedbackComment.trim()) {
      alert('Please rate at least one prediction or provide a comment.')
      return
    }

    // Prepare feedback data with file content
    const feedbackData = {
      predictions: mlResults.predictions.map(pred => {
        // Find the original source file to get content
        const sourceFile = sourceFiles.find(f => f.filename === pred.filename)
        
        return {
          filename: pred.filename,
          prediction: pred.prediction,
          confidence: pred.confidence,
          user_rating: feedback[pred.filename] || null,
          file_content: sourceFile?.content || null  // Include file content
        }
      }),
      general_comment: feedbackComment.trim(),
      timestamp: new Date().toISOString()
    }

    try {
      // Send feedback to backend
      const response = await APIService.submitFeedback(feedbackData)
      
      console.log('Feedback submitted successfully:', response)
      
      // Show success message
      setFeedbackSubmitted(true)
      alert('Thank you for your feedback! Your input has been sent and will help improve the ML model.')
      
      // Reset feedback after 3 seconds
      setTimeout(() => {
        setFeedbackSubmitted(false)
      }, 3000)
      
    } catch (error) {
      console.error('Failed to submit feedback:', error)
      alert('Failed to submit feedback. However, it has been logged locally.\n\nError: ' + error.message)
    }
  }

  // Get language icon (SVG)
  const getLanguageIcon = (language) => {
    const icons = {
      'Python': (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z" fill="currentColor"/>
          <path d="M12 6l-6 6h4v4h4v-4h4z" fill="currentColor"/>
        </svg>
      ),
      'Java': (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <rect x="4" y="4" width="16" height="16" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
          <path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
        </svg>
      ),
      'C': (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="2" fill="none"/>
          <path d="M15 9c-1.5-1-3-1-4.5 0-1.5 1-1.5 5 0 6 1.5 1 3 1 4.5 0" stroke="currentColor" strokeWidth="2" fill="none"/>
        </svg>
      ),
      'C++': (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="2" fill="none"/>
          <path d="M9 12h6M12 9v6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          <path d="M15 9v6M18 12h-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      ),
      'C/C++ Header': (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" strokeWidth="2" fill="none"/>
          <polyline points="14,2 14,8 20,8" stroke="currentColor" strokeWidth="2" fill="none"/>
        </svg>
      )
    }
    return icons[language] || (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" strokeWidth="2" fill="none"/>
        <polyline points="14,2 14,8 20,8" stroke="currentColor" strokeWidth="2" fill="none"/>
      </svg>
    )
  }

  // Get language color
  const getLanguageColor = (language) => {
    const colors = {
      'Python': '#3776ab',
      'Java': '#f89820',
      'C': '#555555',
      'C++': '#f34b7d',
      'C/C++ Header': '#a8b9cc'
    }
    return colors[language] || '#666666'
  }

  // Render highlighted code based on attention weights
  const renderHighlightedCode = (tokens, attentionWeights) => {
    if (!tokens || !attentionWeights || tokens.length === 0) {
      return <div className="no-attention">No attention data available</div>
    }

    // Filter out padding tokens and get valid attention weights
    const validIndices = []
    const validTokens = []
    const validWeights = []

    tokens.forEach((token, idx) => {
      // Skip special tokens and padding
      if (token !== '<s>' && token !== '</s>' && token !== '<pad>') {
        validIndices.push(idx)
        validTokens.push(token)
        validWeights.push(attentionWeights[idx])
      }
    })

    // Normalize weights for better visualization
    const maxWeight = Math.max(...validWeights)
    const minWeight = Math.min(...validWeights)
    const weightRange = maxWeight - minWeight

    // Render tokens with highlighting
    return (
      <code className="attention-code">
        {validTokens.map((token, idx) => {
          // Clean up token (CodeBERT uses Ġ for spaces, Ċ for newlines)
          let cleanToken = token.replace('Ġ', ' ').replace('Ċ', '\n')
          
          // Calculate opacity based on normalized attention weight
          const normalizedWeight = weightRange > 0 
            ? (validWeights[idx] - minWeight) / weightRange 
            : 0

          // Only highlight tokens with significant attention (>20% of max)
          const opacity = normalizedWeight > 0.2 ? normalizedWeight * 0.8 : 0
          
          // Color based on prediction (red for vulnerable areas)
          const backgroundColor = opacity > 0 
            ? `rgba(239, 68, 68, ${opacity})` 
            : 'transparent'

          return (
            <span
              key={idx}
              className="code-token"
              style={{ 
                backgroundColor,
                borderBottom: opacity > 0.5 ? '2px solid rgba(239, 68, 68, 0.5)' : 'none'
              }}
              title={`Attention: ${validWeights[idx].toFixed(4)}`}
            >
              {cleanToken}
            </span>
          )
        })}
      </code>
    )
  }

  return (
    <div className="page-content ml-predictions-page">
      <div className="page-header">
        <div className="header-logo">
          <BrainIcon />
        </div>
        <h1>ML Predictions</h1>
        <p>Select source code files for AI-powered vulnerability prediction</p>
      </div>

      {/* Summary Statistics */}
      <div className="ml-summary-cards">
        <div className="ml-stat-card">
          <div className="ml-stat-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            </svg>
          </div>
          <div className="ml-stat-content">
            <h3>Total Files</h3>
            <div className="ml-stat-number">{sourceFilesSummary.total_files || 0}</div>
            <p>Source code files found</p>
          </div>
        </div>
        <div className="ml-stat-card">
          <div className="ml-stat-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14,2 14,8 20,8"/>
              <line x1="16" y1="13" x2="8" y2="13"/>
              <line x1="16" y1="17" x2="8" y2="17"/>
              <polyline points="10,9 9,9 8,9"/>
            </svg>
          </div>
          <div className="ml-stat-content">
            <h3>Total Lines</h3>
            <div className="ml-stat-number">
              {(sourceFilesSummary.total_lines_of_code || 0).toLocaleString()}
            </div>
            <p>Lines of code</p>
          </div>
        </div>
        <div className="ml-stat-card selected">
          <div className="ml-stat-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="20,6 9,17 4,12"/>
            </svg>
          </div>
          <div className="ml-stat-content">
            <h3>Selected</h3>
            <div className="ml-stat-number">{selectedFiles.length}</div>
            <p>Files ready for analysis</p>
          </div>
        </div>
        <div className="ml-stat-card">
          <div className="ml-stat-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="12,2 2,7 12,12 22,7 12,2"/>
              <polyline points="2,17 12,22 22,17"/>
              <polyline points="2,12 12,17 22,12"/>
            </svg>
          </div>
          <div className="ml-stat-content">
            <h3>Languages</h3>
            <div className="ml-stat-number">
              {Object.keys(sourceFilesSummary.by_language || {}).length}
            </div>
            <p>Programming languages</p>
          </div>
        </div>
      </div>

      {/* Filters and Controls */}
      <div className="ml-controls">
        {/* Search Bar */}
        <div className="ml-search-box">
          <input
            type="text"
            placeholder="Search files by name or path..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* Language Filters */}
        <div className="ml-language-filters">
          <button 
            className={`ml-filter-btn ${filterLanguage === 'all' ? 'active' : ''}`}
            onClick={() => setFilterLanguage('all')}
          >
            All ({sourceFilesSummary.total_files || 0})
          </button>
          {Object.entries(sourceFilesSummary.by_language || {}).map(([lang, count]) => (
            <button
              key={lang}
              className={`ml-filter-btn ${filterLanguage === lang ? 'active' : ''}`}
              onClick={() => setFilterLanguage(lang)}
              style={{
                borderColor: filterLanguage === lang ? getLanguageColor(lang) : 'transparent'
              }}
            >
              {lang} ({count})
            </button>
          ))}
        </div>

        {/* Selection Controls */}
        <div className="ml-selection-controls">
          <button className="ml-control-btn" onClick={handleSelectAll}>
            {selectAll ? 'Deselect All' : 'Select All'} ({filteredFiles.length})
          </button>
          {selectedFiles.length > 0 && (
            <button className="ml-control-btn clear" onClick={handleClearSelection}>
              Clear Selection
            </button>
          )}
        </div>
      </div>

      {/* Files List */}
      <div className="ml-files-section">
        <div className="ml-files-header">
          <h3>Source Code Files</h3>
          <span className="ml-files-count">
            Showing {filteredFiles.length} of {sourceFiles.length} files
          </span>
        </div>

        {filteredFiles.length === 0 ? (
          <div className="no-data-message">
            <h3>No files match your filters</h3>
            <p>Try adjusting your search or language filter</p>
          </div>
        ) : (
          <div className="ml-files-list">
            {filteredFiles.map((file, idx) => (
              <div 
                key={idx} 
                className={`ml-file-card ${selectedFiles.includes(file.full_path) ? 'selected' : ''}`}
                onClick={() => handleFileSelect(file.full_path)}
              >
                <div className="ml-file-checkbox">
                  <input
                    type="checkbox"
                    checked={selectedFiles.includes(file.full_path)}
                    onChange={() => handleFileSelect(file.full_path)}
                    onClick={(e) => e.stopPropagation()}
                  />
                </div>
                
                <div className="ml-file-icon" style={{ color: getLanguageColor(file.language) }}>
                  {getLanguageIcon(file.language)}
                </div>
                
                <div className="ml-file-info">
                  <div className="ml-file-name">{file.filename}</div>
                  <div className="ml-file-path">{file.path}</div>
                  <div className="ml-file-meta">
                    <span 
                      className="ml-file-language"
                      style={{ backgroundColor: getLanguageColor(file.language) + '20', color: getLanguageColor(file.language) }}
                    >
                      {file.language}
                    </span>
                    <span className="ml-file-lines">{file.lines_of_code} lines</span>
                    <span className="ml-file-size">{(file.size_bytes / 1024).toFixed(1)} KB</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Analyze Button - Always appears when files are selected */}
      {selectedFiles.length > 0 && (
        <div className="ml-analyze-section">
          <button 
            className="ml-analyze-btn" 
            onClick={handleAnalyzeSelected}
            disabled={isAnalyzing}
          >
            {isAnalyzing ? (
              <>
                <svg className="spinner" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/>
                </svg>
                Analyzing...
              </>
            ) : (
              'Analyze Selected Files'
            )}
          </button>
          <p className="ml-analyze-note">
            {isAnalyzing 
              ? 'Running vulnerability detection... This may take a few seconds.'
              : mlResults 
                ? 'Select different files and click to start a new analysis'
                : 'Click to analyze selected files using AI model for vulnerability detection.'}
          </p>
        </div>
      )}

      {/* ML Analysis Results */}
      {mlResults && (
        <div className="ml-results-section">
          <div className="ml-results-header">
            <h3>Analysis Results</h3>
          </div>

          {/* Summary Stats */}
          <div className="ml-results-summary">
            <div className="result-stat">
              <span className="stat-label">Total Analyzed</span>
              <span className="stat-value">{mlResults.summary.total_files}</span>
            </div>
            <div className="result-stat safe">
              <span className="stat-label">Safe</span>
              <span className="stat-value">{mlResults.summary.safe_files}</span>
            </div>
            <div className="result-stat vulnerable">
              <span className="stat-label">Vulnerable</span>
              <span className="stat-value">{mlResults.summary.vulnerable_files}</span>
            </div>
            {mlResults.summary.failed_files > 0 && (
              <div className="result-stat failed">
                <span className="stat-label">Failed</span>
                <span className="stat-value">{mlResults.summary.failed_files}</span>
              </div>
            )}
            <div className="result-stat">
              <span className="stat-label">Analysis Time</span>
              <span className="stat-value">{mlResults.summary.analysis_time_seconds}s</span>
            </div>
          </div>

          {/* Individual file results */}
          <div className="ml-predictions-list">
            {mlResults.predictions.map((pred, idx) => (
              <div key={idx} className={`ml-prediction-card ${pred.risk_level?.toLowerCase()}`}>
                <div className="prediction-header">
                  <div className="prediction-file-info">
                    <span className="file-name">{pred.filename}</span>
                    <span className="file-path">{pred.file_path}</span>
                  </div>
                  <span className={`prediction-badge ${pred.prediction?.toLowerCase()}`}>
                    {pred.prediction}
                  </span>
                </div>
                <div className="prediction-details">
                  <div className="detail-item">
                    <span className="detail-label">Language:</span>
                    <span className="detail-value">{pred.language}</span>
                  </div>
                  {pred.error && (
                    <div className="detail-item error">
                      <span className="detail-label">Error:</span>
                      <span className="detail-value">{pred.error}</span>
                    </div>
                  )}
                </div>

                {/* Code Highlighting Visualization */}
                {pred.tokens && pred.attention_weights && pred.tokens.length > 0 && (
                  <div className="code-highlighting-section">
                    <div className="code-highlighting-header">
                      <span className="highlight-label">
                        Code Analysis (Darker = Higher Attention)
                      </span>
                      <button 
                        className="toggle-highlight-btn"
                        onClick={() => {
                          const section = document.getElementById(`highlight-${idx}`)
                          section.style.display = section.style.display === 'none' ? 'block' : 'none'
                        }}
                      >
                        Toggle View
                      </button>
                    </div>
                    <div id={`highlight-${idx}`} className="highlighted-code">
                      {renderHighlightedCode(pred.tokens, pred.attention_weights)}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Feedback Section */}
          <div className="ml-feedback-section">
            <div className="feedback-header">
              <h3>Help Us Improve</h3>
              <p>Your feedback helps train better models. Rate the predictions below:</p>
            </div>

            {/* Per-file feedback */}
            <div className="feedback-files">
              {mlResults.predictions.map((pred, idx) => (
                <div key={idx} className="feedback-file-item">
                  <div className="feedback-file-info">
                    <span className="feedback-filename">{pred.filename}</span>
                    <span className={`feedback-prediction ${pred.prediction?.toLowerCase()}`}>
                      {pred.prediction}
                    </span>
                  </div>
                  <div className="feedback-rating">
                    <span className="rating-label">Was this prediction accurate?</span>
                    <div className="rating-buttons">
                      <button
                        className={`rating-btn correct ${feedback[pred.filename] === 'correct' ? 'active' : ''}`}
                        onClick={() => handleFileFeedback(pred.filename, 'correct')}
                        title="Prediction was correct"
                      >
                        Correct
                      </button>
                      <button
                        className={`rating-btn incorrect ${feedback[pred.filename] === 'incorrect' ? 'active' : ''}`}
                        onClick={() => handleFileFeedback(pred.filename, 'incorrect')}
                        title="Prediction was incorrect"
                      >
                        Incorrect
                      </button>
                      <button
                        className={`rating-btn unsure ${feedback[pred.filename] === 'unsure' ? 'active' : ''}`}
                        onClick={() => handleFileFeedback(pred.filename, 'unsure')}
                        title="Not sure"
                      >
                        Unsure
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* General comment */}
            <div className="feedback-comment">
              <label htmlFor="feedback-comment">Additional Comments (Optional):</label>
              <textarea
                id="feedback-comment"
                placeholder="Any additional feedback about the predictions? What could be improved?"
                value={feedbackComment}
                onChange={(e) => setFeedbackComment(e.target.value)}
                rows="4"
              />
            </div>

            {/* Submit button */}
            <div className="feedback-actions">
              <button
                className={`feedback-submit-btn ${feedbackSubmitted ? 'submitted' : ''}`}
                onClick={handleSubmitFeedback}
                disabled={feedbackSubmitted}
              >
                {feedbackSubmitted ? (
                  <>
                    ✓ Feedback Submitted
                  </>
                ) : (
                  'Submit Feedback'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

export default MLPredictions
