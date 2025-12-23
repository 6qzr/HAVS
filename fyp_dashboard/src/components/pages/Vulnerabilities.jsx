import { useState, useEffect } from 'react'
import { DocumentIcon } from '../shared/Icons'

// Helper function to deduplicate CWE values
const deduplicateCWE = (cweString) => {
  if (!cweString || cweString === 'N/A') {
    return 'N/A'
  }
  
  // Split by comma, trim whitespace, filter empty strings, and remove duplicates
  const cweList = cweString.split(',')
    .map(cwe => cwe.trim())
    .filter(cwe => cwe && cwe.length > 0)
  
  // Use Set to remove duplicates while preserving order
  const uniqueCWEs = [...new Set(cweList)]
  
  return uniqueCWEs.join(', ')
}

// Vulnerabilities Page Component
const Vulnerabilities = () => {
  const [scanResults, setScanResults] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    const results = sessionStorage.getItem('lastScanResults')
    if (results) {
      setScanResults(JSON.parse(results))
    }
  }, [])

  if (!scanResults) {
    return (
      <div className="page-content">
        <div className="page-header">
          <div className="header-logo">
            <DocumentIcon />
          </div>
          <h1>Vulnerabilities</h1>
          <p>Detailed vulnerability analysis</p>
        </div>
        <div className="no-data-message">
          <h3>No vulnerability data available</h3>
          <p>Run a security scan to see detailed vulnerability information</p>
        </div>
      </div>
    )
  }

  const { dependencies, vulnerabilities } = scanResults

  // Filter and process dependencies based on search and severity
  const getFilteredDependencies = () => {
    // Start with all vulnerable dependencies
    let filtered = dependencies.filter(dep => dep.hasVulnerabilities)
    
    // Apply filters to each dependency's CVEs
    filtered = filtered.map(dep => {
      // Filter the CVEs within this dependency
      const filteredCVEs = dep.cves.filter(cve => {
        // Check severity filter
        const matchesSeverity = filterSeverity === 'all' || cve.severity === filterSeverity
        
        // Check search term (search in CVE ID or package name)
        const matchesSearch = searchTerm === '' || 
          cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
          dep.name.toLowerCase().includes(searchTerm.toLowerCase())
        
        return matchesSeverity && matchesSearch
      })
      
      // Return dependency with filtered CVEs
      return {
        ...dep,
        cves: filteredCVEs,
        vulnerabilityCount: filteredCVEs.length
      }
    })
    
    // Remove dependencies that have no CVEs after filtering
    filtered = filtered.filter(dep => dep.cves.length > 0)
    
    return filtered
  }

  const vulnerableDeps = getFilteredDependencies()
  
  // Count total filtered vulnerabilities for the filter buttons
  const getTotalFilteredCount = (severity) => {
    if (severity === 'all') {
      return vulnerabilities.length
    }
    return vulnerabilities.filter(v => v.severity === severity).length
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="header-logo">
          <DocumentIcon />
        </div>
        <h1>Vulnerabilities</h1>
        <p>Detailed vulnerability analysis for all dependencies</p>
      </div>

      {/* Filter Controls */}
      <div className="filter-controls">
        <div className="search-box">
          <input
            type="text"
            placeholder="Search by CVE ID or package name..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="severity-filters">
          <button 
            className={`filter-btn ${filterSeverity === 'all' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('all')}
          >
            All ({getTotalFilteredCount('all')})
          </button>
          <button 
            className={`filter-btn critical ${filterSeverity === 'critical' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('critical')}
          >
            Critical ({getTotalFilteredCount('critical')})
          </button>
          <button 
            className={`filter-btn high ${filterSeverity === 'high' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('high')}
          >
            High ({getTotalFilteredCount('high')})
          </button>
          <button 
            className={`filter-btn medium ${filterSeverity === 'medium' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('medium')}
          >
            Medium ({getTotalFilteredCount('medium')})
          </button>
          <button 
            className={`filter-btn low ${filterSeverity === 'low' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('low')}
          >
            Low ({getTotalFilteredCount('low')})
          </button>
        </div>
      </div>

      {/* Vulnerable Dependencies */}
      <div className="vulnerabilities-section">
        <h2>Vulnerable Dependencies ({vulnerableDeps.length})</h2>
        
        {vulnerableDeps.length === 0 ? (
          <div className="no-data-message">
            <h3>No vulnerabilities found</h3>
            <p>No results match your current filters. Try adjusting your search or filter criteria.</p>
          </div>
        ) : (
          vulnerableDeps.map((dep, idx) => (
          <div key={idx} className="package-card">
            {/* Package Header Row */}
            <div className="package-header-row">
              <div className="package-info">
                <h3 className="package-name">{dep.name}</h3>
                <div className="package-meta">
                  <span className="package-version">v{dep.version}</span>
                  <span className="package-ecosystem">{dep.ecosystem}</span>
                  <span className="package-vuln-count">
                    {dep.vulnerabilityCount} {dep.vulnerabilityCount === 1 ? 'CVE' : 'CVEs'}
                  </span>
                </div>
              </div>
            </div>

            {/* CVE Rows */}
            <div className="cve-rows-container">
              {dep.cves.map((cve, cveIdx) => (
                <div key={cveIdx} className={`cve-row ${cve.cisaKev ? 'cisa-kev-row' : ''}`}>
                  {/* CVE ID Column with CISA KEV Badge */}
                  <div className="cve-column cve-id-col">
                    <div className="cve-id-wrapper">
                    <span className="cve-id">{cve.cve_id}</span>
                      {cve.cisaKev && (
                        <span className="cisa-kev-badge" title="Known Exploited Vulnerability">
                          CISA KEV
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Severity Column */}
                  <div className="cve-column severity-col">
                    <span className={`severity-badge ${cve.severity}`}>
                      {cve.severity.toUpperCase()}
                    </span>
                  </div>

                  {/* CVSS Score Column */}
                  <div className="cve-column cvss-col">
                    {cve.cvss_score ? (
                      <div className="cvss-display">
                        <span className="cvss-label">CVSS</span>
                        <span className="cvss-value">{cve.cvss_score}</span>
                      </div>
                    ) : (
                      <span className="cvss-na">N/A</span>
                    )}
                  </div>

                  {/* CWE Column */}
                  <div className="cve-column cwe-col">
                    <span className="cwe-badge" title="Common Weakness Enumeration">
                      {deduplicateCWE(cve.cwe)}
                    </span>
                  </div>

                  {/* Affected Versions Column */}
                  <div className="cve-column versions-col">
                    {cve.affected_versions && cve.affected_versions.length > 0 ? (
                      <span className="versions-text">{cve.affected_versions.join(', ')}</span>
                    ) : (
                      <span className="versions-na">All versions</span>
                    )}
                  </div>

                  {/* Action Column */}
                  <div className="cve-column action-col">
                    <a 
                      href={cve.url} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="view-btn"
                      title="View on NVD"
                    >
                      View Details
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )))}
      </div>
    </div>
  )
}

export default Vulnerabilities
