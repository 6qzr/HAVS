import { useState, useEffect } from 'react'
import AnimatedCounter from '../shared/AnimatedCounter'
import { HomeIcon } from '../shared/Icons'

// Dashboard Page Component
const Dashboard = () => {
  const [scanResults, setScanResults] = useState(null)
  const [scanUrl, setScanUrl] = useState('')

  useEffect(() => {
    // Load last scan results from sessionStorage
    const results = sessionStorage.getItem('lastScanResults')
    const url = sessionStorage.getItem('lastScanUrl')
    
    if (results) {
      setScanResults(JSON.parse(results))
    }
    if (url) {
      setScanUrl(url)
    }
  }, [])

  // Show placeholder if no scan results
  if (!scanResults) {
    return (
      <div className="dashboard-content">
        <div className="dashboard-header">
          <div className="header-logo">
            <HomeIcon />
          </div>
          <h1>Dashboard</h1>
          <p>Security scan results and analytics</p>
        </div>
        
        <div className="no-data-message">
          <h3>No scan results available</h3>
          <p>Run a security scan to see your results here</p>
        </div>
      </div>
    )
  }

  const { summary, dependencies, vulnerabilities, timestamp, duration } = scanResults

  // Check if no dependencies were scanned (source code only)
  if (!summary || summary.totalDependencies === 0) {
    return (
      <div className="dashboard-content">
        <div className="dashboard-header">
          <div className="header-logo">
            <HomeIcon />
          </div>
          <h1>Dashboard</h1>
          <p>Security scan results and analytics</p>
        </div>
        
        <div className="no-data-message">
          <h3>No dependency files found</h3>
          <p>This scan only contains source code files. No dependencies were scanned.</p>
          <p>To view ML analysis results, go to the <strong>ML Predictions</strong> page.</p>
        </div>
      </div>
    )
  }

  // Extract repo name from URL
  const repoName = scanUrl ? scanUrl.split('/').pop().replace('.git', '') : 'Unknown'
  const repoOwner = scanUrl ? scanUrl.split('/').slice(-2, -1)[0] : ''

  // Calculate risk score (0-100)
  const calculateRiskScore = () => {
    const criticalWeight = 10
    const highWeight = 7
    const mediumWeight = 4
    const lowWeight = 1
    
    const totalScore = (
      summary.criticalCount * criticalWeight +
      summary.highCount * highWeight +
      summary.mediumCount * mediumWeight +
      summary.lowCount * lowWeight
    )
    
    const maxPossibleScore = summary.totalDependencies * criticalWeight
    const riskPercentage = maxPossibleScore > 0 ? (totalScore / maxPossibleScore) * 100 : 0
    
    return Math.min(Math.round(riskPercentage), 100)
  }

  const riskScore = calculateRiskScore()

  // Get risk level based on score
  const getRiskLevel = (score) => {
    if (score >= 75) return { level: 'Critical', class: 'critical' }
    if (score >= 50) return { level: 'High', class: 'high' }
    if (score >= 25) return { level: 'Medium', class: 'medium' }
    return { level: 'Low', class: 'low' }
  }

  const riskLevel = getRiskLevel(riskScore)

  // Get most affected packages (top 5)
  const mostAffectedPackages = [...dependencies]
    .filter(dep => dep.hasVulnerabilities)
    .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount)
    .slice(0, 5)

  // Calculate CWE distribution (top 5 most common CWEs)
  const calculateCWEDistribution = () => {
    const cweCount = {}
    
    // Count each CWE occurrence
    vulnerabilities.forEach(vuln => {
      if (vuln.cwe && vuln.cwe !== 'N/A') {
        // Split multiple CWEs if comma-separated, remove duplicates within the same vulnerability
        const cwes = [...new Set(vuln.cwe.split(',').map(c => c.trim()).filter(c => c && c.length > 0))]
        cwes.forEach(cwe => {
          if (cwe && cwe.startsWith('CWE-')) {
            cweCount[cwe] = (cweCount[cwe] || 0) + 1
          }
        })
      }
    })
    
    // Convert to array and sort by count (descending) - show top 5
    const cweArray = Object.entries(cweCount)
      .map(([cwe, count]) => ({ cwe, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5) // Top 5 CWEs
    
    const totalCWEs = cweArray.reduce((sum, item) => sum + item.count, 0)
    
    return { cweArray, totalCWEs }
  }

  const { cweArray, totalCWEs } = calculateCWEDistribution()

  // Export results as JSON
  const handleExportJSON = () => {
    const dataStr = JSON.stringify(scanResults, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `vulnerability-scan-${repoName}-${Date.now()}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  // Export results as CSV
  const handleExportCSV = () => {
    // Create CSV content
    let csvContent = ''
    
    // Header Section
    csvContent += 'Vulnerability Scan Report\n'
    csvContent += `Repository,${repoName}\n`
    csvContent += `URL,${scanUrl}\n`
    csvContent += `Scan Date,${timestamp ? new Date(timestamp).toLocaleString() : 'N/A'}\n`
    csvContent += `Duration,${duration}s\n`
    csvContent += '\n'
    
    // Summary Section
    csvContent += 'Summary\n'
    csvContent += 'Metric,Count\n'
    csvContent += `Total Dependencies,${summary.totalDependencies}\n`
    csvContent += `Total Vulnerabilities,${summary.totalVulnerabilities}\n`
    csvContent += `Vulnerable Dependencies,${summary.vulnerableDependencies}\n`
    csvContent += `CISA Known Exploited,${summary.cisaKevCount || 0}\n`
    csvContent += `Critical Severity,${summary.criticalCount}\n`
    csvContent += `High Severity,${summary.highCount}\n`
    csvContent += `Medium Severity,${summary.mediumCount}\n`
    csvContent += `Low Severity,${summary.lowCount}\n`
    csvContent += '\n'
    
    // Vulnerabilities Section
    if (vulnerabilities && vulnerabilities.length > 0) {
      csvContent += 'Vulnerabilities\n'
      csvContent += 'CVE ID,Package,Version,Ecosystem,Severity,CVSS Score,CWE,CISA KEV,Status,Affected Versions,URL\n'
      
      vulnerabilities.forEach(vuln => {
        const affectedVersions = vuln.affectedVersions 
          ? (Array.isArray(vuln.affectedVersions) ? vuln.affectedVersions.join('; ') : vuln.affectedVersions)
          : 'N/A'
        
        csvContent += `"${vuln.id}","${vuln.package}","${vuln.version}","${vuln.ecosystem}","${vuln.severity}",${vuln.cvssScore || 'N/A'},"${vuln.cwe || 'N/A'}","${vuln.cisaKev ? 'Yes' : 'No'}","${vuln.status}","${affectedVersions}","${vuln.url}"\n`
      })
      csvContent += '\n'
    }
    
    // Dependencies Section
    if (dependencies && dependencies.length > 0) {
      csvContent += 'Dependencies\n'
      csvContent += 'Name,Version,Ecosystem,Vulnerability Count,Has Vulnerabilities\n'
      
      dependencies.forEach(dep => {
        csvContent += `"${dep.name}","${dep.version}","${dep.ecosystem}",${dep.vulnerabilityCount},${dep.hasVulnerabilities ? 'Yes' : 'No'}\n`
      })
    }
    
    // Create and download CSV file
    const csvBlob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(csvBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `vulnerability-scan-${repoName}-${Date.now()}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }


  return (
    <div className="dashboard-content">
      <div className="dashboard-header">
        <div className="header-logo">
          <HomeIcon />
        </div>
        <h1>Dashboard</h1>
        <p>Security scan results and analytics</p>
        {scanUrl && (
          <div className="repo-info">
            <h2 className="repo-name">{repoOwner}/{repoName}</h2>
            <p className="repo-url">{scanUrl}</p>
          </div>
        )}
        {timestamp && (
          <p className="scan-timestamp">
            Scanned {new Date(timestamp).toLocaleString()} • Duration: {duration}s
          </p>
        )}
      </div>
      
      <div className="dashboard-stats">
        <div className="stat-card">
          <h3>Total Dependencies</h3>
          <div className="stat-number"><AnimatedCounter end={summary.totalDependencies} /></div>
          <p>Packages analyzed</p>
        </div>
        <div className="stat-card">
          <h3>Vulnerabilities Found</h3>
          <div className="stat-number"><AnimatedCounter end={summary.totalVulnerabilities} /></div>
          <p>Across all dependencies</p>
        </div>
        <div className="stat-card">
          <h3>Critical + High Risk</h3>
          <div className="stat-number">
            <AnimatedCounter end={summary.criticalCount + summary.highCount} />
          </div>
          <p>Require immediate attention</p>
        </div>
        <div className="stat-card">
          <h3>Vulnerable Dependencies</h3>
          <div className="stat-number"><AnimatedCounter end={summary.vulnerableDependencies} /></div>
          <p>Packages with CVEs</p>
        </div>
        <div className="stat-card cisa-kev-card">
          <h3>CISA Known Exploited</h3>
          <div className="stat-number"><AnimatedCounter end={summary.cisaKevCount || 0} /></div>
          <p>Actively exploited in the wild</p>
        </div>
      </div>

      {/* Risk Score Card */}
      <div className="risk-score-section">
        <div className="risk-score-card">
          <h3>Overall Risk Score</h3>
          <div className="risk-score-display">
            <div className={`risk-score-circle ${riskLevel.class}`}>
              <span className="risk-score-number">{riskScore}</span>
              <span className="risk-score-max">/100</span>
            </div>
            <div className="risk-level-info">
              <span className={`risk-level-badge ${riskLevel.class}`}>{riskLevel.level} Risk</span>
              <p className="risk-description">
                {riskScore >= 75 && 'Immediate action required. Critical vulnerabilities detected.'}
                {riskScore >= 50 && riskScore < 75 && 'High priority fixes needed. Multiple severe issues found.'}
                {riskScore >= 25 && riskScore < 50 && 'Moderate risk level. Address vulnerabilities soon.'}
                {riskScore < 25 && 'Low risk level. Continue monitoring for updates.'}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="dashboard-sections">
        {/* Severity Distribution */}
        <div className="dashboard-section">
          <h3>Severity Distribution</h3>
          <div className="severity-chart">
            <div className="severity-bar-item">
              <div className="severity-bar-label">
                <span>Critical</span>
                <span className="severity-count">{summary.criticalCount}</span>
              </div>
              <div className="severity-bar-track">
                <div 
                  className="severity-bar-fill critical" 
                  style={{ width: `${summary.totalVulnerabilities > 0 ? (summary.criticalCount / summary.totalVulnerabilities) * 100 : 0}%` }}
                ></div>
              </div>
            </div>
            <div className="severity-bar-item">
              <div className="severity-bar-label">
                <span>High</span>
                <span className="severity-count">{summary.highCount}</span>
              </div>
              <div className="severity-bar-track">
                <div 
                  className="severity-bar-fill high" 
                  style={{ width: `${summary.totalVulnerabilities > 0 ? (summary.highCount / summary.totalVulnerabilities) * 100 : 0}%` }}
                ></div>
              </div>
            </div>
            <div className="severity-bar-item">
              <div className="severity-bar-label">
                <span>Medium</span>
                <span className="severity-count">{summary.mediumCount}</span>
              </div>
              <div className="severity-bar-track">
                <div 
                  className="severity-bar-fill medium" 
                  style={{ width: `${summary.totalVulnerabilities > 0 ? (summary.mediumCount / summary.totalVulnerabilities) * 100 : 0}%` }}
                ></div>
              </div>
            </div>
            <div className="severity-bar-item">
              <div className="severity-bar-label">
                <span>Low</span>
                <span className="severity-count">{summary.lowCount}</span>
              </div>
              <div className="severity-bar-track">
                <div 
                  className="severity-bar-fill low" 
                  style={{ width: `${summary.totalVulnerabilities > 0 ? (summary.lowCount / summary.totalVulnerabilities) * 100 : 0}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        {/* CWE Distribution */}
        <div className="dashboard-section">
          <h3>CWE Distribution</h3>
          <p className="section-subtitle">Top 5 Common Weakness Enumerations</p>
          {cweArray.length > 0 ? (
            <div className="severity-chart">
              {cweArray.map((item, idx) => (
                <div key={idx} className="severity-bar-item">
                  <div className="severity-bar-label">
                    <span>{item.cwe}</span>
                    <span className="severity-count">{item.count}</span>
                  </div>
                  <div className="severity-bar-track">
                    <div 
                      className="severity-bar-fill cwe-fill" 
                      style={{ width: `${totalCWEs > 0 ? (item.count / totalCWEs) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="no-cwe-data">No CWE data available for this scan</p>
          )}
        </div>

        {/* Most Affected Packages */}
        <div className="dashboard-section">
          <h3>Most Affected Packages</h3>
          {mostAffectedPackages.length > 0 ? (
            <div className="affected-packages-list">
              {mostAffectedPackages.map((pkg, idx) => (
                <div key={idx} className="affected-package-item">
                  <div className="package-rank">{idx + 1}</div>
                  <div className="package-info">
                    <div className="package-name">{pkg.name}</div>
                    <div className="package-version">v{pkg.version}</div>
                  </div>
                  <div className="package-vuln-badge">
                    {pkg.vulnerabilityCount} CVE{pkg.vulnerabilityCount > 1 ? 's' : ''}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="no-affected-packages">No vulnerable packages found</p>
          )}
        </div>

        {/* Export Results */}
        <div className="dashboard-section">
          <h3>Export Results</h3>
          <div className="export-options">
            <button className="export-btn json" onClick={handleExportJSON}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14,2 14,8 20,8"/>
              </svg>
              Export as JSON
            </button>
            <button className="export-btn csv" onClick={handleExportCSV}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14,2 14,8 20,8"/>
                <line x1="8" y1="13" x2="16" y2="13"/>
                <line x1="8" y1="17" x2="16" y2="17"/>
              </svg>
              Export as CSV
            </button>
          </div>
          <p className="export-info">Download scan results for reporting or further analysis</p>
        </div>

      </div>
    </div>
  )
}

export default Dashboard
