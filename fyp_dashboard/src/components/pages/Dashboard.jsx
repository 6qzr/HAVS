import { useState, useEffect } from 'react'
import jsPDF from 'jspdf'
import AnimatedCounter from '../shared/AnimatedCounter'
import { HomeIcon } from '../shared/Icons'
import logoImage from '../../assets/logo.png'

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

  // Export results as PDF
  const handleExportPDF = () => {
    const doc = new jsPDF()
    const pageWidth = doc.internal.pageSize.getWidth()
    const pageHeight = doc.internal.pageSize.getHeight()
    const margin = 20
    const maxWidth = pageWidth - (margin * 2)
    let yPos = margin
    const lineHeight = 7
    const sectionSpacing = 10

    // Helper function to add a new page if needed
    const checkPageBreak = (requiredSpace = lineHeight) => {
      if (yPos + requiredSpace > pageHeight - margin) {
        doc.addPage()
        yPos = margin
        return true
      }
      return false
    }

    // Helper function to add text with word wrapping
    const addWrappedText = (text, x, y, maxWidth, fontSize = 10) => {
      doc.setFontSize(fontSize)
      const lines = doc.splitTextToSize(text, maxWidth)
      doc.text(lines, x, y)
      return lines.length * (fontSize * 0.4 + 2)
    }

    // Add logo at the top right
    const logoSize = 25 // Logo height in mm
    const logoWidth = 25 // Logo width in mm
    const logoX = pageWidth - margin - logoWidth
    const logoY = margin
    
    try {
      // Try to add logo - logoImage should be a URL string from Vite
      if (typeof logoImage === 'string') {
        doc.addImage(logoImage, 'PNG', logoX, logoY, logoWidth, logoSize)
      } else if (logoImage && logoImage.src) {
        doc.addImage(logoImage.src, 'PNG', logoX, logoY, logoWidth, logoSize)
      }
    } catch (error) {
      console.warn('Could not add logo to PDF:', error)
    }

    // Title (centered, accounting for logo space)
    doc.setFontSize(20)
    doc.setFont(undefined, 'bold')
    const titleY = margin + logoSize / 2 - 5 // Center vertically with logo
    doc.text('Vulnerability Scan Report', margin, titleY)
    yPos = margin + logoSize + lineHeight * 1.5

    // Header Information
    doc.setFontSize(12)
    doc.setFont(undefined, 'normal')
    yPos += addWrappedText(`Repository: ${repoName}`, margin, yPos, maxWidth, 12)
    if (scanUrl) {
      yPos += addWrappedText(`URL: ${scanUrl}`, margin, yPos, maxWidth, 12)
    }
    if (timestamp) {
      yPos += addWrappedText(`Scan Date: ${new Date(timestamp).toLocaleString()}`, margin, yPos, maxWidth, 12)
    }
    if (duration) {
      yPos += addWrappedText(`Duration: ${duration}s`, margin, yPos, maxWidth, 12)
    }
    yPos += sectionSpacing

    // Summary Section
    checkPageBreak(lineHeight * 15)
    doc.setFontSize(16)
    doc.setFont(undefined, 'bold')
    doc.text('Summary', margin, yPos)
    yPos += lineHeight * 1.5

    doc.setFontSize(11)
    doc.setFont(undefined, 'normal')
    const summaryData = [
      ['Total Dependencies', summary.totalDependencies],
      ['Total Vulnerabilities', summary.totalVulnerabilities],
      ['Vulnerable Dependencies', summary.vulnerableDependencies],
      ['CISA Known Exploited', summary.cisaKevCount || 0],
      ['Critical Severity', summary.criticalCount],
      ['High Severity', summary.highCount],
      ['Medium Severity', summary.mediumCount],
      ['Low Severity', summary.lowCount],
    ]

    summaryData.forEach(([label, value]) => {
      doc.text(`${label}:`, margin, yPos)
      doc.setFont(undefined, 'bold')
      doc.text(String(value), margin + 80, yPos)
      doc.setFont(undefined, 'normal')
      yPos += lineHeight
    })
    yPos += sectionSpacing

    // Risk Score
    checkPageBreak(lineHeight * 5)
    doc.setFontSize(16)
    doc.setFont(undefined, 'bold')
    doc.text('Overall Risk Score', margin, yPos)
    yPos += lineHeight * 1.5

    doc.setFontSize(14)
    doc.setFont(undefined, 'bold')
    doc.text(`${riskScore}/100 - ${riskLevel.level} Risk`, margin, yPos)
    yPos += lineHeight
    doc.setFontSize(10)
    doc.setFont(undefined, 'normal')
    const riskDescription = 
      riskScore >= 75 ? 'Immediate action required. Critical vulnerabilities detected.' :
      riskScore >= 50 ? 'High priority fixes needed. Multiple severe issues found.' :
      riskScore >= 25 ? 'Moderate risk level. Address vulnerabilities soon.' :
      'Low risk level. Continue monitoring for updates.'
    yPos += addWrappedText(riskDescription, margin, yPos, maxWidth, 10)
    yPos += sectionSpacing

    // Severity Distribution
    checkPageBreak(lineHeight * 10)
    doc.setFontSize(16)
    doc.setFont(undefined, 'bold')
    doc.text('Severity Distribution', margin, yPos)
    yPos += lineHeight * 1.5

    doc.setFontSize(11)
    doc.setFont(undefined, 'normal')
    const severityData = [
      ['Critical', summary.criticalCount, '#dc2626'],
      ['High', summary.highCount, '#ea580c'],
      ['Medium', summary.mediumCount, '#f59e0b'],
      ['Low', summary.lowCount, '#84cc16'],
    ]

    severityData.forEach(([severity, count, color]) => {
      const percentage = summary.totalVulnerabilities > 0 
        ? ((count / summary.totalVulnerabilities) * 100).toFixed(1) 
        : '0.0'
      doc.text(`${severity}: ${count} (${percentage}%)`, margin, yPos)
      yPos += lineHeight
    })
    yPos += sectionSpacing

    // CWE Distribution
    if (cweArray.length > 0) {
      checkPageBreak(lineHeight * 10)
      doc.setFontSize(16)
      doc.setFont(undefined, 'bold')
      doc.text('Top CWE Distribution', margin, yPos)
      yPos += lineHeight * 1.5

      doc.setFontSize(11)
      doc.setFont(undefined, 'normal')
      cweArray.forEach((item) => {
        doc.text(`${item.cwe}: ${item.count}`, margin, yPos)
        yPos += lineHeight
      })
      yPos += sectionSpacing
    }

    // Most Affected Packages
    if (mostAffectedPackages.length > 0) {
      checkPageBreak(lineHeight * 10)
      doc.setFontSize(16)
      doc.setFont(undefined, 'bold')
      doc.text('Most Affected Packages', margin, yPos)
      yPos += lineHeight * 1.5

      doc.setFontSize(11)
      doc.setFont(undefined, 'normal')
      mostAffectedPackages.forEach((pkg, idx) => {
        doc.text(`${idx + 1}. ${pkg.name} v${pkg.version} - ${pkg.vulnerabilityCount} CVE(s)`, margin, yPos)
        yPos += lineHeight
      })
      yPos += sectionSpacing
    }

    // Vulnerabilities Section - Grouped by Package (matching Vulnerabilities page)
    const vulnerableDeps = dependencies.filter(dep => dep.hasVulnerabilities)
    
    if (vulnerableDeps.length > 0) {
      checkPageBreak(lineHeight * 15)
      doc.setFontSize(16)
      doc.setFont(undefined, 'bold')
      doc.text(`Vulnerable Dependencies (${vulnerableDeps.length})`, margin, yPos)
      yPos += lineHeight * 2

      // Helper function to deduplicate CWE values
      const deduplicateCWE = (cweString) => {
        if (!cweString || cweString === 'N/A') return 'N/A'
        const cweList = cweString.split(',')
          .map(cwe => cwe.trim())
          .filter(cwe => cwe && cwe.length > 0)
        const uniqueCWEs = [...new Set(cweList)]
        return uniqueCWEs.join(', ')
      }

      // Limit packages to avoid PDF being too large
      const maxPackages = 20
      const packagesToShow = vulnerableDeps.slice(0, maxPackages)
      let totalCVEsShown = 0
      const maxCVEs = 100

      for (let depIdx = 0; depIdx < packagesToShow.length; depIdx++) {
        const dep = packagesToShow[depIdx]
        
        // Package Header
        checkPageBreak(lineHeight * 8)
        doc.setFontSize(12)
        doc.setFont(undefined, 'bold')
        doc.setFillColor(230, 230, 230)
        doc.rect(margin, yPos - 5, pageWidth - (margin * 2), lineHeight + 4, 'F')
        doc.text(dep.name, margin + 2, yPos)
        yPos += lineHeight + 2

        doc.setFontSize(9)
        doc.setFont(undefined, 'normal')
        const packageMeta = `v${dep.version} • ${dep.ecosystem} • ${dep.vulnerabilityCount} ${dep.vulnerabilityCount === 1 ? 'CVE' : 'CVEs'}`
        doc.text(packageMeta, margin + 2, yPos)
        yPos += lineHeight * 1.5

        // CVE Rows for this package
        const cvesToShow = dep.cves.slice(0, Math.min(dep.cves.length, maxCVEs - totalCVEsShown))
        
        if (cvesToShow.length > 0) {
          // CVE Table Header
          doc.setFontSize(8)
          doc.setFont(undefined, 'bold')
          doc.setFillColor(240, 240, 240)
          doc.rect(margin, yPos - 4, pageWidth - (margin * 2), lineHeight + 2, 'F')
          
          let xPos = margin + 2
          const colWidths = [35, 25, 20, 35, 50]
          const headers = ['CVE ID', 'Severity', 'CVSS', 'CWE', 'Affected Versions']
          
          for (let idx = 0; idx < headers.length; idx++) {
            doc.text(headers[idx], xPos, yPos)
            xPos += colWidths[idx]
          }
          yPos += lineHeight + 2

          doc.setFont(undefined, 'normal')
          doc.setFontSize(7)

          for (let cveIdx = 0; cveIdx < cvesToShow.length; cveIdx++) {
            const cve = cvesToShow[cveIdx]
            checkPageBreak(lineHeight * 2)
            
            // CVE ID with CISA KEV indicator
            xPos = margin + 2
            let cveIdText = cve.cve_id || cve.id || 'N/A'
            if (cveIdText.length > 15) {
              cveIdText = cveIdText.substring(0, 12) + '...'
            }
            doc.text(cveIdText, xPos, yPos)
            
            // Check CISA KEV - be more strict with the check (only show if explicitly true or "Yes")
            const isCisaKev = (cve.cisaKev === true) || (cve.cisa_kev === 'Yes')
            if (isCisaKev) {
              doc.setFontSize(6)
              doc.setFont(undefined, 'bold')
              doc.setTextColor(220, 38, 38) // Red for CISA KEV
              doc.text('KEV', xPos + 20, yPos)
              doc.setTextColor(0, 0, 0)
              doc.setFontSize(7)
              doc.setFont(undefined, 'normal')
            }
            xPos += colWidths[0]

            // Severity
            const severity = (cve.severity || 'N/A').toUpperCase()
            doc.text(severity, xPos, yPos)
            xPos += colWidths[1]

            // CVSS Score
            const cvss = cve.cvss_score || cve.cvssScore
            const cvssText = cvss ? cvss.toFixed(1) : 'N/A'
            doc.text(cvssText, xPos, yPos)
            xPos += colWidths[2]

            // CWE
            const cweText = deduplicateCWE(cve.cwe || 'N/A')
            const cweDisplay = cweText.length > 20 ? cweText.substring(0, 17) + '...' : cweText
            doc.text(cweDisplay, xPos, yPos)
            xPos += colWidths[3]

            // Affected Versions
            const affectedVersions = cve.affected_versions || cve.affectedVersions || []
            const versionsText = affectedVersions.length > 0 
              ? (Array.isArray(affectedVersions) ? affectedVersions.join(', ') : affectedVersions)
              : 'All versions'
            const versionsDisplay = versionsText.length > 30 ? versionsText.substring(0, 27) + '...' : versionsText
            doc.text(versionsDisplay, xPos, yPos)

            yPos += lineHeight + 1
            totalCVEsShown++

            // Draw subtle line between CVEs
            if (cveIdx < cvesToShow.length - 1) {
              doc.setDrawColor(220, 220, 220)
              doc.setLineWidth(0.1)
              doc.line(margin, yPos - 1, pageWidth - margin, yPos - 1)
            }
          }

          yPos += lineHeight
        }

        // Draw line between packages
        if (depIdx < packagesToShow.length - 1) {
          doc.setDrawColor(200, 200, 200)
          doc.setLineWidth(0.5)
          doc.line(margin, yPos, pageWidth - margin, yPos)
          yPos += lineHeight
        }

        // Check if we've reached the CVE limit
        if (totalCVEsShown >= maxCVEs) {
          break
        }
      }

      // Add note if truncated
      const totalPackages = vulnerableDeps.length
      const totalCVEs = vulnerableDeps.reduce((sum, dep) => sum + dep.cves.length, 0)
      
      if (totalPackages > maxPackages || totalCVEsShown >= maxCVEs) {
        yPos += lineHeight
        doc.setFontSize(7)
        doc.setFont(undefined, 'italic')
        doc.setTextColor(100, 100, 100)
        let note = ''
        if (totalPackages > maxPackages && totalCVEsShown >= maxCVEs) {
          note = `Note: Showing first ${packagesToShow.length} packages with ${totalCVEsShown} CVEs. Total: ${totalPackages} packages, ${totalCVEs} CVEs. Use JSON/CSV export for complete data.`
        } else if (totalPackages > maxPackages) {
          note = `Note: Showing first ${packagesToShow.length} of ${totalPackages} packages. Use JSON/CSV export for complete data.`
        } else if (totalCVEsShown >= maxCVEs) {
          note = `Note: Showing first ${totalCVEsShown} of ${totalCVEs} CVEs. Use JSON/CSV export for complete data.`
        }
        doc.text(note, margin, yPos)
        doc.setTextColor(0, 0, 0)
        doc.setFont(undefined, 'normal')
      }
    }

    // Footer
    const totalPages = doc.internal.getNumberOfPages()
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i)
      doc.setFontSize(8)
      doc.setFont(undefined, 'italic')
      doc.text(
        `Page ${i} of ${totalPages} - Generated ${new Date().toLocaleString()}`,
        pageWidth / 2,
        pageHeight - 10,
        { align: 'center' }
      )
    }

    // Save the PDF
    doc.save(`vulnerability-scan-${repoName}-${Date.now()}.pdf`)
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
            <button className="export-btn pdf" onClick={handleExportPDF}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14,2 14,8 20,8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
                <polyline points="10,9 9,9 8,9"/>
              </svg>
              Export as PDF
            </button>
          </div>
          <p className="export-info">Download scan results for reporting or further analysis</p>
        </div>

      </div>
    </div>
  )
}

export default Dashboard
