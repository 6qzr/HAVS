import { HelpIcon } from '../shared/Icons'

// About Page Component
const About = () => {
  return (
    <div className="page-content">
      <div className="page-header">
        <div className="header-logo">
          <HelpIcon />
        </div>
        <h1>About</h1>
        <p>AI-Powered Security Vulnerability Scanner</p>
      </div>

      <div className="content-area">
        <div className="about-sections">
          {/* Overview Section */}
          <div className="about-section">
            <h2>Overview</h2>
            <p>
              This is a comprehensive security vulnerability scanning tool that combines 
              traditional dependency scanning with AI/ML technology to detect security 
              vulnerabilities in your codebase.
            </p>
          </div>

          {/* Features Section */}
          <div className="about-section">
            <h2>Key Features</h2>
            <div className="feature-list">
              <div className="feature-item">
                <strong>Dependency Scanning</strong>
                <p>
                  Scans project dependencies (npm, pip, Maven) against the National Vulnerability 
                  Database for known CVEs.
                </p>
              </div>
              <div className="feature-item">
                <strong>AI-Powered Analysis</strong>
                <p>
                  Uses a fine-tuned UniXcoder model to analyze source code and predict 
                  vulnerabilities in Python, Java, C, and C++ files.
                </p>
              </div>
              <div className="feature-item">
                <strong>Comprehensive Reporting</strong>
                <p>
                  Detailed reports with severity ratings, CVSS scores, CWE classifications, 
                  and CISA KEV alerts.
                </p>
              </div>
              <div className="feature-item">
                <strong>GitHub Actions Integration</strong>
                <p>
                  Automated vulnerability scanning on every push or pull request.
                </p>
              </div>
            </div>
          </div>

          {/* Contact Info */}
          <div className="about-section">
            <h2>Contact Information</h2>
            <div className="contact-info">
              <div className="contact-item">
                <strong>Email</strong>
                <span>imohammedalabri@gmail.com</span>
              </div>
              <div className="contact-item">
                <strong>Email</strong>
                <span>qaisalj@gmail.com</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default About

