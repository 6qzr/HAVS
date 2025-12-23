import { useState, useEffect } from 'react'
import './App.css'

// Import shared components
import { ShieldIcon, HomeIcon, DocumentIcon, BrainIcon, GitHubActionsIcon, HelpIcon } from './components/shared/Icons'
import FloatingParticles from './components/shared/FloatingParticles'

// Import page components
import ScanRepository from './components/pages/ScanRepository'
import Dashboard from './components/pages/Dashboard'
import Vulnerabilities from './components/pages/Vulnerabilities'
import MLPredictions from './components/pages/MLPredictions'
import GitHubActions from './components/pages/GitHubActions'
import About from './components/pages/About'

/*
 * BACKEND INTEGRATION GUIDE
 * ========================
 * 
 * This frontend is ready for backend integration. The scan functionality currently uses mock data.
 * 
 * KEY INTEGRATION POINTS:
 * 1. handleScan() function - Replace mock implementation with real API calls
 * 2. Progress updates - Replace mock progress with real-time status from backend
 * 3. Results display - Add UI to show scan results (vulnerabilities, dependencies, etc.)
 * 
 * REQUIRED BACKEND ENDPOINTS:
 * - POST /api/scan - Start security scan
 * - GET /api/scan/{id}/progress - Get scan progress
 * - GET /api/scan/{id}/results - Get scan results
 * 
 * See detailed comments in ScanRepository component for complete API specifications.
 */


function App() {
  const [activeItem, setActiveItem] = useState('Scan Repository')
  const [isLoaded, setIsLoaded] = useState(false)
  
  useEffect(() => {
    setIsLoaded(true)
  }, [])

  const navigationItems = [
    { id: 'Scan Repository', icon: <ShieldIcon />, label: 'Scan Repository' },
    { id: 'Dashboard', icon: <HomeIcon />, label: 'Dashboard' },
    { id: 'Vulnerabilities', icon: <DocumentIcon />, label: 'Vulnerabilities' },
    { id: 'ML Predictions', icon: <BrainIcon />, label: 'ML Predictions' },
    { id: 'GitHub Actions', icon: <GitHubActionsIcon />, label: 'GitHub Actions' },
    { id: 'About', icon: <HelpIcon />, label: 'About' }
  ]

  return (
    <div className={`app-container ${isLoaded ? 'loaded' : ''}`}>
      <FloatingParticles />
      <div className="sidebar">
        <nav className="sidebar-nav">
          {navigationItems.map((item) => (
            <div
              key={item.id}
              className={`nav-item ${activeItem === item.id ? 'active' : ''}`}
              onClick={() => setActiveItem(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </div>
          ))}
        </nav>
        
        <div className="sidebar-footer">
          <div className="version-text">v1.0.0 Beta</div>
        </div>
      </div>
      
      <div className="main-content">
        {activeItem === 'Scan Repository' && <ScanRepository onScanComplete={setActiveItem} />}
        {activeItem === 'Dashboard' && <Dashboard />}
        {activeItem === 'Vulnerabilities' && <Vulnerabilities />}
        {activeItem === 'ML Predictions' && <MLPredictions />}
        {activeItem === 'GitHub Actions' && <GitHubActions />}
        {activeItem === 'About' && <About />}
      </div>
    </div>
  )
}

export default App
