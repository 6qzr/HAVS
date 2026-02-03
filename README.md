# 🔒 HAVS: Hybrid Automated Vulnerability Scanner

A professional-grade security analysis platform for modern software development. **HAVS** (Hybrid Automated Vulnerability Scanner) combines traditional CVE-based dependency analysis with a **Fine-tuned UniXcoder AI model** to deliver high-precision security insights.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## � Key Features

*   🤖 **AI-Powered Core**: Leverages a fine-tuned **UniXcoder** model for deep semantic analysis of source code.
*   ⚖️ **High Precision (Z-Score)**: Uses statistical Z-score adaptive thresholding to eliminate noise and detect subtle vulnerabilities.
*   � **Dependency Scanning**: Automatic CVE detection across `npm` (package.json), `pip` (requirements.txt), and `Maven` (pom.xml).
*   🔍 **Pattern-Matching Engine**: Supplemented by a regex-based pattern engine for 100% reliable detection of common injection points.
*   📤 **Flexible Analysis**: Support for GitHub URLs, ZIP uploads, or individual file drops.
*   📊 **Real-time Dashboard**: Interactive React-based dashboard with real-time scan progress via WebSockets.

---

## 🛠️ Tech Stack

### Backend
- **Framework**: FastAPI (Python)
- **ML Engine**: PyTorch & HuggingFace Transformers
- **Intelligence**: Fine-tuned UniXcoder Model
- **Vulnerability Data**: NIST NVD API

### Frontend
- **Framework**: React.js with Vite
- **Styling**: Vanilla CSS (Modern Aesthetics)
- **Communication**: REST API & WebSockets

---

## ⚡ Quick Start

### 1. Prerequisites
- **Python 3.11+**
- **Node.js 18+**
- **NVD API Key** (Recommended: [Get one here](https://nvd.nist.gov/developers/request-an-api-key))

### 2. Installation & Setup

```bash
# Clone the repository
git clone https://github.com/your-username/havs.git
cd havs

# Setup Environment
cp env.example .env
# Edit .env and add your NVD_API_KEY
```

### 3. Running the Application

**On Windows (PowerShell):**
```powershell
./start.ps1
```

**On Linux/Mac:**
```bash
chmod +x start.sh
./start.sh
```

---

## 📊 Deployment & Access

Once started, the application will be available at:
- **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)
- **Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ML Analysis Service**: Port 8002
- **Dependency Service**: Port 8001

---

## � Project Structure

```text
├── backend/
│   ├── api/            # Main FastAPI endpoints
│   ├── core/           # ML Logic & Scanning Engines
│   └── services/       # Microservices (ML, Dependency)
├── fyp_dashboard/      # React Frontend Source
├── ml_model/           # Local model binaries & configs
├── logs/               # Automated service logs
└── requirements.txt    # Python dependencies
```

---

## �️ Security Best Practices

HAVS is designed with security in mind:
- **Rate Limiting**: Automatic NVD API rate-limit handling.
- **Normalization**: Code normalization to strip noise (comments/whitespace) before AI analysis.
- **Cleanup**: Automatic temporary directory cleanup after scan completion.

---

## 🤝 Contributing

This project was developed as a Final Year Project (FYP). We welcome contributions, bug reports, and suggestions for improving the ML model's accuracy.

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---
*Developed with ❤️ for Advanced Software Security.*

