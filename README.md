# 🔒 Vulnerability Scanner with ML Detection

A comprehensive security scanning system that combines traditional CVE scanning with AI-powered source code analysis for detecting vulnerabilities in your projects.

## ✨ Features

- 🔍 **Dependency Scanning** - Detect CVEs in npm, pip, and Maven dependencies
- 🤖 **ML-Powered Analysis** - AI source code vulnerability detection using RoBERTa
- 📤 **Multiple Upload Methods** - GitHub URL, ZIP archives, or individual files
- ⚡ **Real-time Progress** - WebSocket updates for long-running scans
- 🔄 **GitHub Actions Integration** - Automated scanning on push/PR
- 📊 **Comprehensive Reports** - Detailed vulnerability analysis with CVSS scores

## 🚀 Quick Start

**Prerequisites:** Python 3.7+, Node.js 16+

### 1. Install Dependencies

```bash
pip install -r requirements.txt
cd fyp_dashboard && npm install
```

### 2. Configure Environment

```bash
# Copy environment template
cp env.example .env

# Add your NVD API key (get from: https://nvd.nist.gov/developers/request-an-api-key)
nano .env
```

### 3. Run Application

```bash
# Start both frontend and backend (single command)
./start.sh
```

The script will:
- Load environment variables from `.env`
- Start backend services (ports 8000, 8001, 8002)
- Install frontend dependencies (if needed)
- Start frontend dev server

**Access:**
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

**Stop:** Press `Ctrl+C` to stop all services

## 🛠️ Tech Stack

**Backend:** FastAPI, PyTorch, Transformers, NVD API  
**Frontend:** React, Vite, WebSocket  
**ML Model:** RoBERTa (CodeBERT-based) fine-tuned for vulnerability detection

## 📊 Supported Files

**Dependencies:** `package.json`, `requirements.txt`, `pom.xml`  
**Source Code:** `.py`, `.java`, `.c`, `.cpp`  
**Archives:** `.zip`

## 🎯 Usage Examples

```bash
# Scan GitHub repository
Enter URL → Automatic clone and scan

# Upload ZIP archive
Drag & drop → Extract and analyze

# Multiple files
Select files → Upload → Batch analysis
```

## 📚 Documentation

- **API Documentation:** http://localhost:8000/docs (when running)
- **ML Model:** GraphCodeBERT base model (automatically downloaded from HuggingFace)
- **Environment Setup:** See `env.example` template

## 🔒 Security

- File size limits (100MB per file, 500MB extracted)
- Path traversal protection
- ZIP bomb prevention
- Automatic cleanup of temporary files

## ⚙️ Configuration

Key environment variables:
- `NVD_API_KEY` - Required for optimal scanning speed (50 req/30s vs 5 req/30s)
- `GITHUB_TOKEN` - Optional, for webhook integration

## 📝 Project Structure

```
├── backend/              # FastAPI microservices
│   ├── api.py           # Main API
│   ├── services/        # Dependency & ML analysis services
│   └── core/            # Scanner & ML inference logic
├── fyp_dashboard/       # React frontend
└── requirements.txt     # Python dependencies
```

## 🐛 Troubleshooting

**Common Issues:**

```bash
# Port already in use
lsof -ti:8000 | xargs kill -9
lsof -ti:5173 | xargs kill -9

# Permission denied for start.sh
chmod +x start.sh

# Missing .env file
cp env.example .env
nano .env  # Add your NVD_API_KEY
```
## 🤝 Contributing

This is a Final Year Project (FYP). Contributions and feedback are welcome!

## 📄 License

MIT License

---

**Ready to scan!** 🚀

