import { useState } from 'react'
import { GitHubActionsIcon } from '../shared/Icons'

const GitHubActions = () => {
  const [copied, setCopied] = useState(false)

  // Build workflow content with proper escaping for GitHub Actions syntax
  const getWorkflowContent = () => {
    const openBrace = '{'
    const closeBrace = '}'
    const doubleOpen = openBrace + openBrace
    const doubleClose = closeBrace + closeBrace
    
    // Use string concatenation to avoid JSX parsing issues
    const result = 'name: Automated Vulnerability Scan\n\n' +
      'on:\n' +
      '  push:\n' +
      '    branches: [ main, master, develop ]\n' +
      '  pull_request:\n' +
      '    branches: [ main, master, develop ]\n\n' +
      'jobs:\n' +
      '  scan:\n' +
      '    runs-on: ubuntu-latest\n' +
      '    \n' +
      '    steps:\n' +
      '    - name: Checkout code\n' +
      '      uses: actions/checkout@v4\n' +
      '      with:\n' +
      '        fetch-depth: 0\n' +
      '    \n' +
      '    - name: Detect changed files\n' +
      '      id: changed-files\n' +
      '      uses: tj-actions/changed-files@v40\n' +
      '      with:\n' +
      '        files: |\n' +
      '          **/package.json\n' +
      '          **/requirements.txt\n' +
      '          **/pom.xml\n' +
      '          **/*.py\n' +
      '          **/*.java\n' +
      '          **/*.cpp\n' +
      '          **/*.c\n' +
      '    \n' +
      '    - name: Check for dependency files\n' +
      '      id: check-deps\n' +
      '      run: |\n' +
      '        if [ -n "$' + doubleOpen + ' steps.changed-files.outputs.any_changed ' + doubleClose + '" ]; then\n' +
      '          DEPS_FOUND=false\n' +
      '          for file in $' + doubleOpen + ' steps.changed-files.outputs.all_changed_files ' + doubleClose + '; do\n' +
      '            if [[ "$file" == *"package.json" ]] || [[ "$file" == *"requirements.txt" ]] || [[ "$file" == *"pom.xml" ]]; then\n' +
      '              DEPS_FOUND=true\n' +
      '              break\n' +
      '            fi\n' +
      '          done\n' +
      '          echo "deps_found=$DEPS_FOUND" >> $GITHUB_OUTPUT\n' +
      '        else\n' +
      '          echo "deps_found=false" >> $GITHUB_OUTPUT\n' +
      '        fi\n' +
      '    \n' +
      '    - name: Check for source code files\n' +
      '      id: check-source\n' +
      '      run: |\n' +
      '        if [ -n "$' + doubleOpen + ' steps.changed-files.outputs.any_changed ' + doubleClose + '" ]; then\n' +
      '          SOURCE_FOUND=false\n' +
      '          for file in $' + doubleOpen + ' steps.changed-files.outputs.all_changed_files ' + doubleClose + '; do\n' +
      '            if [[ "$file" == *.py ]] || [[ "$file" == *.java ]] || [[ "$file" == *.cpp ]] || [[ "$file" == *.c ]]; then\n' +
      '              SOURCE_FOUND=true\n' +
      '              break\n' +
      '            fi\n' +
      '          done\n' +
      '          echo "source_found=$SOURCE_FOUND" >> $GITHUB_OUTPUT\n' +
      '        else\n' +
      '          echo "source_found=false" >> $GITHUB_OUTPUT\n' +
      '        fi\n' +
      '    \n' +
      '    - name: Scan dependencies\n' +
      '      if: steps.check-deps.outputs.deps_found == \'true\'\n' +
      '      run: |\n' +
      '        python3 << \'EOF\'\n' +
      '        import json\n' +
      '        import os\n' +
      '        import sys\n' +
      '        \n' +
      '        changed_files = os.environ.get(\'CHANGED_FILES\', \'\').split()\n' +
      '        files_data = []\n' +
      '        \n' +
      '        for file_path in changed_files:\n' +
      '            if any(file_path.endswith(ext) for ext in [\'package.json\', \'requirements.txt\', \'pom.xml\']):\n' +
      '                if os.path.isfile(file_path):\n' +
      '                    with open(file_path, \'r\', encoding=\'utf-8\') as f:\n' +
      '                        content = f.read()\n' +
      '                    files_data.append({\n' +
      '                        "path": file_path,\n' +
      '                        "content": content\n' +
      '                    })\n' +
      '        \n' +
      '        payload = {\n' +
      '            "files": files_data,\n' +
      '            "repository": os.environ.get(\'GITHUB_REPOSITORY\'),\n' +
      '            "commit_sha": os.environ.get(\'GITHUB_SHA\'),\n' +
      '            "pr_number": int(os.environ.get(\'PR_NUMBER\', \'0\')) if os.environ.get(\'PR_NUMBER\') else None,\n' +
      '            "event_type": os.environ.get(\'GITHUB_EVENT_NAME\', \'push\')\n' +
      '        }\n' +
      '        \n' +
      '        import requests\n' +
      '        api_url = os.environ.get(\'SCANNER_API_URL\')\n' +
      '        api_token = os.environ.get(\'SCANNER_API_TOKEN\', \'\')\n' +
      '        \n' +
      '        headers = {"Content-Type": "application/json"}\n' +
      '        if api_token:\n' +
      '            headers["Authorization"] = f"Bearer {api_token}"\n' +
      '        \n' +
      '        response = requests.post(\n' +
      '            f"{api_url}/github/scan-dependencies",\n' +
      '            json=payload,\n' +
      '            headers=headers,\n' +
      '            timeout=600\n' +
      '        )\n' +
      '        response.raise_for_status()\n' +
      '        print(response.json())\n' +
      '        EOF\n' +
      '      env:\n' +
      '        CHANGED_FILES: $' + doubleOpen + ' steps.changed-files.outputs.all_changed_files ' + doubleClose + '\n' +
      '        SCANNER_API_URL: $' + doubleOpen + ' secrets.SCANNER_API_URL ' + doubleClose + '\n' +
      '        SCANNER_API_TOKEN: $' + doubleOpen + ' secrets.SCANNER_API_TOKEN ' + doubleClose + '\n' +
      '        GITHUB_REPOSITORY: $' + doubleOpen + ' github.repository ' + doubleClose + '\n' +
      '        GITHUB_SHA: $' + doubleOpen + ' github.sha ' + doubleClose + '\n' +
      '        PR_NUMBER: $' + doubleOpen + ' github.event.pull_request.number ' + doubleClose + '\n' +
      '        GITHUB_EVENT_NAME: $' + doubleOpen + ' github.event_name ' + doubleClose + '\n' +
      '    \n' +
      '    - name: Scan source code with ML\n' +
      '      if: steps.check-source.outputs.source_found == \'true\'\n' +
      '      run: |\n' +
      '        python3 << \'EOF\'\n' +
      '        import json\n' +
      '        import os\n' +
      '        import sys\n' +
      '        \n' +
      '        changed_files = os.environ.get(\'CHANGED_FILES\', \'\').split()\n' +
      '        files_data = []\n' +
      '        \n' +
      '        for file_path in changed_files:\n' +
      '            if any(file_path.endswith(ext) for ext in [\'.py\', \'.java\', \'.cpp\', \'.c\']):\n' +
      '                if os.path.isfile(file_path):\n' +
      '                    with open(file_path, \'r\', encoding=\'utf-8\', errors=\'ignore\') as f:\n' +
      '                        content = f.read()\n' +
      '                    \n' +
      '                    # Determine language\n' +
      '                    if file_path.endswith(\'.py\'):\n' +
      '                        language = \'Python\'\n' +
      '                    elif file_path.endswith(\'.java\'):\n' +
      '                        language = \'Java\'\n' +
      '                    elif file_path.endswith(\'.cpp\') or file_path.endswith(\'.c\'):\n' +
      '                        language = \'C/C++\'\n' +
      '                    else:\n' +
      '                        language = \'Unknown\'\n' +
      '                    \n' +
      '                    # Count lines\n' +
      '                    lines = len(content.splitlines())\n' +
      '                    \n' +
      '                    files_data.append({\n' +
      '                        "path": file_path,\n' +
      '                        "filename": os.path.basename(file_path),\n' +
      '                        "language": language,\n' +
      '                        "content": content,\n' +
      '                        "lines_of_code": lines\n' +
      '                    })\n' +
      '        \n' +
      '        payload = {\n' +
      '            "files": files_data,\n' +
      '            "repository": os.environ.get(\'GITHUB_REPOSITORY\'),\n' +
      '            "commit_sha": os.environ.get(\'GITHUB_SHA\'),\n' +
      '            "pr_number": int(os.environ.get(\'PR_NUMBER\', \'0\')) if os.environ.get(\'PR_NUMBER\') else None,\n' +
      '            "event_type": os.environ.get(\'GITHUB_EVENT_NAME\', \'push\')\n' +
      '        }\n' +
      '        \n' +
      '        import requests\n' +
      '        api_url = os.environ.get(\'SCANNER_API_URL\')\n' +
      '        api_token = os.environ.get(\'SCANNER_API_TOKEN\', \'\')\n' +
      '        \n' +
      '        headers = {"Content-Type": "application/json"}\n' +
      '        if api_token:\n' +
      '            headers["Authorization"] = f"Bearer {api_token}"\n' +
      '        \n' +
      '        response = requests.post(\n' +
      '            f"{api_url}/github/scan-ml",\n' +
      '            json=payload,\n' +
      '            headers=headers,\n' +
      '            timeout=600\n' +
      '        )\n' +
      '        response.raise_for_status()\n' +
      '        print(response.json())\n' +
      '        EOF\n' +
      '      env:\n' +
      '        CHANGED_FILES: $' + doubleOpen + ' steps.changed-files.outputs.all_changed_files ' + doubleClose + '\n' +
      '        SCANNER_API_URL: $' + doubleOpen + ' secrets.SCANNER_API_URL ' + doubleClose + '\n' +
      '        SCANNER_API_TOKEN: $' + doubleOpen + ' secrets.SCANNER_API_TOKEN ' + doubleClose + '\n' +
      '        GITHUB_REPOSITORY: $' + doubleOpen + ' github.repository ' + doubleClose + '\n' +
      '        GITHUB_SHA: $' + doubleOpen + ' github.sha ' + doubleClose + '\n' +
      '        PR_NUMBER: $' + doubleOpen + ' github.event.pull_request.number ' + doubleClose + '\n' +
      '        GITHUB_EVENT_NAME: $' + doubleOpen + ' github.event_name ' + doubleClose + '\n'
    
    return result
  }
  
  const workflowContent = getWorkflowContent()

  const copyToClipboard = () => {
    navigator.clipboard.writeText(workflowContent)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="github-actions-page">
      <div className="page-header">
        <div className="header-logo">
          <GitHubActionsIcon />
        </div>
        <h1>GitHub Actions Integration</h1>
        <p>Automated vulnerability scanning for your GitHub repositories</p>
      </div>

      <div className="content-area">
        <div className="info-section">
          <h2>Automated Scanning</h2>
          <p>
            Set up GitHub Actions to automatically scan your code for vulnerabilities 
            on every push or pull request.
          </p>
          
          <div className="feature-list">
            <div className="feature-item">
              <strong>Dependency Scanning</strong>
              <p>Automatically scans when <code>package.json</code>, <code>requirements.txt</code>, or <code>pom.xml</code> files are changed</p>
            </div>
            <div className="feature-item">
              <strong>ML Analysis</strong>
              <p>Automatically analyzes source code when <code>.py</code>, <code>.java</code>, <code>.cpp</code>, or <code>.c</code> files are changed</p>
            </div>
            <div className="feature-item">
              <strong>Results in GitHub</strong>
              <p>Results are posted as comments on pull requests or commits</p>
            </div>
          </div>
        </div>

        <div className="setup-section">
          <h2>Setup Instructions</h2>
          
          <div className="step">
            <h3>Step 1: Create GitHub Actions Workflow</h3>
            <p>Create a workflow file in your repository:</p>
            <div className="code-block">
              <div className="code-header">
                <span>.github/workflows/vulnerability-scan.yml</span>
                <button onClick={copyToClipboard} className="copy-button">
                  {copied ? '✓ Copied!' : 'Copy'}
                </button>
              </div>
              <pre><code>{workflowContent}</code></pre>
            </div>
          </div>

          <div className="step">
            <h3>Step 2: Configure GitHub Secrets</h3>
            <p>Add the following secrets to your GitHub repository:</p>
            <div className="secrets-list">
              <div className="secret-item">
                <strong>SCANNER_API_URL</strong>
                <p>Your scanner API URL (e.g., <code>http://your-server.com:8000</code> or <code>https://api.example.com</code>)</p>
              </div>
              <div className="secret-item">
                <strong>SCANNER_API_TOKEN</strong>
                <p>API token for authentication (optional, can be empty for public APIs)</p>
              </div>
              <div className="secret-item">
                <strong>GITHUB_TOKEN</strong>
                <p>GitHub personal access token with <code>repo</code> permissions (automatically available in GitHub Actions as <code>$&#123;&#123; secrets.GITHUB_TOKEN &#125;&#125;</code>)</p>
              </div>
            </div>
            
            <div className="info-box">
              <strong>How to add secrets:</strong>
              <ol>
                <li>Go to your repository on GitHub</li>
                <li>Click <strong>Settings</strong> → <strong>Secrets and variables</strong> → <strong>Actions</strong></li>
                <li>Click <strong>New repository secret</strong></li>
                <li>Add each secret with its value</li>
              </ol>
            </div>
          </div>

          <div className="step">
            <h3>Step 3: Configure Backend</h3>
            <p>Set the <code>GITHUB_TOKEN</code> environment variable on your backend server:</p>
            <div className="code-block">
              <pre><code>export GITHUB_TOKEN=your_github_personal_access_token</code></pre>
            </div>
            <p className="note">
              The backend needs this token to post results back to GitHub.
            </p>
          </div>

          <div className="step">
            <h3>Step 4: Test the Workflow</h3>
            <p>Make a commit that changes a dependency file or source code file:</p>
            <ul>
              <li>Push to trigger the workflow</li>
              <li>Check the <strong>Actions</strong> tab in your repository</li>
              <li>View results in the pull request or commit comments</li>
            </ul>
          </div>
        </div>

        <div className="how-it-works">
          <h2>How It Works</h2>
          
          <div className="workflow-diagram">
            <div className="workflow-step">
              <div className="step-number">1</div>
              <div className="step-content">
                <strong>Push/PR Event</strong>
                <p>Developer pushes code or creates pull request</p>
              </div>
            </div>
            
            <div className="workflow-arrow">→</div>
            
            <div className="workflow-step">
              <div className="step-number">2</div>
              <div className="step-content">
                <strong>Detect Changes</strong>
                <p>GitHub Actions detects changed files</p>
              </div>
            </div>
            
            <div className="workflow-arrow">→</div>
            
            <div className="workflow-step">
              <div className="step-number">3</div>
              <div className="step-content">
                <strong>Route to Scanner</strong>
                <p>
                  Dependency files → Dependency Scanner<br/>
                  Source code files → ML Analysis
                </p>
              </div>
            </div>
            
            <div className="workflow-arrow">→</div>
            
            <div className="workflow-step">
              <div className="step-number">4</div>
              <div className="step-content">
                <strong>Post Results</strong>
                <p>Results posted as PR comment or commit comment</p>
              </div>
            </div>
          </div>
        </div>

        <div className="file-types">
          <h2>Supported File Types</h2>
          
          <div className="file-types-grid">
            <div className="file-type-card">
              <h3>Dependency Files</h3>
              <ul>
                <li><code>package.json</code> (npm/Node.js)</li>
                <li><code>requirements.txt</code> (Python/pip)</li>
                <li><code>pom.xml</code> (Java/Maven)</li>
              </ul>
              <p className="file-type-note">→ Scanned for CVEs</p>
            </div>
            
            <div className="file-type-card">
              <h3>Source Code Files</h3>
              <ul>
                <li><code>.py</code> (Python)</li>
                <li><code>.java</code> (Java)</li>
                <li><code>.cpp</code> (C++)</li>
                <li><code>.c</code> (C)</li>
              </ul>
              <p className="file-type-note">→ Analyzed with ML model</p>
            </div>
          </div>
        </div>

        <div className="example-results">
          <h2>Example Results</h2>
          
          <div className="result-example">
            <h3>Dependency Scan Results</h3>
            <div className="example-comment">
              <strong>Dependency Vulnerability Scan Results</strong>
              <ul>
                <li>Total Dependencies Scanned: 15</li>
                <li>Vulnerable Dependencies: 3</li>
                <li>Total Vulnerabilities: 8</li>
              </ul>
              <p><strong>Vulnerable Dependencies:</strong></p>
              <ul>
                <li>express v4.16.0: 2 CVE(s)</li>
                <li>lodash v4.17.15: 3 CVE(s)</li>
              </ul>
            </div>
          </div>
          
          <div className="result-example">
            <h3>ML Analysis Results</h3>
            <div className="example-comment">
              <strong>ML Vulnerability Analysis Results</strong>
              <ul>
                <li>Total Files Analyzed: 5</li>
                <li>Vulnerable Files: 2</li>
                <li>Safe Files: 3</li>
              </ul>
              <p><strong>Vulnerable Files Detected:</strong></p>
              <ul>
                <li>src/app.py - CRITICAL (Confidence: 92%)</li>
                <li>src/utils.py - HIGH (Confidence: 78%)</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default GitHubActions
