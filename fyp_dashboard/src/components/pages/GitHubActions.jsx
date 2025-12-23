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
    
    // Read the workflow file content directly
    // Since we can't read files in React, we'll construct it from the uploaded YAML
    const result = 'name: Automated Vulnerability Scan\n\n' +
      'on:\n' +
      '  push:\n' +
      '  pull_request:\n\n' +
      'jobs:\n' +
      '  scan:\n' +
      '    runs-on: ubuntu-latest\n' +
      '    \n' +
      '    steps:\n' +
      '    - name: Checkout code\n' +
      '      uses: actions/checkout@v4\n' +
      '      with:\n' +
      '        fetch-depth: 0  # Fetch full history for diff\n' +
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
      '    - name: Install Python dependencies\n' +
      '      if: steps.check-deps.outputs.deps_found == \'true\' || steps.check-source.outputs.source_found == \'true\'\n' +
      '      run: |\n' +
      '        pip install requests --quiet\n' +
      '    \n' +
      '    - name: Scan dependencies\n' +
      '      if: steps.check-deps.outputs.deps_found == \'true\'\n' +
      '      id: scan-deps\n' +
      '      run: |\n' +
      '        # Collect dependency files and create JSON\n' +
      '        python3 << \'EOF\'\n' +
      '        import json\n' +
      '        import os\n' +
      '        import sys\n' +
      '        \n' +
      '        # Get changed files from environment (space-separated)\n' +
      '        changed_files_str = os.environ.get(\'CHANGED_FILES\', \'\')\n' +
      '        changed_files = changed_files_str.split() if changed_files_str else []\n' +
      '        \n' +
      '        files_data = []\n' +
      '        \n' +
      '        for file_path in changed_files:\n' +
      '            if any(file_path.endswith(ext) for ext in [\'package.json\', \'requirements.txt\', \'pom.xml\']):\n' +
      '                if os.path.isfile(file_path):\n' +
      '                    try:\n' +
      '                        with open(file_path, \'r\', encoding=\'utf-8\') as f:\n' +
      '                            content = f.read()\n' +
      '                        files_data.append({\n' +
      '                            "path": file_path,\n' +
      '                            "content": content\n' +
      '                        })\n' +
      '                    except Exception as e:\n' +
      '                        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)\n' +
      '        \n' +
      '        if not files_data:\n' +
      '            print("No dependency files found to scan", file=sys.stderr)\n' +
      '            sys.exit(0)\n' +
      '        \n' +
      '        # Handle PR number - only set if it\'s a pull request event\n' +
      '        pr_number = None\n' +
      '        pr_number_str = os.environ.get(\'PR_NUMBER\', \'\')\n' +
      '        if pr_number_str and pr_number_str.strip() and pr_number_str.strip() != \'null\':\n' +
      '            try:\n' +
      '                pr_number = int(pr_number_str)\n' +
      '            except ValueError:\n' +
      '                pr_number = None\n' +
      '        \n' +
      '        payload = {\n' +
      '            "files": files_data,\n' +
      '            "repository": os.environ.get(\'GITHUB_REPOSITORY\'),\n' +
      '            "commit_sha": os.environ.get(\'GITHUB_SHA\'),\n' +
      '            "pr_number": pr_number,\n' +
      '            "event_type": os.environ.get(\'GITHUB_EVENT_NAME\', \'push\')\n' +
      '        }\n' +
      '        \n' +
      '        import requests\n' +
      '        api_url = os.environ.get(\'SCANNER_API_URL\')\n' +
      '        api_token = os.environ.get(\'SCANNER_API_TOKEN\', \'\')\n' +
      '        \n' +
      '        if not api_url:\n' +
      '            print("Error: SCANNER_API_URL secret is not set", file=sys.stderr)\n' +
      '            sys.exit(1)\n' +
      '        \n' +
      '        # Strip trailing slash from API URL to avoid double slashes\n' +
      '        api_url = api_url.rstrip(\'/\')\n' +
      '        \n' +
      '        headers = {"Content-Type": "application/json"}\n' +
      '        if api_token:\n' +
      '            headers["Authorization"] = f"Bearer {api_token}"\n' +
      '        \n' +
      '        # Verify API is accessible with health check\n' +
      '        try:\n' +
      '            health_response = requests.get(f"{api_url}/health", timeout=10)\n' +
      '            health_response.raise_for_status()\n' +
      '            print(f"✅ API health check passed: {health_response.json()}", file=sys.stderr)\n' +
      '        except Exception as e:\n' +
      '            print(f"⚠️  API health check failed: {e}", file=sys.stderr)\n' +
      '            print(f"   API URL: {api_url}", file=sys.stderr)\n' +
      '            print(f"   This might indicate the API is not deployed or URL is incorrect", file=sys.stderr)\n' +
      '        \n' +
      '        # Debug: Print the URL being called\n' +
      '        endpoint_url = f"{api_url}/github/scan-dependencies"\n' +
      '        print(f"Calling API endpoint: {endpoint_url}", file=sys.stderr)\n' +
      '        \n' +
      '        try:\n' +
      '            response = requests.post(\n' +
      '                endpoint_url,\n' +
      '                json=payload,\n' +
      '                headers=headers,\n' +
      '                timeout=600\n' +
      '            )\n' +
      '            response.raise_for_status()\n' +
      '            result = response.json()\n' +
      '            print(json.dumps(result, indent=2))\n' +
      '            # Save result to file for summary\n' +
      '            with open(\'/tmp/deps_scan_result.json\', \'w\') as f:\n' +
      '                json.dump(result, f, indent=2)\n' +
      '        except requests.exceptions.RequestException as e:\n' +
      '            print(f"Error calling scanner API: {e}", file=sys.stderr)\n' +
      '            if hasattr(e, \'response\') and e.response is not None:\n' +
      '                print(f"Response: {e.response.text}", file=sys.stderr)\n' +
      '            sys.exit(1)\n' +
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
      '      id: scan-ml\n' +
      '      run: |\n' +
      '        # Collect source code files and create JSON\n' +
      '        python3 << \'EOF\'\n' +
      '        import json\n' +
      '        import os\n' +
      '        import sys\n' +
      '        \n' +
      '        # Get changed files from environment (space-separated)\n' +
      '        changed_files_str = os.environ.get(\'CHANGED_FILES\', \'\')\n' +
      '        changed_files = changed_files_str.split() if changed_files_str else []\n' +
      '        \n' +
      '        files_data = []\n' +
      '        \n' +
      '        for file_path in changed_files:\n' +
      '            if any(file_path.endswith(ext) for ext in [\'.py\', \'.java\', \'.cpp\', \'.c\']):\n' +
      '                if os.path.isfile(file_path):\n' +
      '                    try:\n' +
      '                        with open(file_path, \'r\', encoding=\'utf-8\', errors=\'ignore\') as f:\n' +
      '                            content = f.read()\n' +
      '                        \n' +
      '                        # Determine language\n' +
      '                        if file_path.endswith(\'.py\'):\n' +
      '                            language = \'Python\'\n' +
      '                        elif file_path.endswith(\'.java\'):\n' +
      '                            language = \'Java\'\n' +
      '                        elif file_path.endswith(\'.cpp\') or file_path.endswith(\'.c\'):\n' +
      '                            language = \'C/C++\'\n' +
      '                        else:\n' +
      '                            language = \'Unknown\'\n' +
      '                        \n' +
      '                        # Count lines\n' +
      '                        lines = len(content.splitlines())\n' +
      '                        \n' +
      '                        files_data.append({\n' +
      '                            "path": file_path,\n' +
      '                            "filename": os.path.basename(file_path),\n' +
      '                            "language": language,\n' +
      '                            "content": content,\n' +
      '                            "lines_of_code": lines\n' +
      '                        })\n' +
      '                    except Exception as e:\n' +
      '                        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)\n' +
      '        \n' +
      '        if not files_data:\n' +
      '            print("No source code files found to scan", file=sys.stderr)\n' +
      '            sys.exit(0)\n' +
      '        \n' +
      '        # Handle PR number - only set if it\'s a pull request event\n' +
      '        pr_number = None\n' +
      '        pr_number_str = os.environ.get(\'PR_NUMBER\', \'\')\n' +
      '        if pr_number_str and pr_number_str.strip() and pr_number_str.strip() != \'null\':\n' +
      '            try:\n' +
      '                pr_number = int(pr_number_str)\n' +
      '            except ValueError:\n' +
      '                pr_number = None\n' +
      '        \n' +
      '        payload = {\n' +
      '            "files": files_data,\n' +
      '            "repository": os.environ.get(\'GITHUB_REPOSITORY\'),\n' +
      '            "commit_sha": os.environ.get(\'GITHUB_SHA\'),\n' +
      '            "pr_number": pr_number,\n' +
      '            "event_type": os.environ.get(\'GITHUB_EVENT_NAME\', \'push\')\n' +
      '        }\n' +
      '        \n' +
      '        import requests\n' +
      '        api_url = os.environ.get(\'SCANNER_API_URL\')\n' +
      '        api_token = os.environ.get(\'SCANNER_API_TOKEN\', \'\')\n' +
      '        \n' +
      '        if not api_url:\n' +
      '            print("Error: SCANNER_API_URL secret is not set", file=sys.stderr)\n' +
      '            sys.exit(1)\n' +
      '        \n' +
      '        # Strip trailing slash from API URL to avoid double slashes\n' +
      '        api_url = api_url.rstrip(\'/\')\n' +
      '        \n' +
      '        headers = {"Content-Type": "application/json"}\n' +
      '        if api_token:\n' +
      '            headers["Authorization"] = f"Bearer {api_token}"\n' +
      '        \n' +
      '        # Verify API is accessible with health check\n' +
      '        try:\n' +
      '            health_response = requests.get(f"{api_url}/health", timeout=10)\n' +
      '            health_response.raise_for_status()\n' +
      '            print(f"✅ API health check passed: {health_response.json()}", file=sys.stderr)\n' +
      '        except Exception as e:\n' +
      '            print(f"⚠️  API health check failed: {e}", file=sys.stderr)\n' +
      '            print(f"   API URL: {api_url}", file=sys.stderr)\n' +
      '            print(f"   This might indicate the API is not deployed or URL is incorrect", file=sys.stderr)\n' +
      '        \n' +
      '        # Debug: Print the URL being called\n' +
      '        endpoint_url = f"{api_url}/github/scan-ml"\n' +
      '        print(f"Calling API endpoint: {endpoint_url}", file=sys.stderr)\n' +
      '        \n' +
      '        try:\n' +
      '            response = requests.post(\n' +
      '                endpoint_url,\n' +
      '                json=payload,\n' +
      '                headers=headers,\n' +
      '                timeout=600\n' +
      '            )\n' +
      '            response.raise_for_status()\n' +
      '            result = response.json()\n' +
      '            print(json.dumps(result, indent=2))\n' +
      '            # Save result to file for summary\n' +
      '            with open(\'/tmp/ml_scan_result.json\', \'w\') as f:\n' +
      '                json.dump(result, f, indent=2)\n' +
      '        except requests.exceptions.RequestException as e:\n' +
      '            print(f"Error calling ML scanner API: {e}", file=sys.stderr)\n' +
      '            if hasattr(e, \'response\') and e.response is not None:\n' +
      '                print(f"Response: {e.response.text}", file=sys.stderr)\n' +
      '            sys.exit(1)\n' +
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
      '    - name: Display Scan Summary\n' +
      '      if: always() && (steps.check-deps.outputs.deps_found == \'true\' || steps.check-source.outputs.source_found == \'true\')\n' +
      '      run: |\n' +
      '        python3 << \'EOF\'\n' +
      '        import json\n' +
      '        import os\n' +
      '        import sys\n' +
      '        \n' +
      '        summary_lines = []\n' +
      '        summary_lines.append("# 🔍 Vulnerability Scan Summary")\n' +
      '        summary_lines.append("")\n' +
      '        summary_lines.append(f"**Repository:** {os.environ.get(\'GITHUB_REPOSITORY\', \'N/A\')}")\n' +
      '        summary_lines.append(f"**Branch:** {os.environ.get(\'GITHUB_REF_NAME\', \'N/A\')}")\n' +
      '        summary_lines.append(f"**Commit:** {os.environ.get(\'GITHUB_SHA\', \'N/A\')[:7]}")\n' +
      '        summary_lines.append(f"**Event:** {os.environ.get(\'GITHUB_EVENT_NAME\', \'N/A\')}")\n' +
      '        summary_lines.append("")\n' +
      '        summary_lines.append("---")\n' +
      '        summary_lines.append("")\n' +
      '        \n' +
      '        # Dependency Scan Results\n' +
      '        deps_scan_file = \'/tmp/deps_scan_result.json\'\n' +
      '        if os.path.exists(deps_scan_file):\n' +
      '            summary_lines.append("## 📦 Dependency Scan Results")\n' +
      '            summary_lines.append("")\n' +
      '            try:\n' +
      '                with open(deps_scan_file, \'r\') as f:\n' +
      '                    deps_result = json.load(f)\n' +
      '                \n' +
      '                if isinstance(deps_result, dict):\n' +
      '                    # Get summary stats\n' +
      '                    summary = deps_result.get(\'summary\', {})\n' +
      '                    total_vulns = summary.get(\'total_vulnerabilities\', 0)\n' +
      '                    vuln_by_severity = summary.get(\'vulnerabilities_by_severity\', {})\n' +
      '                    \n' +
      '                    summary_lines.append(f"**Status:** ✅ Scan Completed")\n' +
      '                    summary_lines.append(f"**Dependencies Scanned:** {summary.get(\'total_deps_scanned\', 0)}")\n' +
      '                    summary_lines.append(f"**Dependencies with Vulnerabilities:** {summary.get(\'deps_with_vulnerabilities\', 0)}")\n' +
      '                    summary_lines.append(f"**Total Vulnerabilities:** {total_vulns}")\n' +
      '                    summary_lines.append("")\n' +
      '                    \n' +
      '                    if total_vulns > 0:\n' +
      '                        # Show severity breakdown\n' +
      '                        if vuln_by_severity:\n' +
      '                            summary_lines.append("**Severity Breakdown:**")\n' +
      '                            if vuln_by_severity.get(\'critical\', 0) > 0:\n' +
      '                                summary_lines.append(f"- 🔴 Critical: {vuln_by_severity[\'critical\']}")\n' +
      '                            if vuln_by_severity.get(\'high\', 0) > 0:\n' +
      '                                summary_lines.append(f"- 🟠 High: {vuln_by_severity[\'high\']}")\n' +
      '                            if vuln_by_severity.get(\'medium\', 0) > 0:\n' +
      '                                summary_lines.append(f"- 🟡 Medium: {vuln_by_severity[\'medium\']}")\n' +
      '                            if vuln_by_severity.get(\'low\', 0) > 0:\n' +
      '                                summary_lines.append(f"- 🟢 Low: {vuln_by_severity[\'low\']}")\n' +
      '                            summary_lines.append("")\n' +
      '                        \n' +
      '                        # List vulnerabilities from dependencies only (ignore duplicate root vulnerabilities array)\n' +
      '                        summary_lines.append("### Affected Dependencies:")\n' +
      '                        summary_lines.append("")\n' +
      '                        \n' +
      '                        dependencies = deps_result.get(\'dependencies\', [])\n' +
      '                        vuln_count = 0\n' +
      '                        \n' +
      '                        # Severity ordering for sorting (highest to lowest)\n' +
      '                        severity_order = {\'CRITICAL\': 0, \'HIGH\': 1, \'MEDIUM\': 2, \'LOW\': 3, \'UNKNOWN\': 4}\n' +
      '                        \n' +
      '                        def get_severity_rank(cve):\n' +
      '                            """Get severity rank for sorting (lower number = higher severity)"""\n' +
      '                            severity = cve.get(\'severity\', \'Unknown\').upper()\n' +
      '                            return severity_order.get(severity, 4)\n' +
      '                        \n' +
      '                        for dep in dependencies:\n' +
      '                            if isinstance(dep, dict):\n' +
      '                                cves = dep.get(\'cves\', [])\n' +
      '                                if cves:\n' +
      '                                    pkg_name = dep.get(\'name\', \'Unknown\')\n' +
      '                                    pkg_version = dep.get(\'version\', \'Unknown\')\n' +
      '                                    summary_lines.append(f"#### {pkg_name} ({pkg_version})")\n' +
      '                                    \n' +
      '                                    # Sort CVEs by severity (highest to lowest)\n' +
      '                                    sorted_cves = sorted(cves, key=get_severity_rank)\n' +
      '                                    \n' +
      '                                    for cve in sorted_cves[:5]:  # Show first 5 CVEs per package (sorted by severity)\n' +
      '                                        vuln_count += 1\n' +
      '                                        if vuln_count > 15:  # Stop after 15 total\n' +
      '                                            break\n' +
      '                                        \n' +
      '                                        cve_id = cve.get(\'cve_id\', \'N/A\')\n' +
      '                                        severity = cve.get(\'severity\', \'Unknown\').upper()\n' +
      '                                        cvss = cve.get(\'cvss_score\', \'N/A\')\n' +
      '                                        cwe = cve.get(\'cwe\', \'N/A\')\n' +
      '                                        cisa_kev = cve.get(\'cisa_kev\', \'No\')\n' +
      '                                        url = cve.get(\'url\', \'\')\n' +
      '                                        \n' +
      '                                        severity_emoji = {\n' +
      '                                            \'CRITICAL\': \'🔴\',\n' +
      '                                            \'HIGH\': \'🟠\',\n' +
      '                                            \'MEDIUM\': \'🟡\',\n' +
      '                                            \'LOW\': \'🟢\'\n' +
      '                                        }.get(severity, \'⚪\')\n' +
      '                                        \n' +
      '                                        # CISA KEV badge\n' +
      '                                        kev_badge = \' ⚠️ **CISA KEV**\' if cisa_kev == \'Yes\' else \'\'\n' +
      '                                        \n' +
      '                                        # Build CVE line with link\n' +
      '                                        cve_link = f"[{cve_id}]({url})" if url else cve_id\n' +
      '                                        summary_lines.append(f"- {severity_emoji} **{cve_link}**{kev_badge}")\n' +
      '                                        summary_lines.append(f"  - **Severity:** {severity} | **CVSS:** {cvss}")\n' +
      '                                        summary_lines.append(f"  - **CWE:** {cwe}")\n' +
      '                                    \n' +
      '                                    if len(sorted_cves) > 5:\n' +
      '                                        summary_lines.append(f"  *... and {len(sorted_cves) - 5} more CVEs*")\n' +
      '                                    summary_lines.append("")\n' +
      '                            \n' +
      '                            if vuln_count > 15:\n' +
      '                                remaining = total_vulns - vuln_count\n' +
      '                                if remaining > 0:\n' +
      '                                    summary_lines.append(f"*... and {remaining} more vulnerabilities. See full results below.*")\n' +
      '                                break\n' +
      '                    else:\n' +
      '                        summary_lines.append("✅ No vulnerabilities detected in dependencies!")\n' +
      '                    \n' +
      '                    # Show full JSON in collapsible section\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("<details>")\n' +
      '                    summary_lines.append("<summary>View Full Dependency Scan Results</summary>")\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("```json")\n' +
      '                    summary_lines.append(json.dumps(deps_result, indent=2))\n' +
      '                    summary_lines.append("```")\n' +
      '                    summary_lines.append("</details>")\n' +
      '                else:\n' +
      '                    summary_lines.append(f"**Status:** ✅ Scan Completed")\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("```json")\n' +
      '                    summary_lines.append(json.dumps(deps_result, indent=2))\n' +
      '                    summary_lines.append("```")\n' +
      '            except Exception as e:\n' +
      '                summary_lines.append(f"**Status:** ⚠️ Error reading results")\n' +
      '                summary_lines.append(f"**Error:** {str(e)}")\n' +
      '        else:\n' +
      '            summary_lines.append("## 📦 Dependency Scan Results")\n' +
      '            summary_lines.append("")\n' +
      '            summary_lines.append("ℹ️ No dependency files were scanned")\n' +
      '        \n' +
      '        summary_lines.append("")\n' +
      '        summary_lines.append("---")\n' +
      '        summary_lines.append("")\n' +
      '        \n' +
      '        # ML Source Code Scan Results\n' +
      '        ml_scan_file = \'/tmp/ml_scan_result.json\'\n' +
      '        if os.path.exists(ml_scan_file):\n' +
      '            summary_lines.append("## 🤖 ML Source Code Scan Results")\n' +
      '            summary_lines.append("")\n' +
      '            try:\n' +
      '                with open(ml_scan_file, \'r\') as f:\n' +
      '                    ml_result = json.load(f)\n' +
      '                \n' +
      '                if isinstance(ml_result, dict):\n' +
      '                    # Extract key information from predictions array\n' +
      '                    predictions = ml_result.get(\'predictions\', [])\n' +
      '                    summary = ml_result.get(\'summary\', {})\n' +
      '                    \n' +
      '                    # Filter for vulnerable files only\n' +
      '                    vulnerable_predictions = [\n' +
      '                        p for p in predictions \n' +
      '                        if isinstance(p, dict) and p.get(\'success\') and p.get(\'prediction\') == \'VULNERABLE\'\n' +
      '                    ]\n' +
      '                    \n' +
      '                    total_files = summary.get(\'total_files\', 0)\n' +
      '                    vulnerable_files = summary.get(\'vulnerable_files\', len(vulnerable_predictions))\n' +
      '                    safe_files = summary.get(\'safe_files\', 0)\n' +
      '                    failed_files = summary.get(\'failed_files\', 0)\n' +
      '                    analysis_time = summary.get(\'analysis_time_seconds\', 0)\n' +
      '                    \n' +
      '                    summary_lines.append(f"**Status:** ✅ Scan Completed")\n' +
      '                    summary_lines.append(f"**Total Files Analyzed:** {total_files}")\n' +
      '                    summary_lines.append(f"**Vulnerable Files:** {vulnerable_files}")\n' +
      '                    summary_lines.append(f"**Safe Files:** {safe_files}")\n' +
      '                    if failed_files > 0:\n' +
      '                        summary_lines.append(f"**Failed Files:** {failed_files}")\n' +
      '                    summary_lines.append(f"**Analysis Time:** {analysis_time}s")\n' +
      '                    summary_lines.append("")\n' +
      '                    \n' +
      '                    if vulnerable_files > 0:\n' +
      '                        summary_lines.append("### ⚠️ Vulnerable Files Detected:")\n' +
      '                        summary_lines.append("")\n' +
      '                        for i, pred in enumerate(vulnerable_predictions[:10], 1):  # Show first 10\n' +
      '                            file_path = pred.get(\'file_path\', pred.get(\'filename\', \'Unknown\'))\n' +
      '                            filename = pred.get(\'filename\', \'Unknown\')\n' +
      '                            risk_level = pred.get(\'risk_level\', \'Unknown\')\n' +
      '                            confidence = pred.get(\'confidence\', 0)\n' +
      '                            confidence_pct = int(confidence * 100) if confidence else 0\n' +
      '                            language = pred.get(\'language\', \'Unknown\')\n' +
      '                            \n' +
      '                            risk_emoji = {\n' +
      '                                \'CRITICAL\': \'🔴\',\n' +
      '                                \'HIGH\': \'🟠\',\n' +
      '                                \'MEDIUM\': \'🟡\',\n' +
      '                                \'LOW\': \'🟢\'\n' +
      '                            }.get(risk_level, \'⚪\')\n' +
      '                            \n' +
      '                            summary_lines.append(f"{i}. {risk_emoji} **{file_path}**")\n' +
      '                            summary_lines.append(f"   - **Risk Level:** {risk_level} | **Confidence:** {confidence_pct}% | **Language:** {language}")\n' +
      '                        \n' +
      '                        if vulnerable_files > 10:\n' +
      '                            summary_lines.append(f"\\n*... and {vulnerable_files - 10} more vulnerable files*")\n' +
      '                    else:\n' +
      '                        summary_lines.append("✅ No security issues detected in source code!")\n' +
      '                    \n' +
      '                    # Show full JSON in collapsible section\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("<details>")\n' +
      '                    summary_lines.append("<summary>View Full ML Scan Results</summary>")\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("```json")\n' +
      '                    summary_lines.append(json.dumps(ml_result, indent=2))\n' +
      '                    summary_lines.append("```")\n' +
      '                    summary_lines.append("</details>")\n' +
      '                else:\n' +
      '                    summary_lines.append(f"**Status:** ✅ Scan Completed")\n' +
      '                    summary_lines.append("")\n' +
      '                    summary_lines.append("```json")\n' +
      '                    summary_lines.append(json.dumps(ml_result, indent=2))\n' +
      '                    summary_lines.append("```")\n' +
      '            except Exception as e:\n' +
      '                summary_lines.append(f"**Status:** ⚠️ Error reading results")\n' +
      '                summary_lines.append(f"**Error:** {str(e)}")\n' +
      '        else:\n' +
      '            summary_lines.append("## 🤖 ML Source Code Scan Results")\n' +
      '            summary_lines.append("")\n' +
      '            summary_lines.append("ℹ️ No source code files were scanned")\n' +
      '        \n' +
      '        summary_lines.append("")\n' +
      '        summary_lines.append("---")\n' +
      '        summary_lines.append("")\n' +
      '        \n' +
      '        # Write summary to both stdout and file\n' +
      '        summary_text = "\\n".join(summary_lines)\n' +
      '        print(summary_text)\n' +
      '        \n' +
      '        # Write to GitHub Actions summary\n' +
      '        summary_file = os.environ.get(\'GITHUB_STEP_SUMMARY\', \'/dev/null\')\n' +
      '        try:\n' +
      '            with open(summary_file, \'w\') as f:\n' +
      '                f.write(summary_text)\n' +
      '        except Exception:\n' +
      '            pass  # Ignore if file doesn\'t exist\n' +
      '        EOF\n' +
      '      env:\n' +
      '        GITHUB_REPOSITORY: $' + doubleOpen + ' github.repository ' + doubleClose + '\n' +
      '        GITHUB_REF_NAME: $' + doubleOpen + ' github.ref_name ' + doubleClose + '\n' +
      '        GITHUB_SHA: $' + doubleOpen + ' github.sha ' + doubleClose + '\n' +
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
              <p>Results are posted as comments on pull requests or commits, and displayed in the GitHub Actions summary</p>
            </div>
            <div className="feature-item">
              <strong>Health Checks</strong>
              <p>Automatic API health verification before scanning to ensure the service is available</p>
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
            <h3>Step 3: Test the Workflow</h3>
            <p>Make a commit that changes a dependency file or source code file:</p>
            <ul>
              <li>Push to any branch or create a pull request to trigger the workflow</li>
              <li>Check the <strong>Actions</strong> tab in your repository</li>
              <li>View the scan summary in the workflow run summary</li>
            </ul>
            <p className="note">
              <strong>Note:</strong> The workflow triggers on all push and pull request events (no branch restrictions).
            </p>
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
                <p>Results posted as PR comment, commit comment, and GitHub Actions summary</p>
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
            <h3>Vulnerability Scan Summary</h3>
            <div className="example-comment">
              <h4>🔍 Vulnerability Scan Summary</h4>
              <p></p>
              <p><strong>Repository:</strong> owner/repo-name</p>
              <p><strong>Branch:</strong> test/workflow-test</p>
              <p><strong>Commit:</strong> abc1234</p>
              <p><strong>Event:</strong> pull_request</p>
              <p></p>
              <hr style={{ border: 'none', borderTop: '1px solid rgba(255, 255, 255, 0.1)', margin: '16px 0' }} />
              <p></p>
              <h4>📦 Dependency Scan Results</h4>
              <p></p>
              <p><strong>Status:</strong> ✅ Scan Completed</p>
              <p><strong>Dependencies Scanned:</strong> 8</p>
              <p><strong>Dependencies with Vulnerabilities:</strong> 1</p>
              <p><strong>Total Vulnerabilities:</strong> 6</p>
              <p></p>
              <p><strong>Severity Breakdown:</strong></p>
              <ul style={{ listStyleType: 'none', paddingLeft: '0' }}>
                <li>• 🔴 Critical: 0</li>
                <li>• 🟠 High: 3</li>
                <li>• 🟡 Medium: 2</li>
                <li>• 🟢 Low: 1</li>
              </ul>
              <p></p>
              <p><strong>Affected Dependencies:</strong></p>
              <p></p>
              <h5>transformers (4.47.0)</h5>
              <p></p>
              <ul style={{ listStyleType: 'none', paddingLeft: '0' }}>
                <li>• 🟠 <strong>CVE-2024-11392</strong></li>
                <li>&nbsp;&nbsp;&nbsp;&nbsp;Severity: HIGH | CVSS: 8.8</li>
                <li>&nbsp;&nbsp;&nbsp;&nbsp;CWE: CWE-502</li>
              </ul>
              <p></p>
              <details>
                <summary style={{ cursor: 'pointer', color: 'var(--accent-primary)' }}>View Full Dependency Scan Results ▼</summary>
              </details>
              <p></p>
              <hr style={{ border: 'none', borderTop: '1px solid rgba(255, 255, 255, 0.1)', margin: '16px 0' }} />
              <p></p>
              <h4>🤖 ML Source Code Scan Results</h4>
              <p></p>
              <p><strong>Status:</strong> ✅ Scan Completed</p>
              <p><strong>Total Files Analyzed:</strong> 5</p>
              <p><strong>Vulnerable Files:</strong> 2</p>
              <p><strong>Safe Files:</strong> 3</p>
              <p><strong>Analysis Time:</strong> 12.5s</p>
              <p></p>
              <p><strong>⚠️ Vulnerable Files Detected:</strong></p>
              <p></p>
              <ol>
                <li>🔴 <strong>backend/api.py</strong></li>
                <li>&nbsp;&nbsp;&nbsp;&nbsp;Risk Level: CRITICAL | Confidence: 92%</li>
                <li></li>
                <li>🟠 <strong>src/utils.py</strong></li>
                <li>&nbsp;&nbsp;&nbsp;&nbsp;Risk Level: HIGH | Confidence: 78%</li>
              </ol>
              <p></p>
              <details>
                <summary style={{ cursor: 'pointer', color: 'var(--accent-primary)' }}>View Full ML Scan Results ▼</summary>
              </details>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default GitHubActions
