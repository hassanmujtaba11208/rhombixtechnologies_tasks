import re
from dataclasses import dataclass
from typing import List


@dataclass
class VulnerabilityFinding:
    vuln_name: str
    vuln_type: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    severity: str
    cvss_score: float
    file_name: str
    line_number: int
    code_snippet: str
    description: str
    risk_explanation: str
    remediation: str
    confidence: str = "High"


class BaseScanner:
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.split("\n")
        self.findings: List[VulnerabilityFinding] = []

    def _get_line(self, n: int) -> str:
        if 1 <= n <= len(self.lines):
            return self.lines[n - 1]
        return ""

    def scan(self) -> List[VulnerabilityFinding]:
        raise NotImplementedError


class PythonScanner(BaseScanner):
    def scan(self) -> List[VulnerabilityFinding]:
        findings = []

        # SQL Injection (very basic heuristic)
        sql_pattern = re.compile(
            r"(execute|cursor\.execute|executemany)\s*\(\s*([\"'].*%s.*[\"']|f[\"'])",
            re.IGNORECASE,
        )
        for m in sql_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Possible SQL Injection",
                    vuln_type="Injection",
                    cwe_id="CWE-89",
                    cwe_name="SQL Injection",
                    owasp_category="A03:2021 Injection",
                    severity="Critical",
                    cvss_score=9.8,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Dynamic SQL query detected with string formatting. This can lead to SQL injection.",
                    risk_explanation="User input may be concatenated into SQL queries, allowing attackers to modify queries and access/modify data.",
                    remediation="Use parameterized queries or ORM methods. Avoid string formatting in SQL statements.",
                    confidence="Medium",
                )
            )

        # Hardcoded password
        pwd_pattern = re.compile(
            r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']",
        )
        for m in pwd_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Hardcoded Password",
                    vuln_type="Hardcoded Secret",
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    severity="High",
                    cvss_score=7.5,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Hardcoded password detected in source code.",
                    risk_explanation="Credentials in code can be leaked via version control, logs, or reverse engineering.",
                    remediation="Use environment variables or a secret manager. Do not commit secrets to code.",
                    confidence="High",
                )
            )

        # Hardcoded API key
        api_key_pattern = re.compile(
            r"(?i)(api[_-]?key|apikey)\s*=\s*[\"'][^\"']+[\"']",
        )
        for m in api_key_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Hardcoded API Key",
                    vuln_type="Hardcoded Secret",
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    severity="Critical",
                    cvss_score=9.1,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Hardcoded API key detected in source code.",
                    risk_explanation="Exposed API keys can be used to access services as a legitimate user.",
                    remediation="Store API keys in environment variables or a secret manager.",
                    confidence="High",
                )
            )

        # Weak hash (md5/sha1 for passwords)
        weak_hash = re.compile(r"(?i)(md5|sha1)\s*\(")
        for m in weak_hash.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Weak Hash Function",
                    vuln_type="Weak Cryptography",
                    cwe_id="CWE-327",
                    cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                    owasp_category="A02:2021 Cryptographic Failures",
                    severity="Medium",
                    cvss_score=5.3,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Use of weak hash function (MD5/SHA1) detected.",
                    risk_explanation="These algorithms are not suitable for security-sensitive purposes.",
                    remediation="Use SHA-256/SHA-3 or dedicated password hashing (bcrypt, argon2).",
                    confidence="Medium",
                )
            )

        self.findings = findings
        return findings


class JavaScriptScanner(BaseScanner):
    def scan(self) -> List[VulnerabilityFinding]:
        findings = []

        # eval usage
        eval_pattern = re.compile(r"\beval\s*\(")
        for m in eval_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Use of eval()",
                    vuln_type="Dangerous Function",
                    cwe_id="CWE-95",
                    cwe_name="Improper Neutralization of Directives in Dynamically Evaluated Code",
                    owasp_category="A03:2021 Injection",
                    severity="High",
                    cvss_score=8.1,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Use of eval() can lead to code injection if input is not fully trusted.",
                    risk_explanation="Attackers may inject and execute arbitrary JavaScript code.",
                    remediation="Avoid eval(); use safer alternatives like JSON.parse for data.",
                    confidence="High",
                )
            )

        # innerHTML with variables (very rough)
        inner_html_pattern = re.compile(r"\.innerHTML\s*=\s*[^;]*\$\{")
        for m in inner_html_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Potential XSS via innerHTML",
                    vuln_type="Cross-Site Scripting (XSS)",
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    owasp_category="A03:2021 Injection",
                    severity="High",
                    cvss_score=7.5,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="innerHTML assignment with template literals may allow XSS.",
                    risk_explanation="Unsanitized user input rendered as HTML can execute attacker scripts.",
                    remediation="Use textContent or sanitize HTML before assigning to innerHTML.",
                    confidence="Medium",
                )
            )

        # Hardcoded secrets
        api_key_pattern = re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"'][^\"']+[\"']")
        for m in api_key_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Hardcoded API Key",
                    vuln_type="Hardcoded Secret",
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    severity="Critical",
                    cvss_score=9.1,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Hardcoded API key detected in JavaScript code.",
                    risk_explanation="Client-side secrets can be extracted by anyone viewing the code.",
                    remediation="Do not store secrets in client-side code. Use server-side APIs.",
                    confidence="High",
                )
            )

        self.findings = findings
        return findings


class PHPSanner(BaseScanner):
    def scan(self) -> List[VulnerabilityFinding]:
        findings = []

        # SQL injection (mysql_query / mysqli_query with variables)
        sql_pattern = re.compile(
            r"(mysql_query|mysqli_query)\s*\(\s*[^,]*\$",
            re.IGNORECASE,
        )
        for m in sql_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Possible SQL Injection",
                    vuln_type="Injection",
                    cwe_id="CWE-89",
                    cwe_name="SQL Injection",
                    owasp_category="A03:2021 Injection",
                    severity="Critical",
                    cvss_score=9.8,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Dynamic SQL query with variables detected. May be vulnerable to SQL injection.",
                    risk_explanation="Unsanitized input can alter SQL queries and compromise the database.",
                    remediation="Use prepared statements (PDO, mysqli prepared statements).",
                    confidence="Medium",
                )
            )

        # Hardcoded password
        pwd_pattern = re.compile(r"(?i)(\$password|\$passwd|\$pwd)\s*=\s*[\"'][^\"']+[\"']")
        for m in pwd_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Hardcoded Password",
                    vuln_type="Hardcoded Secret",
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    severity="High",
                    cvss_score=7.5,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Hardcoded password detected in PHP code.",
                    risk_explanation="Credentials in code can be leaked via version control or deployment.",
                    remediation="Use environment variables or secure config files outside code.",
                    confidence="High",
                )
            )

        self.findings = findings
        return findings


class HTMLScanner(BaseScanner):
    def scan(self) -> List[VulnerabilityFinding]:
        findings = []

        # Inline event handlers (very rough)
        handler_pattern = re.compile(r"\s(on\w+)\s*=\s*[\"'][^\"']*[\"']")
        for m in handler_pattern.finditer(self.content):
            line_no = self.content[: m.start()].count("\n") + 1
            findings.append(
                VulnerabilityFinding(
                    vuln_name="Inline Event Handler",
                    vuln_type="Potential XSS Vector",
                    cwe_id="CWE-79",
                    cwe_name="Improper Neutralization of Input During Web Page Generation",
                    owasp_category="A03:2021 Injection",
                    severity="Low",
                    cvss_score=3.7,
                    file_name=self.file_path,
                    line_number=line_no,
                    code_snippet=self._get_line(line_no),
                    description="Inline event handler detected (e.g., onclick). Can be an XSS vector if combined with dynamic content.",
                    risk_explanation="If attributes are populated with unsanitized data, attackers may inject scripts.",
                    remediation="Prefer external JS and event listeners; sanitize any dynamic content.",
                    confidence="Low",
                )
            )

        self.findings = findings
        return findings


def get_scanner_for_file(file_path: str, content: str):
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    if ext == "py":
        return PythonScanner(file_path, content)
    elif ext in ("js", "jsx", "ts", "tsx"):
        return JavaScriptScanner(file_path, content)
    elif ext == "php":
        return PHPSanner(file_path, content)
    elif ext in ("html", "htm"):
        return HTMLScanner(file_path, content)
    else:
        # Fallback: minimal generic scanner
        return BaseScanner(file_path, content)