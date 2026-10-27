# Nector

Nector is a Intermidate AI-powered vulnerability tester for websites and web applications.

Just enter a website URL, start a scan, and get a clear security report showing possible vulnerabilities, how serious they are, and what you can do to fix them.

**Please scan responsibly.** Only use Nector on websites you own or have permission to test.

## What Nector Does

- Scans a website from a single URL
- Checks for common web vulnerabilities
- Reviews security headers and HTTPS setup
- Looks for exposed files, admin panels, and common misconfigurations
- Uses AI to explain findings in simple, non-technical language
- Shows a security score and sorts issues by severity
- Lets you download the full scan report

## Tech Stack

| Part | Technology |
|---|---|
| Frontend | Type script / Next.js |
| Backend | Python  |
| Scanning | OWASP ZAP, Nuclei |
| AI | GEMINI API |
| Database | MONGO DB |

Nector uses Nuclei, a fast and customizable vulnerability scanner that uses templates to detect known security issues.

## 🔍 How It Works

1. You enter the website URL you want to test.
2. Nector runs a scan using OWASP ZAP and Nuclei.
3. The scanners collect raw security findings.
4. GLM Flash reviews the findings and explains them clearly.
5. You get a simple dashboard report with severity levels and fixes.

```text
Website URL → Security Scanners → Raw Findings → AI Explanation → Easy Report
```


## 🧪 Testing Safely

Use Nector only on:

- Websites you own
- Local practice apps such as DVWA, OWASP WebGoat, or Juice Shop
- Websites where you have clear written permission to test

Never scan a website without permission. Active security testing can disrupt a website and may be illegal.