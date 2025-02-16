# Email Spoofing Demonstration Tool  

## 🚀 Overview  
This project is a **comprehensive email spoofing simulation tool** designed strictly for **educational, security testing, and controlled environments**. The tool provides various functionalities to analyze domain vulnerabilities, generate spoofed emails, and test email security defenses.  

## 🔥 Features  
- ✅ **Email Spoofing Simulation** – Send crafted emails to test domain security policies.  
- ✅ **DMARC, SPF & DKIM Analysis** – Verify domain security settings to check for spoofing vulnerabilities.  
- ✅ **AI-Generated HTML Emails** – Generate realistic phishing-like emails using OpenAI's API for controlled testing.  
- ✅ **Manual & Automated Email Editing** – Modify generated emails using an inline editor or regenerate them dynamically.  
- ✅ **Custom Headers & Reply-To Manipulation** – Personalize email headers and manage responses.  
- ✅ **Bulk Email Testing (Batch Mode)** – Scan multiple domains and send emails concurrently.  
- ✅ **Real-Time Progress Bar** – Get live feedback during domain scans.  
- ✅ **Security Awareness Training** – Use as a phishing simulation tool for user training.  

## ⚙️ Installation  
```bash
git clone https://github.com/yourusername/email-spoofing-tool.git
cd email-spoofing-tool
pip install -r requirements.txt
🚀 Usage
Run the tool:

bash
Copiar
python main.py
Main Menu Options:

Single Domain Analysis:
Analyze DMARC/SPF/DKIM for one domain.
Optionally send a spoofed email if the domain is found vulnerable.
Batch Mode (Concurrent Scanning):
Analyze multiple domains (listed in a file) concurrently.
Optionally send spoofed emails in bulk to all vulnerable domains.
About:
Displays information about the tool, its purpose, and authorship.
Exit:
Quit the program.
SMTP Configuration:

You need an SMTP server to send emails. If you don’t have one, you can use a service like Brevo to obtain SMTP credentials (host, port, username, and password).
When prompted by the tool, enter the SMTP details accordingly.
Sending Spoofed Emails:

Email Generation:
Manual (Option 1): Write the HTML body of the email directly.
AI (Option 2): Provide a prompt to generate a phishing-like HTML email using OpenAI.
Attachments & Headers:
Attach files from local disk or via URL.
Set additional headers (like Reply-To) or add a custom signature (X-Hacked-By).
Reporting:

After scanning (single or batch), an HTML report (spoofing_report.html) is generated, summarizing domain vulnerabilities and their DMARC/SPF/DKIM status.
⚠️ Disclaimer
This tool is intended ONLY for legal penetration testing, cybersecurity research, and educational purposes in controlled environments. Unauthorized use is strictly prohibited.
Always ensure you have explicit permission before conducting any security tests.

