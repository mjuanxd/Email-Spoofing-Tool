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
```

## 🚀 Usage
### 1. Run the Tool
```bash
python main.py
```
![Captura de pantalla 2025-02-16 202303](https://github.com/user-attachments/assets/255a8fa2-9dc8-4529-8d8d-cf7ad7595766)



### 2. Main Menu Options
- **Single Domain Analysis**:  
  - Analyze DMARC/SPF/DKIM for one domain.  
  - Optionally send a spoofed email if the domain is found vulnerable.

![Captura de pantalla 2025-02-16 202348](https://github.com/user-attachments/assets/5036eaac-f6cd-4bf0-8976-0eac7a16e83d)


- **Batch Mode (Concurrent Scanning)**:  
  - Analyze multiple domains (listed in a file) concurrently.  
  - Optionally send spoofed emails in bulk to all vulnerable domains.
- **About**:  
  - Displays information about the tool, its purpose, and authorship.
- **Exit**:  
  - Quit the program.

### 3. SMTP Configuration
- You need an SMTP server to send emails. If you don’t have one, you can use a service like **[Brevo](https://www.brevo.com/)** to obtain SMTP credentials (host, port, username, and password).
- When prompted by the tool, enter the SMTP details accordingly.

### 4. Sending Spoofed Emails
- **Email Generation**:  
  - **Manual (Option 1)**: Write the HTML body of the email directly.
  - **AI (Option 2)**: Provide a prompt to generate a phishing-like HTML email using OpenAI.
 
![Captura de pantalla 2025-02-16 202511](https://github.com/user-attachments/assets/35511bb4-cde2-4229-b9b9-2fb880994295)

    
- **Attachments & Headers**:  
  - Attach files from local disk or via URL.  
  - Set additional headers (like Reply-To) or add a custom signature (X-Hacked-By).

### 5. Reporting
- After scanning (single or batch), an **HTML report** (`spoofing_report.html`) is generated, summarizing domain vulnerabilities and their DMARC/SPF/DKIM status.

## ⚠️ Disclaimer
This tool is intended **ONLY** for **legal penetration testing, cybersecurity research, and educational purposes** in controlled environments. **Unauthorized use is strictly prohibited.**  
Always ensure you have explicit permission before conducting any security tests.

---

**Happy Testing!**  
*Author: atypical_exe*

