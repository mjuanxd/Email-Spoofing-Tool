# Email Spoofing  Tool

## 🚀 Overview
This project is a **email spoofing tool** designed strictly for **educational, security testing, and controlled environments**. The tool provides various functionalities to analyze domain vulnerabilities, generate spoofed emails, and test email security defenses.

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
### Windows Installation
1. **Download & Install Python** (if not installed):  
   - Download from [Python Official Site](https://www.python.org/downloads/).
   - Ensure you check the box **"Add Python to PATH"** during installation.
2. **Clone the repository & Install dependencies**:
   ```bash
   git clone https://github.com/yourusername/email-spoofing-tool.git
   cd email-spoofing-tool
   pip install -r requirements.txt
   ```
3. **Run the tool**:
   ```bash
   python main.py
   ```
   ![Captura de pantalla 2025-02-16 204309](https://github.com/user-attachments/assets/7ab6b8ed-ed98-4f2b-8cda-d396f16b40eb)

   



### Linux/macOS Installation
1. **Ensure Python3 & Git are installed**:
   ```bash
   sudo apt update && sudo apt install python3 python3-venv git -y  # Debian-based
   sudo pacman -S python python-virtualenv git  # Arch-based
   ```
2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/email-spoofing-tool.git
   cd email-spoofing-tool
   ```
3. **Set up a Virtual Environment (Recommended for Linux/macOS users)**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Activate the virtual environment
   pip install -r requirements.txt
   ```
4. **Run the tool**:
   ```bash
   python main.py
   ```
   ![Captura de pantalla 2025-02-16 204354](https://github.com/user-attachments/assets/f5c16792-e2a5-4457-b9bd-93e168b5cbe4)


## 🚀 Usage
### 1. Run the Tool
```bash
python main.py
```

### 2. Main Menu Options
- **Single Domain Analysis**:  
  - Analyze DMARC/SPF/DKIM for one domain.  
  - Optionally send a spoofed email if the domain is found vulnerable.

![Captura de pantalla 2025-02-16 202348](https://github.com/user-attachments/assets/ac9e3cc8-868a-4099-ae7f-9135bf7af0c1)

    
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

![Captura de pantalla 2025-02-16 202511](https://github.com/user-attachments/assets/6ec0f5ae-c92b-4dad-8c17-882cc8347a95)

- **Attachments & Headers**:  
  - Attach files from local disk or via URL.  
  - Set additional headers (like Reply-To) or add a custom signature (X-Hacked-By).

### 5. Reporting
- After scanning (single or batch), an **HTML report** (`spoofing_report.html`) is generated, summarizing domain vulnerabilities and their DMARC/SPF/DKIM status.

## ⚠️ Disclaimer
This tool is intended **ONLY** for **legal penetration testing, cybersecurity research, and educational purposes** in controlled environments. **Unauthorized use is strictly prohibited.**  
Always ensure you have explicit permission before conducting any security tests.

---

**Happy Pentesting!**  
*Author: atypical_exe*

