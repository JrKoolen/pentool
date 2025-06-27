# Setting Up a Local Test Environment

## **Option 1: XAMPP + Vulnerable Apps (Recommended)**

### **Step 1: Install XAMPP**
1. Download XAMPP: https://www.apachefriends.org/
2. Install with default settings
3. Start Apache and MySQL services

### **Step 2: Install Vulnerable Applications**

#### **DVWA (Damn Vulnerable Web Application)**
```bash
# Download DVWA
wget https://github.com/digininja/DVWA/archive/master.zip
# Extract to C:\xampp\htdocs\dvwa
# Configure database in config/config.inc.php
# Default credentials: admin/password
```

#### **OWASP Juice Shop**
```bash
# Using Docker
docker run -d -p 3000:3000 bkimminich/juice-shop
# Access at http://localhost:3000
```

#### **WebGoat**
```bash
# Download from https://owasp.org/www-project-webgoat/
# Run with: java -jar webgoat-server-8.2.2.jar
# Access at http://localhost:8080/WebGoat
```

## **Option 2: Docker Vulnerable Apps**

### **Vulhub**
```bash
# Clone Vulhub
git clone https://github.com/vulhub/vulhub.git
cd vulhub

# Start specific vulnerable apps
docker-compose up -d
```

### **VulnHub**
```bash
# Download VMs from https://www.vulnhub.com/
# Import into VirtualBox or VMware
```

## **Option 3: Online Practice Platforms**

### **PortSwigger Web Security Academy**
- Free online labs
- Realistic vulnerable applications
- Progressive difficulty levels
- URL: https://portswigger.net/web-security/all-labs

### **HackTheBox**
- Web challenges
- Requires solving entry challenge
- URL: https://www.hackthebox.com/

### **TryHackMe**
- Web application rooms
- Guided learning paths
- URL: https://tryhackme.com/

## **Recommended Test Scenarios**

### **1. SQL Injection Testing**
- Target: `http://testphp.vulnweb.com/artists.php?artist=1`
- Payloads: `' OR 1=1--`, `admin'--`, `' UNION SELECT 1,2,3--`

### **2. XSS Testing**
- Target: `http://testphp.vulnweb.com/guestbook.php`
- Payloads: `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`

### **3. Directory Traversal**
- Target: `http://testphp.vulnweb.com/`
- Payloads: `../../../etc/passwd`, `..\..\..\windows\system32\drivers\etc\hosts`

### **4. File Upload Testing**
- Target: `http://testphp.vulnweb.com/upload.php`
- Upload: PHP shells, image files with embedded code

### **5. Authentication Bypass**
- Target: `http://testphp.vulnweb.com/login.php`
- Methods: SQL injection, default credentials, session manipulation

## **Safety Guidelines**

### **✅ Legal Testing:**
- Your own systems
- Authorized test environments
- Public bug bounty programs
- Educational platforms
- Intentionally vulnerable applications

### **❌ Illegal Testing:**
- Unauthorized systems
- Production environments
- Systems you don't own
- Government/military systems
- Financial institutions (without permission)

## **Testing Checklist**

### **Before Testing:**
- [ ] Verify you have permission
- [ ] Document your testing scope
- [ ] Set up proper logging
- [ ] Have a rollback plan

### **During Testing:**
- [ ] Use non-destructive payloads
- [ ] Monitor system resources
- [ ] Document all findings
- [ ] Respect rate limits

### **After Testing:**
- [ ] Clean up any test data
- [ ] Document vulnerabilities found
- [ ] Provide remediation recommendations
- [ ] Secure any test accounts

## **Quick Start Commands**

### **Start Local Test Environment:**
```bash
# Start your local server
python serve_local.py

# Start GUI
python gui_main.py

# Test against local site
http://localhost:8080
```

### **Test Against Public Sites:**
```bash
# Test against Acunetix test site
http://testphp.vulnweb.com/artists.php?artist=1

# Test against OWASP test site
http://demo.testfire.net/
```

## **Resources**

### **Vulnerability Databases:**
- https://cve.mitre.org/ - Common Vulnerabilities and Exposures
- https://nvd.nist.gov/ - National Vulnerability Database
- https://www.exploit-db.com/ - Exploit Database

### **Learning Resources:**
- https://owasp.org/ - Open Web Application Security Project
- https://portswigger.net/web-security - Web Security Academy
- https://www.hacker101.com/ - Hacker101

### **Tools:**
- Burp Suite Community Edition
- OWASP ZAP
- Nikto
- Nmap
- Your custom penetration testing tool! 🎯 