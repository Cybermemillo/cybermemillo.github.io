---
title: Vulnerability analysis of Windowsplotable7 and Metasploitable3
description: A report on vulnerability analysis of Windowsplotable7 and Metasploitable3, 10 of the most serious vulnerabilities that these machines contain are analyzed, and solutions to these are offered.
date: 2024-11-28 20:26
categories: [Reports, Vulnerability Reports]
tags: [Metaesplotable3, Windowsplotable7, Vuln analysis, English, Reports, Blue Team]
---
# Introduction

The present work aims to perform an exhaustive analysis of vulnerabilities in two specific laboratory systems, known as Windowsplotable7 and Metasploitable3. Both environments are designed for teaching and practicing cybersecurity techniques, making them ideal platforms for vulnerability identification and assessment. 

The analysis will be developed using professional tools widely recognized in the field of computer security: NMAP, for the initial discovery of services and ports, as well as OpenVAS and Nessus for in-depth vulnerability assessment.

The adopted methodology will follow a series of strategic steps to ensure a rigorous and complete analysis:

1. Initial NMAP scan: A comprehensive NMAP scan will be performed to identify open ports and running services on both systems. Different NMAP modules and parameters will be used to delineate the initial attack surface and detect potential vulnerable access points.
   
2. Analysis of **Windowsplotable7 with OpenVAS** (Black Box Analysis): In this case, a black box approach will be chosen, performing the analysis without prior knowledge of the system's internal configuration. Using OpenVAS, the vulnerabilities detected will be identified and evaluated, prioritizing those that represent a higher security risk.
   
3. Analysis of **Metasploitable3 with Nessus** (White Box Analysis): The analysis of Metasploitable3 will be of white box type, allowing a more detailed study of the system's internal configurations and characteristics. 
   
This will facilitate the identification of complex vulnerabilities and the evaluation of the security configuration with greater precision.

From the results obtained, the **10 most critical vulnerabilities** detected in each system will be selected. A detailed investigation will be carried out on each one, exploring its origin, the possible impact on system security and the most effective methods for its patching and mitigation. 

This work seeks not only to identify potential threats, but also to offer a practical approach to best practices in the protection of Windows and Linux environments, providing recommendations based on the experience gained during the analysis.

The study aims to be a didactic contribution to the field of cybersecurity, showing the importance of a correct identification and management of vulnerabilities in exposed systems, applying professional methodologies and tools that allow the continuous improvement of security in any type of computing environment.

<hr>

## Windowsplotable 7

## Windowsplotable7 NMAP

The command used to do the NMAP of Windowsplotable7 was the following:

>nmap -sC -sV -p- --open -O -Pn -T4 -v 10.0.2.13 > escaneoWindowsplotable7.

This is a good basis for performing port and service scanning on a system. 
The command has the following arguments:
1. -sC: To run basic Nmap scripts, to detect common vulnerabilities.
2. -sV: To detect the versions of the services that are listening on the ports.
3. -p-: We scan all the ports so that none is omitted.
4. --open: Show only the open ports.
5. -O: To try to show the operating system.
6. -Pn: Disables PING in case there is a firewall blocking ICMP pings.
7. -T4: We accelerate the scanning (for pure comfort, really it would be necessary to do it more stealthily).
8. -v: We add verbosity to have more information in real time.
9. 10.0.2.13: The IP address of the equipment.
10. With \> escaneoWindowsplotable7 we make to save the results in a file.

## Summary of potential vulnerabilities scanned with the NMAP
1. **MS17-010 (EternalBlue)**: Apply appropriate patches to fix the vulnerability.
2. **BlueKeep (CVE-2019-0708)**: Apply the corresponding Remote Desktop Protocol patches to fix the vulnerability.
3. **UPnP and SMB misconfigured**: Review security settings.
4. **Brute-force attacks on RDP**: Review and strengthen passwords, use multi-factor authentication and change the self-signed certificate to a certificate from a trusted issuer.
5. **Unnecessary exposure of RPC ports**: Restrict access to those ports and configure a Firewall.
## Development of potential vulnerabilities scanned with OpenVAS

1. **MS17-010 (EternalBlue)**.
   1. Description:  This vulnerability affects the SMBv1 protocol and allows remote code execution on vulnerable systems. It directly affects the SMBv1 port configured on this system on ports 139 and 445.
   2. Impact: 
      1. Remote access to the system
      2. Spread of malware within the internal network
   3. Mitigation:
      1. Apply MS17-010 security patch provided by Microsoft.
      2. Disable SMBv1.
      3. Restrict access to ports 139 and 445.
2. **BlueKeep (CVE-2019-0708)**.
   1. Description:  This is a critical vulnerability in the Remote Desktop Protocol as it allows remote code execution on unauthenticated systems. 
   2. Impact: 
      1. Full system access
      2. Spread of malware within the internal network
   3. Mitigation: 
      1. Apply critical patches provided by Microsoft
      2. Implement VPN to protect access to the RDP.
      3. Configure multi-factor authentication.
      4. Disable RDP if it is not really necessary.

3. **Insecure configuration of SMB and UPnP**
   1. Description: Both services are configured without proper security measures. On the system ports 2869 and 10243 respond to HTTP requests. SMB has “Message signing” disabled, which leaves it exposed to possible MItM.
   2. Impact:
      1. On the SMB, potential attackers could intercept and modify data in transit.
      2. Misconfigured UPnP could allow external attackers to redirect traffic.
   3. Mitigation:
      1. Enable SMB signing.
      2. Review and limit access to UPnP related ports.

4. **Brute force attacks on RDP**.
   1. Description: RDP does not appear to be adequately protected and is a target for brute force attacks. In addition, it is configured with a self-signed certificate, making it vulnerable to a spoofing attack.
   2. Impact: 
      1. If credentials are compromised, attackers could control the system remotely and move laterally to other systems on the network.
   3. Mitigation:
      1. Configuration of secure and strong passwords.
      2. Use of multi-factor authentication.
      3. Changing the self-signed certificate to one issued by a trusted authority.

5. **Unnecessary exposure of RPC ports.**
   1. Description: RPC dynamic ports are open and exposed. This leaves the door open to several vulnerabilities that have previously been targeted.
   2. Impact:
      1. Potential remote code execution through RPC flaws
      2. Increased attack area by exposing non-essential services.
   3. Mitigation:
      1. Restrict access to these ports.
      2. Configure firewalls to block unauthorized access.

<hr>

## Windowsplotable7 Vulnerability Scan with OpenVAS

### Windowsplotable7 Vulnerability Scan Summary

1. **TLS/SSL Server Supports TLS Version 1.0**
   1. Description: The server supports TLS 1.0, an encryption protocol considered insecure and obsolete.
   2. Impact: It is susceptible to attacks such as POODLE and BEAST, compromising data confidentiality and integrity.
   3. Mitigation: Disable support for TLS 1.0 and enable TLS 1.2 or higher.

2. **SSL/TLS: Certificate Signed Using a Weak Signature Algorithm**
   1. Description: The server certificate uses SHA-1.
   2. Impact: Facilitates collision attacks that could allow an attacker to spoof the server's identity.
   3. Mitigation: Replace the certificate with one signed by a more robust algorithm such as SHA-256.

3. **TCP Timestamps**
   1. Description: The system responds with TCP timestamps that can be used to calculate uptime.
   2. Impact: Attackers could infer information about maintenance or restart windows.
   3. Mitigation: Disable TCP timestamps in the operating system configuration.
   
4. **DCE/RPC and MSRPC Services Enumeration Reporting**
   1. Description: DCE/RPC services enable the enumeration of services and resources. 
   2. Impact: They expose sensitive information that can facilitate reconnaissance in early stages of an attack.
   3. Mitigation: Restrict access to DCE/RPC ports and enforce access control lists.

5. **Microsoft Windows SMB Server Multiple Vulnerabilities**
   1. Description: The SMBv1 implementation on the server is vulnerable to remote code execution.
   2. Impact: The attacker could take control of the system using an exploit such as EternalBlue.
   3. Mitigation: Apply patch MS17-010 and disable the SMBv1 protocol.

6. **SMTP Server Exposed Over the Internet:**
   1. Description: SMTP server is accessible from the internet without security controls.
   2. Impact: Can be abused for user enumeration and spamming.
   3. Mitigation: Configure the server to accept only authenticated connections and limit access by IP.

7. **Weak SSH Host Key:**
   1. Description: The host key used for SSH has a size and algorithm that is considered to be weak.
   2. Impact: Allows attackers to perform brute force attacks and decrypt communications.
   3. Mitigation: Regenerate the keys using stronger algorithms.

8. **SSL/TLS: Deprecated Cipher Suites Detected**
   1. Description: Deprecated or insecure cipher suites have been detected in the SSL/TLS server.
   2. Impact: Vulnerability to attacks such as CRIME, BREACH and brute force.
   3. Mitigation: Upgrade configuration to use modern and secure ciphers.

9.  **PHP Version detected**
    1.  Description: An older version of PHP has been detected with known vulnerabilities.
    2.  Impact: Exposure to exploits that may allow remote code execution and data leaks.
    3.  Mitigation: Upgrade to the latest stable PHP version.

10. **Open Ports detected**
    1. Description: Multiple open ports have been identified on the system, and there are some that are not linked to essential services. 2.
    2. Impact: Open ports increase the attack surface and can be used to perform network scans, brute force, exploit vulnerabilities, etc. ....
    3. Mitigation: Perform an exhaustive analysis of the associated services to disable those that are not essential and apply access controls through firewalls.

### Windowsplotable7 Vulnerability Scanning Development
1. **TLS/SSL Server Supports TLS Version 1.0**
   1. Description: The server still allows connections via the TLS 1.0 protocol. This protocol, although once standard, is now obsolete due to vulnerabilities that make it insecure against modern attacks.
   2. Impact: TLS 1.0 is susceptible to attacks such as POODLE (Padding Oracle on Downgraded Legacy Encryption) and BEAST (Browser Exploit Against SSL/TLS). These attacks can compromise the confidentiality and integrity of transmitted data, allowing its interception or manipulation.
   3. Mitigation:
      1. disable support for TLS 1.0 in the server configuration.
      2. Ensure that only modern versions of TLS (TLS 1.2 or higher) are enabled.
      3. Perform tests to ensure compatibility with clients using the updated versions.

4. **SSL/TLS: Certificate Signed Using A Weak Signature Algorithm**
   1. Description: The SSL/TLS certificate uses the SHA-1 algorithm, which is considered weak due to advances in collision attacks that allow certificates to be forged.
   2. Impact:
      1. Attackers can create fake certificates that appear legitimate, facilitating man-in-the-middle (MITM) attacks.
      2. Negatively impacts browser trust, displaying warnings to users.
   3. Mitigation:
      1. Request a new certificate signed with more robust algorithms such as SHA-256 or higher.
      2. Ensure that the server is configured to prioritize strong certificates during SSL/TLS negotiation.

4. **TCP Timestamps**
      1. Description: Timestamps in TCP packets allow an attacker to calculate system uptime, facilitating attacks based on pattern analysis.
      2. Impact: Attackers can deduce maintenance or reboot windows to launch attacks at times of vulnerability. This information can also aid in operating system identification and classification.
    3. Mitigation: 
         1. Disable TCP timestamps in the operating system configuration. 
         2. Perform post-testing to ensure that the disabling does not impact critical services.

5. **DCE/RPC and MSRPC Services Enumeration Reporting**
   1. Description: DCE/RPC services allow for enumeration of details such as enabled services and shared resources on the network.
   2. Impact:
      1. Attackers can use this information to plan advanced attack phases, such as exploiting specific services.
      2. Facilitates reconnaissance in Windows environments where DCE/RPC is actively used.
    3. Mitigation:
         1. Restrict access to DCE/RPC ports using firewalls.
         2. Implement access policies based on whitelists or Access Control Lists (ACLs).
         3. Disable non-essential services to reduce the attack surface.

6. **Microsoft Windows SMB Server Multiple Vulnerabilities (4013389)**
   1. Description: The SMBv1 protocol implementation has multiple critical vulnerabilities, including remote code execution.
   2. Impact:
      1. Exploits such as Eternal Blue can be used to take control of the system.
      2. Facilitates the spread of ransomware such as Wanna Cry on corporate networks.
   3. Mitigation:
      1. Install the MS17-010 patch to fix known vulnerabilities.
      2. Disable SMBv1 and migrate to more secure versions of the protocol (SMBv2 or SMBv3).

7. **SMTP Server Exposed Over the Internet**
   1. Description: SMTP server is publicly available without security controls, exposing it to abuse.
   2. Impact:
      1. Attackers can use the server to enumerate valid users using the VRFY command.
      2. It can be exploited to send spam or phishing, affecting the reputation of the domain.
   3. Mitigation:
      1. Configure the SMTP server to accept only authenticated connections.
      2. Implement access control lists to limit access by IP address.
      3. Regularly monitor server usage to detect suspicious activity.

8. **Weak SSH Host Key**
   1. Description: SSH server uses host keys with insufficient size or weak algorithms.
   2. Impact:
      Weak keys may be vulnerable to brute force or decryption attacks
      1. Prolonged exposure of these keys makes it easy to exploit them in a persistent attack environment.
   3. Mitigation:
      1. Regenerate SSH keys using strong algorithms such as RSA of at least 2048 bits or ECDSA.
      2. Enforce strict key rotation and secure key storage policies.

9.  **SSL/TLS: Deprecated Cipher Suites Detected**
       1. Description: The server allows the use of deprecated cipher suites that do not provide adequate protection against modern attacks.
       2. Impact: 
          1. Vulnerable to attacks such as CRIME, BREACH or Lucky13, which exploit flaws in weak ciphers.
          2. Risk of decryption of communications if use of these suites is forced.
       3. Mitigation:
          1. Update SSL/TLS configuration to disable obsolete ciphers.
          2. Prioritize the use of modern suites such as AES-GCM with long keys.

10. **PHP Version Detected**
   1. Description: The server is running an old PHP version with known vulnerabilities.
   2. Impact:
      1. Attackers can exploit vulnerabilities in this version to execute arbitrary code or steal sensitive data.
      2. Increases the risk of attacks on web applications that rely on this version of PHP.
   3. Mitigation:
      1. Upgrade to the latest stable version of PHP.
      2. Review dependent applications to ensure compatibility with the new version.

11. **Open Ports Detected**
    Description: Multiple open ports were detected, some of them unnecessary or without protected services behind.
    1. Impact:
       1. Attackers can perform port scans to identify vulnerable services.
       2. Every open port is a potential entry point for attacks.
    2. Mitigation:
       1. Implement a port shutdown policy, allowing only those ports that are strictly necessary.
       2. Use firewalls to restrict access to specific ports based on IP addresses or authorized ranges.
       3. Perform regular audits to detect and close unnecessary ports.

<hr>

## Metaesploitable3

## NMAP of Metaesploitable3

The command used to NMAP Metaesploitable3 was as follows:

>nmap -sC -sV -p- --open -O -Pn -T4 -v 10.0.2.13 > escaneoMetaesploitable3

This is a good basis for performing port and service scanning on a system. 
The command has the following arguments:
1. -sC: To run basic Nmap scripts, to detect common vulnerabilities.
2. -sV: To detect the versions of the services that are listening on the ports.
3. -p-: We scan all the ports so that none is omitted.
4. --open: Show only the open ports.
5. -O: To try to show the operating system.
6. -Pn: Disables PING in case there is a firewall blocking ICMP pings.
7. -T4: We accelerate the scanning (for pure comfort, really it would be necessary to do it more stealthily).
8. -v: We add verbosity to have more information in real time.
9. 10.0.2.16: The IP address of the equipment.
10. With \> escaneoMetaesploitable3 we save the results in a file.

## Summary of potential vulnerabilities scanned with the NMAP

1. **ProFTPD 1.3.5 (FTP)**
   1. Description: FTP server using ProFTPD version 1.3.5. 2.
   2. Impact: Historically, ProFTPD has had vulnerabilities that allow remote code execution or unauthorized access to the system.
   3. Mitigation: Upgrade to the latest stable version of ProFTPD and disable unnecessary features.

2. **OpenSSH 6.6.1p1 (SSH)**
   1. Description: SSH service that allows secure connections to the system. 2.
   2. Impact: Older versions of OpenSSH may be susceptible to brute force attacks or specific vulnerabilities that allow elevation of privileges.
   3. Mitigation: Upgrade OpenSSH to a newer version and apply good security practices such as using SSH keys instead of passwords.

3. **Apache HTTPD 2.4.7 (HTTP)**
   1. Description: Apache web server, version 2.4.7.
   2. Impact: Older versions of Apache may be vulnerable to directory traversal, command injection, or DoS attacks.
   3. Mitigation: Upgrade to the latest version and disable unneeded modules. Consider implementing a WAF (Web Application Firewall).

4. **Samba 4.3.11-Ubuntu (NetBIOS/SMB)**
   1. Description: File and resource sharing service over network using Samba. 2.
   2. Impact: Older versions of Samba may allow privilege escalation or unauthorized access to shared resources.
   3. Mitigation: Upgrade Samba to the latest stable version, disable anonymous access, and use secure authentication.

5. **CUPS 1.7 (IPP)**
   1. Description: Common UNIX Printing System (CUPS) based print server.
   2. Impact: May be vulnerable to DoS attacks, information disclosure or remote code execution. 3.
   3. Mitigation: Upgrade to a newer version of CUPS and restrict access to the print server via firewall or access rules.

6. **MySQL (unauthorized)**
   1. Description: MySQL database accessible without authorization. 2.
   2. Impact: May allow SQL injection attacks and unauthorized access to sensitive data. 3.
   3. Mitigation: Restrict access to the database to trusted hosts only and ensure that authentication is properly configured.

7. **WEBrick 1.3.1 (Ruby HTTP)**
   1. Description: Ruby based HTTP server, version 1.3.1.
   2. Impact: The default configuration may be insecure, allowing attacks such as remote code execution or buffer overflows.
   3. Mitigation: Upgrade to a more secure version or consider using another more robust web server for production environments.

8. **UnrealIRCd (IRC)**
   1. Description: IRC server based on UnrealIRCd. 2.
   2. Impact: Some versions have had integrated backdoors that allow remote execution of commands.
   3. Mitigation: Verify the integrity of the software and upgrade to a secure version. Configure restrictive access rules for the service.

9.  **Jetty 8.1.7 (HTTP)**
       1. Description: Jetty web server, version 8.1.7.
       2. Impact: Older versions may have vulnerabilities that allow remote code execution or DoS attacks. 3.
       3. Mitigation: Upgrade to the latest version of Jetty and apply additional security settings, such as disabling insecure HTTP methods.

### Development of vulnerabilities found with NMAP
1. **ProFTPD 1.3.5 (FTP)**
   1. Description: ProFTPD is an open source FTP server known for its flexibility and modularity. Version 1.3.5 has a history of critical vulnerabilities, including flaws that allow attackers to execute arbitrary commands on the server with elevated privileges if they exploit incorrect configurations or software bugs.
   2. Impact: Successful exploitation of vulnerabilities in ProFTPD 1.3.5 can lead to remote code execution, unauthorized file access, credential theft and, potentially, full control of the FTP server. This compromises the confidentiality, integrity and availability of the affected system.
   3. Mitigation: Upgrade ProFTPD to the latest stable version, where known security flaws have been fixed. In addition, properly configure security settings in the proftpd.conf file, disable anonymous accounts if they are not needed, and restrict access to specific IP addresses using access controls. It is also recommended to enable FTPS to protect data transmission.

2. **OpenSSH 6.6.1p1 (SSH)**
   1. Description: OpenSSH 6.6.1 is an SSH server that allows users to securely connect to remote systems. Older versions, such as 6.6.1, can be vulnerable to brute force attacks, key reuse attacks and other security issues if not properly patched.
   2. Impact: Vulnerabilities in OpenSSH 6.6.1 could allow attackers to gain unauthorized access to the system through brute-force attacks or by exploiting bugs in the SSH protocol implementation. This could result in privilege escalation, data theft and system compromise.
   3. Mitigation: Upgrade to a newer version of OpenSSH that includes security fixes. Implement strong password policies, use SSH keys instead of passwords, disable root login via SSH, and configure the service to allow only a limited number of authentication attempts. Also, enable two-factor authentication when possible.

3. **Apache HTTPD 2.4.7 (HTTP)**
   1. Description: Apache is one of the most widely used web servers in the world. Version 2.4.7, although stable, contains known vulnerabilities that can be exploited if security patches have not been applied. This includes risks of directory traversal, command injection and denial of service (DoS) issues.
   2. Impact: An attacker could exploit vulnerabilities in Apache 2.4.7 to gain unauthorized access to sensitive directories and files, execute malicious code on the server, or disrupt the service. This compromises the security of hosted information and the stability of the web server.
   3. Mitigation: Upgrade Apache to the latest version available. Ensure that the security recommendations for the httpd.conf file configuration are implemented, including restricting insecure HTTP methods and disabling directory browsing. Implement a WAF (Web Application Firewall) to monitor and block malicious requests.

4. **Samba 4.3.11-Ubuntu (NetBIOS/SMB)**
   1. Description: Samba is a free implementation of the SMB protocol that allows file and printer sharing on a network. Version 4.3.11 has vulnerabilities that may allow an attacker to escalate privileges, gain unauthorized access to shared resources or perform denial of service attacks.
   2. Impact: Vulnerabilities in Samba 4.3.11 can be exploited to gain access to sensitive files, compromise user accounts, and potentially take control of the system if combined with other attack techniques.
   3. Mitigation: Upgrade Samba to the latest stable version and apply the recommended security settings. Restrict access to shared folders using Access Control Lists (ACLs), disable anonymous access and enable secure user authentication (NTLMv2).

5. **CUPS 1.7 (IPP)**
   1. Description: CUPS (Common UNIX Printing System) is a print server widely used in UNIX and Linux environments. Version 1.7 can be vulnerable to DoS attacks, exposure of sensitive information and remote code execution if not properly configured.
   2. Impact: An attacker could exploit vulnerabilities in CUPS 1.7 to disable the print service, access the server configuration or execute malicious code on the host system. This would affect the availability and security of the printing environment.
   3. Mitigation: Upgrade CUPS to the latest version that includes security fixes. Limit access to the print server by configuring firewall rules and using access control lists in the CUPS configuration. Secure communication with SSL/TLS if possible.

6. **MySQL (unauthorized)**
   1. Description: The MySQL database service is remotely accessible without authentication, which is a significant security risk. This can allow SQL injection attacks and unauthorized access to the database.
   2. Impact: Attackers can exploit the lack of security in MySQL to steal, modify or delete critical information. In addition, they could gain administrative access if they exploit the vulnerabilities properly.
   3. Mitigation: Configure MySQL to only accept connections from trusted hosts. Ensure that all accounts have strong passwords and enable secure authentication. Review permission settings on tables and restrict IP-based access.

7. **WEBrick 1.3.1 (Ruby HTTP)**
   1. Description: WEBrick is a simple web server bundled with Ruby. Although it is easy to use, version 1.3.1 is unsuitable for production environments due to possible vulnerabilities in session handling, buffer overflows and insecure default configuration.
   2. Impact: Exploitation of vulnerabilities in WEBrick could lead to remote code execution, exposure of sensitive data and denial of service attacks, compromising the confidentiality and availability of the server.
   3. Mitigation: Consider migrating to a more robust web server for production, such as Nginx or Apache. If using WEBrick, upgrade to a recent version, apply secure configurations and use mod_security or a WAF to protect against common web attacks.
8. **UnrealIRCd (IRC)**
   1. Description: UnrealIRCd is an IRC server used for real-time communication. There have been incidents of versions with backdoors that allowed remote execution of commands, compromising the entire communication infrastructure.
   2. Impact: An attacker could use a backdoor or exploit a vulnerability in UnrealIRCd to gain full access to the server, allowing arbitrary commands to be executed and compromising the security of the system.
   3. Mitigation: Verify the integrity of the software by downloading UnrealIRCd from official and trusted sources. Upgrade to a backdoors-free version and properly configure access restrictions for users and channels.

9. **Jetty 8.1.7 (HTTP)**
   1. Description: Jetty is a lightweight and flexible web server used for web applications. Version 8.1.7 has known vulnerabilities that allow DoS attacks, exploitation of insecure HTTP methods and, potentially, remote code execution.
   2. Impact: If an attacker exploits a vulnerability in Jetty, they could execute malicious code on the server, access sensitive information or disrupt the web service, affecting users and the integrity of the server.
   3. Mitigation: Upgrade Jetty to the latest version that includes security patches. Configure access restrictions to the administration interface and disable insecure HTTP methods. Implement good security practices in web application development.

<hr>

## Analysis of Metasploitable3 vulnerabilities with Nessus
### Summary of vulnerabilities found with Nessus

1. **Bash Remote Code Execution (Shellshock)**.
   1. Description: The host version of Bash allows command injection through manipulation of environment variables, which can allow remote execution of arbitrary code.
   2. Impact: An attacker could execute arbitrary commands on the system, completely compromising the integrity, confidentiality and availability of the affected host.
   3. Solution: Upgrade Bash to the latest version.

2. **ProFTPD mod_copy Information Disclosure**
   1. Description: The version of ProFTPD installed allows information disclosure due to insecure commands (SITE CPFR and SITE CPTO) available to unauthenticated users, allowing files to be read/written on web accessible paths.
   2. Impact: An unauthenticated attacker can access and modify sensitive files, compromising confidentiality and data integrity.
   3. Solution: Upgrade to ProFTPD 1.3.5a / 1.3.6rc1 or higher.

3. **Canonical Ubuntu Linux SEoL (14.04.x)**
   1. Description: Ubuntu 14.04.x is no longer supported by the vendor, which implies the absence of future security patches.
   2. Impact: The system may be vulnerable to new threats due to the lack of patches, compromising the overall security of the environment.
   3. Solution: Upgrade to a supported version of Ubuntu.
4. **Linux Sudo Privilege Escalation (Out-of-bounds Write)**
      1. Description: Sudo, in versions prior to 1.9.5p2, has a buffer overflow in the heap that allows privilege escalation to root via certain commands.
   5. Impact: A local or remote user could obtain administrator privileges, compromising the integrity and confidentiality of the system.
   6. Solution: Upgrade sudo to a version that fixes the vulnerability.

4. **IP Forwarding Enabled**
   1. Description: The host has IP forwarding enabled, which allows packets to be redirected through the system, potentially bypassing some security controls.
   2. Impact: An attacker could redirect traffic through the host, which facilitates sniffing attacks and bypassing of network restrictions, affecting confidentiality and integrity.
   3. Solution: Disable IP forwarding if it is not a router.

5. **Node.js Module node-tar < 6.2.1 DoS**
   1. Description: In versions of the node-tar module prior to 6.2.1, validation is missing when unzipping files, which may allow an attacker to exhaust CPU and memory.
   2. Impact: An attacker could cause a Denial of Service (DoS), affecting system availability.
   3. Solution: Upgrade to node-tar version 6.2.1 or later.

6. **MySQL Denial of Service (Jul 2020 CPU)**
   1. Description: MySQL versions up to 5.7.29 and 8.0.19 are vulnerable to a DoS through certain network protocols, allowing an attacker with elevated privileges to block the service.
   2. Impact: An attacker could cause the MySQL server to crash repeatedly, affecting the availability of the database and causing service interruptions.
   3. Solution: Review the vendor's advisory and upgrade MySQL.

7. **ICMP Timestamp Request Remote Date Disclosure**
   1. Description: The host responds to ICMP timestamp requests, disclosing the system date, which can aid attackers in bypassing time-based authentication protocols.
   2. Impact: Disclosure of system time can facilitate synchronization and network analysis attacks, affecting confidentiality.
   3. Solution: Filter ICMP timestamp requests and ICMP timestamp responses.

8. **SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)**
   1. Description: The SSH server is vulnerable to a weakness in prefix truncation that allows a man-in-the-middle attacker to reduce the security of the connection.
   2. Impact: An attacker could intercept and manipulate the SSH connection, compromising the integrity and confidentiality of the transferred data.
   3. Solution: Contact the vendor for an update or disable the affected algorithms.

9.  **TLS Version 1.0 Protocol Detection**
    1. Description: The service accepts connections encrypted with TLS 1.0, which has known cryptographic problems. It is recommended to use newer versions.
    2. Impact: The security of connections can be compromised, allowing downgrade attacks and compromising the confidentiality of the communication.
    3. Solution: Enable support for TLS 1.2 and 1.3, and disable TLS 1.0. 

## Development of the vulnerabilities found with Nessus
1. **Bash Remote Code Execution (Shellshock)**
   1. Description: The Shellshock vulnerability affects versions of Bash that allow command injection via manipulated environment variables. An attacker can exploit this if they have the ability to set environment variable values before invoking Bash, allowing them to execute arbitrary commands on the affected system.
   2. Impact: An attacker could gain full access to the system, compromising its integrity, confidentiality and availability. The vulnerability is particularly dangerous on systems that use Bash in critical configurations, such as CGI on web servers, where a remote attacker could execute malicious commands.
   3. Solution: Upgrade Bash to the latest available version that addresses the Shellshock vulnerability. This usually involves applying the patches provided by the operating system vendor or compiling an updated version of Bash from source code.

2. **ProFTPD mod_copy Information Disclosure**
   1. Description: The affected version of ProFTPD allows unauthenticated users to execute SITE CPFR and SITE CPTO commands via the mod_copy module. This allows copying files to and from accessible locations on the server, including public web paths.
   2. Impact: An attacker could access sensitive files or overwrite important data, compromising the confidentiality and integrity of the system. This vulnerability facilitates information disclosure and unauthorized manipulation of files on the server.
   3. Solution: Upgrade ProFTPD to version 1.3.5a, 1.3.6rc1 or higher, where this vulnerability is fixed. Alternatively, disable the mod_copy module if it is not needed.

3. **Canonical Ubuntu Linux SEoL (14.04.x)**
   1. Description: The installed Ubuntu version, 14.04.x, is no longer maintained by Canonical, which means it will no longer receive security patches or updates. This end-of-life (SEoL) exposes the system to unmitigated security risks.
   2. Impact: The system may be targeted by new exploits due to the lack of patches, affecting the integrity, confidentiality and availability of the platform. This is especially critical in production environments or servers exposed to the Internet.
   3. Solution: Migrate to a supported version of Ubuntu, such as 20.04 LTS or later, that is active in the support cycle and receives regular security updates.

4. **Linux Sudo Privilege Escalation (Out-of-bounds Write)**
   1. Description: A vulnerability in sudo versions prior to 1.9.5p2 allows a heap-based buffer overflow, which facilitates privilege escalation to root when sudoedit -s is used in conjunction with certain command line arguments.
   2. Impact: An attacker with local access could exploit this vulnerability to gain root privileges, compromising the entire security of the system. This affects the integrity of the system, potentially allowing malicious modifications at the administrative level.
   3. Workaround: Upgrade sudo to version 1.9.5p2 or higher, which contains the buffer overflow fix. In environments where the upgrade is not immediate, restrict the use of sudo to trusted users.

5. **IP Forwarding Enabled**
   1. Description: The IP forwarding feature is enabled on the system, allowing the host to forward network packets. This can be exploited by an attacker to redirect traffic through the server, potentially bypassing network controls.
   2. Impact: Enabling IP forwarding on non-router systems may allow an attacker to use the system as a transit point for attacks, which could affect the confidentiality of network traffic or allow bypassing of filtering rules.
   3. Solution: Disable IP forwarding if it is not necessary. On Linux, use the command echo 0 > /proc/sys/net/ipv4/ip_forward. On Windows, set IPEnableRouter to 0 in the registry, and on macOS, run sysctl -w net.inet.ip.forwarding=0.

6. **Node.js Module node-tar < 6.2.1 DoS**
   1. Description: Versions prior to 6.2.1 of the node-tar module lack validation when decompressing files, allowing an attacker to use a malicious file to exhaust CPU and memory resources, causing a Denial of Service (DoS).
   2. Impact: An attacker could destabilize the Node.js application, affecting its availability by causing excessive resource consumption, which can lead to system crash or inability to provide service.
   3. Solution: Upgrade node-tar to version 6.2.1 or higher to fix this vulnerability. This should be done through the package manager used (npm or yarn) in the project environment.

7. **MySQL Denial of Service (Jul 2020 CPU)**
   1. Description: MySQL versions up to 5.7.29 and 8.0.19 have a vulnerability that allows a privileged attacker to cause a Denial of Service (DoS) by exploiting the replication component.
   2. Impact: An attacker could cause the MySQL server to crash repeatedly, compromising the availability of the database and affecting the operability of the applications that depend on it.
   3. Solution: Follow the guidance provided in the July 2020 MySQL critical patch advisory and upgrade to newer versions of MySQL.

8. **ICMP Timestamp Request Remote Date Disclosure**
   1. Description: The system responds to ICMP timestamp requests, which discloses the system date and time. This can be exploited by an attacker to synchronize attacks or bypass time-based authentication mechanisms.
   2. Impact: Revealing the exact time of the system can facilitate synchronization attacks, such as spoofing time-based credentials or analyzing network behavior, compromising confidentiality.
   3. Solution: Filter inbound ICMP timestamp requests and outbound responses through rules in the system firewall.

9. **SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)**
   1. Description: The SSH server has a weakness in prefix management that allows a man-in-the-middle attacker to manipulate communication, reducing the security of the key exchange.
   2. Impact: An attacker could intercept and alter SSH communications, compromising the integrity and confidentiality of transferred data, and potentially impersonate legitimate users.
   3. Solution: Contact the software vendor for an update that implements more stringent key exchange measures. Disable vulnerable algorithms if possible.

10. **TLS Version 1.0 Protocol Detection**
    1. Description: The system accepts encrypted connections using the TLS 1.0 protocol, which has known vulnerabilities. TLS 1.2 and 1.3 are more secure and recommended versions.
    2. Impact: Communication could be compromised due to vulnerabilities in TLS 1.0, which would allow downgrade attacks, compromising the confidentiality of the data.
    3. Solution: Configure the system to disable TLS 1.0 and enable TLS 1.2 and 1.3 instead, adjusting the server configuration to improve communication security.

# Conclusions

The vulnerability analysis performed on the Windowsplotable7 and Metasploitable3 systems provides a clear vision of the importance of proactive security in technological environments, especially in systems that do not receive constant updates or whose initial configuration is vulnerable. Throughout this study, advanced vulnerability analysis methodologies were used using tools such as NMAP, OpenVAS and Nessus, each providing a different approach to identifying and assessing potential risks.

In the case of Windowsplotable7, black box analysis with OpenVAS identified a number of vulnerabilities related to insecure configurations, outdated protocols and unnecessary exposure of services. These findings highlight the need to keep operating systems up to date and apply secure configuration policies, as many of the vulnerabilities detected could have been mitigated with proper patch management and the implementation of best practices in service configuration.
In addition, the importance of restricting access to certain ports and services was highlighted, minimizing the attack surface.

On the other hand, in Metasploitable3, the white box analysis with Nessus allowed a deep evaluation of the system, taking advantage of privileged access to identify critical vulnerabilities in internal configurations, installed applications and obsolete services. This approach demonstrated the importance of performing periodic security audits in environments where full access is available, as it allowed the detection of problems that might have gone unnoticed in a black box analysis. Vulnerabilities in software version management, lack of package updates, and the presence of default or insecure configurations stand out.

This analysis highlights the relevance of a solid and well-structured security strategy that considers both infrastructure protection and vulnerability management in the lifecycle of each system. With the information and best practices obtained in this study, it is possible to improve the security posture in similar environments, increasing resilience to potential threats.