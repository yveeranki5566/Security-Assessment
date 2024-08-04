# Security-Assessment

Performed Port scanning and vulnerability assessment on Windows and Linux VM operating systems, to identify available hosts and their respective services and assess the detected vulnerabilities using Nmap and Nessus tools.

**Below are the implementation steps.**
**NMAP SCANNING:**
1. Run the basic Nmap scan on target IP address using /24 CIDR notation from the Linux terminal. 
   ![image](https://github.com/user-attachments/assets/cb054557-d095-4ea8-8074-8d2da3fadb96)

   ![image](https://github.com/user-attachments/assets/cc35507b-bf1f-4179-bcf5-2bd825bbfaf4)

2.	Run Nmap TCP scan and UDP scan on the target IP addresses.

    ![image](https://github.com/user-attachments/assets/a1d9ab00-d5c1-4557-94bb-c6532f5c584f)
    ![image](https://github.com/user-attachments/assets/21f9c485-5468-4517-9c82-f71a410df06c)

3.	Run version and OS detection scans for furthermore details.
    Version detection scan on open ports:

    ![image](https://github.com/user-attachments/assets/9b609450-2d7f-4902-bfd6-f85598b74ca6)

    OS detection scan:

    ![image](https://github.com/user-attachments/assets/cae59dc3-d6a9-4c31-892b-8e07aa8b9916)

 4.	List the targets using Nmap -sL

    ![image](https://github.com/user-attachments/assets/dd158609-c5fb-4abd-a68a-8d02ff7de425)
   	
 5. Run fast scan -F to see the most popular 100 ports data.

     ![image](https://github.com/user-attachments/assets/0ab641e5-f7c3-4ae2-a357-c2b5b72158f0)

 6. Use greppable output for quick search of data.

    ![image](https://github.com/user-attachments/assets/bfef2f39-1e39-4df5-9b6b-337c9f82a365)

 7.	Firewall/IDS evasion techniques.
    a.Source port spoofing: 
    Spoofing the source port as 80:

    ![image](https://github.com/user-attachments/assets/f6facf4b-7b02-4944-828f-28f006db2215)

 8.	Used NSE default, safe scripts to run on target windows subnet to gather more details.
    ![image](https://github.com/user-attachments/assets/b87c918b-c92b-45f3-9546-59b9a65e896c)


**VULNERABILITY SCANNING USING NESSUS ESSENTIALS:**

a.	Run the initial discovery scan for the target windows subnet.

![image](https://github.com/user-attachments/assets/635a033a-3f26-4e8a-99af-6e8a8c46368e)

![image](https://github.com/user-attachments/assets/abd3bdb2-58b7-409b-8969-f5f38107c641)
We can see there are two hosts discovered.
b. Create a new scan using Basic Network Scan template.

  ![image](https://github.com/user-attachments/assets/4371aced-1b0b-4ee5-8e03-41d285035827)

c. Save and launch the sample network scan.

   ![image](https://github.com/user-attachments/assets/f87aed88-798c-416a-8e36-72c6a719ba8e)
   We can see the vulnerabilities for each discovered host here.
   
d.Search for critical and high severity vulnerabilities using the filter tab.
  ![image](https://github.com/user-attachments/assets/7282f9b0-7b2f-4e4c-8c31-b22a161c6112)

  ![image](https://github.com/user-attachments/assets/a73532dd-7beb-43c3-abcb-d86efd8bb3d1)

**Windows OS Vulnerabilities:**

a.	**Port 22: **
    ![image](https://github.com/user-attachments/assets/720b1832-70b6-4fab-afae-8eb0b58b82dd)

   We can observe there is a vulnerability of medium level severity. When we click on it, we get additional details as below: 

  **Name of the Vulnerability: SSH Terrapin Prefix Truncation Weakness**
    Severity level: Medium 
  **Description:** The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness known as Terrapin. This can allow a remote, man-in-the-middle attacker to bypass integrity checks and downgrade the connection's security.
  **Solution:** Contact the vendor for an update with the strict key exchange countermeasures or disable the affected algorithms.

c.	**Port 445:**

   ![image](https://github.com/user-attachments/assets/563c7e49-c1d5-472e-aeb3-1e78a8fabd00)

   We can observe there is a vulnerability of medium level severity. When we click on it we get additional details as below: 
   **Name of the Vulnerability: SMB Signing not required.**
   Severity level: Medium
   **Description:** Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.
   **Solution:** Enforce message signing in the host's configuration. On Windows, this is found in the policy setting 'Microsoft network server: Digitally sign communications (always)'. On Samba, the setting is called 'server signing'.

d. **Port 3389:**

   ![image](https://github.com/user-attachments/assets/1052a71a-0d3e-43af-b78c-e2ab6a9d54ab)

**Name of the Vulnerability: SSL Medium Strength Cipher Suites Supported.**
Severity level: High
**Description:** The remote host supports the use of SSL ciphers that offer medium strength encryption. 
**Solution:** Reconfigure the affected application, if possible, to avoid use of medium strength ciphers.

**Name of the Vulnerability: SSL Certificate Cannot Be Trusted.**
Severity level: Medium
**Description:** The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below:
First, the top of the certificate chain sent by the server might not be descended from a known public certificate authority.
Second, the certificate chain may contain a certificate that is not valid at the time of the scan.
Third, the certificate chain may contain a signature that either didn't match the certificate's information or could not be verified.
If the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host.
**Solution:** Purchase or generate a proper SSL certificate for this service.

**Name of the Vulnerability: SSL Self-Signed Certificate.**
Severity level: Medium
**Description:** The X.509 certificate chain for this service is not signed by a recognized certificate authority. If the remote host is a public host in production, this nullifies the use of SSL as anyone could establish a man-in-the-middle attack against the remote host.
**Solution:** Purchase or generate a proper SSL certificate for this service.

**Name of the Vulnerability: TLS Version 1.0 Protocol Detection.**
Severity level: Medium
**Description:** The remote service accepts connections encrypted using TLS 1.0. TLS 1.0 has several cryptographic design flaws. Modern implementations of TLS 1.0 mitigate these problems, but newer versions of TLS like 1.2 and 1.3 are designed against these flaws and should be used whenever possible.
**Solution:** Enable support for TLS 1.2 and 1.3 and disable support for TLS 1.0.

**Name of the Vulnerability: TLS Version 1.1 Protocol Deprecated.**
Severity level: Medium
**Description:** The remote service accepts connections encrypted using TLS 1.1. TLS 1.1 lacks support for current and recommended cipher suites. Ciphers that support encryption before MAC computation, and authenticated encryption modes such as GCM cannot be used with TLS 1.1
**Solution:** Enable support for TLS 1.2 and/or 1.3 and disable support for TLS 1.1.

**LINUX OS Vulnerabilities:**

a.**Port 22:**

   ![image](https://github.com/user-attachments/assets/9d027e99-7a51-450a-a9c2-30b4322618a3)
 **Name of the Vulnerability:** OpenSSH < 9.6 Multiple Vulnerabilities.
   Severity level: Medium
 **Description:** The version of OpenSSH installed on the remote host is prior to 9.6. It is, therefore, affected by multiple vulnerabilities as referenced in the release-9.6 advisory.
 **Solution:** Upgrade to OpenSSH version 9.6 or later.

 **Name of the Vulnerability:** SSH Terrapin Prefix Truncation Weakness
   Severity level: Medium
 **Description:** The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness known as Terrapin. This can allow a remote, man-in-the-middle attacker to bypass integrity checks and downgrade the connection's security.
 **Solution:** Contact the vendor for an update with the strict key exchange countermeasures or disable the affected algorithms.

b.**Port 3389:**

   ![image](https://github.com/user-attachments/assets/cd7dd351-2426-4922-8171-f6ccd4f42308)

   ![image](https://github.com/user-attachments/assets/9971715e-6794-48fb-b1c3-682fe985d4aa)

   We can observe four different types of vulnerabilities in this port.

 **Name of the Vulnerability:** Remote Desktop Protocol Server Man-in-the-Middle Weakness.                           
   Severity level: Medium
 **Description:** The remote version of the Remote Desktop Protocol Server (Terminal Service) is vulnerable to a man-in-the-middle (MiTM) attack. The RDP client makes no effort to validate the identity of the server when setting up encryption. An attacker with the ability to intercept traffic from the RDP server can establish encryption with the client and server 
   without being detected. A MiTM attack of this nature would allow the attacker to obtain any sensitive information transmitted, including authentication credentials.
 **Solution:** Force the use of SSL as a transport layer for this service if supported, On Microsoft Windows operating systems, select the 'Allow connections only from computers running Remote Desktop with Network Level Authentication' setting if it is available.

 **Name of the Vulnerability:** SSL Anonymous Cipher Suites Supported
   Severity level: Medium
 **Description:**  The remote host supports the use of anonymous SSL ciphers. While this enables an administrator to set up a service that encrypts traffic without having to generate and configure SSL certificates, it offers no way to verify the remote host's identity and renders the service vulnerable to a man-in-the-middle attack.
 **Solution:** Reconfigure the affected application, if possible, to avoid use of weak ciphers.

**Name of the Vulnerability:** SSL Certificate Cannot Be Trusted.
  Severity level: Medium
**Description:** The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below:
  First, the top of the certificate chain sent by the server might not be descended from a known public certificate authority.
  Second, the certificate chain may contain a certificate that is not valid at the time of the scan.
  Third, the certificate chain may contain a signature that either didn't match the certificate's information or could not be verified.
  If the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host.
**Solution:** Purchase or generate a proper SSL certificate for this service.

**Name of the Vulnerability:** SSL Self-Signed Certificate.
  Severity level: Medium
**Description:** The X.509 certificate chain for this service is not signed by a recognized certificate authority. If the remote host is a public host in production, this nullifies the use of SSL as anyone could establish a man-in-the-middle attack against the remote host.
**Solution:** Purchase or generate a proper SSL certificate for this service.

The Following actions are seen in the Remediations tab:
![image](https://github.com/user-attachments/assets/be473883-57da-48e1-ab29-b5e8c352f9a6)

**Conclusion:** Performed various types of scans using NMAP (network mapper) to gather information on ports, their state and services and the respective versions of services running on the target. 
  Conducted vulnerability scanning using NESSUS essentials to identify the threats or weaknesses on the hosts, within the target network that can be exploited, and gathered more information on the vulnerabilities that are identified on the open ports and solutions to be implemented.
 
















	

   




    






