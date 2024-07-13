Black Diamond's Pen Tester Utility Suite
Black Diamond's Pen Tester Utility Suite is a comprehensive and versatile toolkit designed for cybersecurity professionals, ethical hackers, and penetration testers. This suite integrates multiple security analysis tools into a single, user-friendly graphical user interface (GUI) built with Python and PyQt5.

## Features and Capabilities

    
    WHOIS Lookup: Retrieve detailed information about domain registration.
    DNS Lookup: Perform DNS queries to gather information about domain name systems.
    Port Scan: Scan for open ports and running services on the target domain.
    Network Traffic Monitoring: Capture and analyze network traffic to and from the target domain.
    Web Scraper: Extract and analyze content from web pages.
    Metadata Extraction: Extract metadata from files to uncover hidden information.
    Vulnerabilities Scan: Identify common vulnerabilities in web applications.
    SQL Injection: Test for SQL injection vulnerabilities.
    JavaScript Injection: Test for cross-site scripting (XSS) vulnerabilities.
    Cookie Manipulation: Modify cookies to test for session handling vulnerabilities.
    Blockchain and Geolocation
    Blockchain Analysis: Analyze blockchain addresses and transactions.
    Geolocation Mapping: Geolocate addresses and visualize them on a map.
    Open Source Intelligence (OSINT)
    OSINT Integration: Scrape forums and websites for valuable information.


## Usage Guide

*** Step 1: Select Your Target ***
Begin by identifying the domain or IP address of your target. Enter this information in the respective fields of the WHOIS Lookup, DNS Lookup, and Port Scan tabs to gather basic information about the target.

Step 2: OSINT
Navigate to the OSINT Integration tab. Enter the URL of relevant forums or websites to scrape information. Use this data to gain insights into the target's digital footprint and potential vulnerabilities.

Step 3: Vulnerability Analysis
Move to the Vulnerabilities Scan tab. Enter the target's URL and perform a scan to identify common vulnerabilities. Use the SQL Injection and JavaScript Injection tabs to test for specific injection vulnerabilities.

Step 4: Web Scraping and Metadata Extraction
In the Web Scraper tab, enter the target's URL to extract and analyze web content. Use the Metadata Extraction tab to upload files and uncover hidden metadata that may contain valuable information.

Step 5: Network Traffic Monitoring
Use the Network Traffic tab to monitor and capture network traffic to and from the target. This can help identify suspicious activity and potential attack vectors.

Step 6: Blockchain and Geolocation Analysis
If applicable, use the Blockchain Analysis tab to investigate blockchain addresses and transactions associated with the target. Use the Geolocation Mapping tab to visualize physical addresses related to the target.

Step 7: Reporting and Documentation
Document your findings and generate reports for each step. This will help in providing a comprehensive overview of the target's security posture and potential vulnerabilities.

Installation
To install and run Black Diamond's Pen Tester Utility Suite, follow these steps:

Clone the Repository:
git clone https://github.com/Mcleese902/BlackDiamonds-PenTesters-Utility-Suite.git

cd BlackDiamonds-PenTesters-Utility-Suite

Install Dependencies:
pip install -r requirements.txt

Run the Application:
python main.py


*** Contribution ***
Contributions are welcome! Please fork the repository and submit pull requests with detailed descriptions of your changes.

License
This project is licensed under the MIT License.



### UPDATE
Black Diamond's Pen Tester Utility Suite is in the early stages of development, and we are actively working on improving and expanding its features. Our goal is to create a comprehensive and robust penetration testing toolkit that meets the needs of both novice and experienced cybersecurity professionals. Below are some major upgrades we plan to implement for each feature already included in the suite:

#### Planned Upgrades

### Network and Domain Analysis
- **WHOIS Lookup**:
  - **Upgrade**: Implement a caching mechanism to store recent WHOIS lookup results to reduce redundant queries and improve performance.
  - **Feature Addition**: Add support for bulk WHOIS lookups for multiple domains at once.

- **DNS Lookup**:
  - **Upgrade**: Enhance the DNS lookup feature to include reverse DNS lookups.
  - **Feature Addition**: Integrate DNSSEC validation to verify the integrity and authenticity of DNS responses.

- **Port Scan**:
  - **Upgrade**: Improve the scanning speed and accuracy by leveraging advanced port scanning techniques.
  - **Feature Addition**: Add the ability to customize scan parameters such as scan type, port range, and timeout.

- **Network Traffic Monitoring**:
  - **Upgrade**: Implement real-time traffic analysis with graphical visualization of network data.
  - **Feature Addition**: Add packet capture filtering options to focus on specific types of traffic or protocols.

### Web and Application Security
- **Web Scraper**:
  - **Upgrade**: Enhance the web scraper to handle dynamic content and JavaScript-rendered pages using headless browser automation.
  - **Feature Addition**: Add functionality to identify and extract specific types of data such as email addresses, phone numbers, and URLs.

- **Metadata Extraction**:
  - **Upgrade**: Improve the extraction speed and accuracy by supporting additional file formats.
  - **Feature Addition**: Implement automatic detection and extraction of sensitive information from metadata.

- **Vulnerabilities Scan**:
  - **Upgrade**: Integrate with additional vulnerability databases to provide more comprehensive scan results.
  - **Feature Addition**: Add automated vulnerability remediation suggestions based on scan results.

- **SQL Injection**:
  - **Upgrade**: Enhance the SQL injection module to support more advanced injection techniques and bypass methods.
  - **Feature Addition**: Add automated detection of common SQL injection payloads in web traffic.

- **JavaScript Injection**:
  - **Upgrade**: Improve the injection detection rate by supporting a wider range of XSS vectors and payloads.
  - **Feature Addition**: Implement a sandbox environment to safely test JavaScript injection payloads.

- **Cookie Manipulation**:
  - **Upgrade**: Enhance the cookie manipulation module to support session fixation and hijacking tests.
  - **Feature Addition**: Add the ability to automate the testing of HTTP-only and secure cookie flags.

### Blockchain and Geolocation
- **Blockchain Analysis**:
  - **Upgrade**: Improve the blockchain analysis speed and accuracy by integrating with multiple blockchain explorers.
  - **Feature Addition**: Add the ability to trace and visualize blockchain transaction flows.

- **Geolocation Mapping**:
  - **Upgrade**: Enhance the geolocation mapping feature to support additional geocoding services.
  - **Feature Addition**: Implement interactive map visualization with clustering and heatmap support.

### Open Source Intelligence (OSINT)
- **OSINT Integration**:
  - **Upgrade**: Improve the OSINT scraping capabilities to handle more complex web structures and anti-scraping mechanisms.
  - **Feature Addition**: Add support for automated sentiment analysis and entity recognition in scraped data.

### Overall Enhancements
- **User Interface**:
  - **Upgrade**: Redesign the user interface to improve usability and accessibility.
  - **Feature Addition**: Implement dark mode and customizable themes.

- **Performance**:
  - **Upgrade**: Optimize the performance of all modules to handle larger datasets and more concurrent operations.
  - **Feature Addition**: Add multi-threading and parallel processing support for intensive tasks.

We appreciate your support and feedback as we continue to develop and enhance Black Diamond's Pen Tester Utility Suite. Stay tuned for more updates and improvements!
