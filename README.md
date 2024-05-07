# CVE Fetcher: Automation System Documentation
- Creator: Shavit Luzon
- GitHub: @ShaCode256
- Check out more cool software! https://github.com/shaCode256

## Purpose
The purpose of this system is to assess software product vulnerabilities using data from reliable sources like the National Vulnerability Database (NVD). By inputting product Common Platform Enumeration (CPE) and versions, users can generate readable PDF reports that visualize research findings regarding associated Common Vulnerabilities and Exposures (CVEs).

### Objectives:
- Vulnerability Assessment
- Enhancing Security
- Data Integrity and Reliability
- User-Friendly Interface
- Automated Report Generation

## Overview
This document provides detailed information about the automation script designed to interact with cybersecurity-related APIs, retrieve relevant data, perform analyses, and generate reports. The script aims to enhance security by identifying potential threats and vulnerabilities based on data obtained from sources such as the CVE (Common Vulnerabilities and Exposures) database API.

## Design Choices

### Security Controls
- **Input Validation:** Ensures user-provided data adheres to the expected format for Common Platform Enumeration (CPE) strings using regular expressions. This validation ensures data integrity.
- **Error Handling:** Implements robust error handling mechanisms to prevent information leakage through error messages.
- **AES Encryption:** Generates a unique key and supplies methods to encrypt and decrypt analysis results.
### Implementation Specifics
- **API Integration:** Utilizes the CVE database API to retrieve vulnerability data.
- **Data Analysis:** Extracts vulnerability information, including CVE ID, description, and affected products. Utilizes comparison techniques and visualization tools to identify patterns, trends, or suspicious activities in the data
- **Reporting:** Generates PDF weakness reports containing CVE details and visualizations depicting affected product counts for each CVE.
- **Visualization:** Utilizes Matplotlib for creating bar charts to visualize affected product counts.
- **Severity Analysis:** Classifies vulnerabilities into critical, high, medium, and low severity levels based on CVSS scores.
- **Encryption of Reports:** Implements AES encryption with a provided key to protect sensitive information in reports.

## Unit Testing
Unit tests are provided within the script file to ensure correctness and functionality.

## Prerequisites
- Python 3.x installed on your system.
- Required libraries installed.
  list is supplied "requirements.txt".
  run "pip install -r"


## Running the Script
1. Download the CVE Automation folder.
2. Navigate to the directory containing the script files.
3. Run unit tests: `python test.py`.
4. Run the automation script: `python main.py`.

## Conclusion
The automation script provides a comprehensive solution for retrieving, analyzing, and reporting vulnerability data from cybersecurity-related APIs. Its integration with severity analysis features enhances its utility in identifying and prioritizing vulnerabilities. The updated documentation facilitates easy deployment, usage, and maintenance, ensuring its relevance in enhancing organizational security posture.
