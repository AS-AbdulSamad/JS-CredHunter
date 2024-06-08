# JS-CredHunter
JS-CredHunter is a specialized command-line tool crafted to empower penetration testers in swiftly uncovering potential security vulnerabilities by scrutinizing JavaScript files for sensitive information. By parsing JavaScript code, it assists in the identification of URLs, API endpoints, or other snippets that may inadvertently expose credentials or authentication tokens, thereby aiding in comprehensive security assessments and the fortification of systems against potential cyber threats.

## Features:
**Sensitive Data Detection:** Utilizes advanced algorithms to detect sensitive information such as passwords, API keys, and authentication tokens embedded within JavaScript files.
**Credentials Enumeration:** Scans for a wide range of credentials including usernames, passwords, access tokens, and secret keys that might be exposed in JavaScript code.

## Usage:
Create a folder containing all the js files.
Run the JS-CredHunter.py script with the path to the URL file as an argument. Example: python3 js-CredHunter.py <directory_path>
View the matched URLs grouped by keyword.

## Sample:
![image](https://github.com/AS-AbdulSamad/JS-CredHunter/assets/116205223/841bb9e2-6697-45a4-9796-bd8b5fb7d96e)

## Disclaimer:
JS-CredHunter is a utility developed by ABStronics for educational and informational purposes exclusively. While JS-CredHunter aims to assist users in identifying potential security risks within JavaScript files, it is imperative for users to uphold the security of their systems and networks. ABStronics disclaims any warranty regarding the accuracy, completeness, or efficacy of JS-CredHunter in detecting vulnerabilities or mitigating security threats. By utilizing JS-CredHunter, you acknowledge and accept that ABStronics shall not be held liable for any damages or losses arising from the utilization or misapplication of this tool.
