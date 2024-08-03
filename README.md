# Developers-Are-Victims-Too-A-Comprehensive-Analysis-of-The-VS-Code-Extension-Ecosystem

### This repository contains the analysis artifacts of the submitted paper titled with "Developers Are Victims Too : A Comprehensive Analysis of The VS Code Extension Ecosystem" for the ICSE 2025, 47th International Conference on Software Engineering.

##### This table contains a summary of the details about each folder in the provided artifacts repository.

|File Name (with file path)|Content Description|
| :- | :- |
|filtered\_extension\_details.json|Basic details about the identified extensions on the VS Code Extension Marketplace that are either malicious, vulnerable, or suspicious.|
|API Analysis/Category wise API calls.xlsx|Analysis of all extensions on how developers used API methods to develop the extensions, based on the extension category as listed in the extension manifest file.|
|API Analysis/settings.json file updates.xlsx|Analysis of extensions that modify the settings.json file of VSCode during runtime.|
|API Analysis/NODE\_TLS\_REJECT\_UNAUTHORIZED.xlsx|Analysis of extensions that degrade the TLS/SSL certificates while the extension is running or has started to run.|
|API Analysis/suspicious\_extensions\_critical\_file\_access.xlsx|This file contains the results of the analysis on critical file access, indicating whether an extension accesses critical files in the operating system.|
|Dynamic Analysis (Verified behavior with manual execution)/ICSE Dynamic Analysis - Report.xlsx|This file contains the identified suspicious extensions details and summary of their behaviors.|
|Dynamic Analysis (Verified behavior with manual execution)/ Logs |<p>This folder contains logs and flows related to several suspicious extensions.</p><p></p><p>Note that we have not included all the logs and flow files to maintain the anonymity of the authors, as these files contain information that could reveal their identities. The steps to generate the flows and logs are provided later in this document, should you need to create them.</p>|
|Instrumented VSCode|VSCode application which we instrumented to find extensions' API usages in the VSCode extension API interface. Currently, we only support macOS and Windows applications.|
|Manifest File Analysis/Extension Dependency Analysis/extension\_dependency\_list.json|A JSON file containing extension details (extension ID, name, and dependency extension names in the format publisher:extension name) on the extension and the dependent extensions that are required to be installed prior to the given extension. The JSON file contains an array of Python dictionaries with the above details.|
|Manifest File Analysis/Extension Dependency Analysis/extension\_pack\_dependency\_list.json|A JSON file containing extension details (extension ID, name, and the set of other extensions to be installed with the given extension, listed in the format publisher:extension name). The JSON file contains an array of Python dictionaries with the above details.|
|Manifest File Analysis/extension\_code\_repository\_data.json|This file contains details about each extension’s code repository.|
|Manifest File Analysis/manifest\_file\_capabilities\_access\_list.json|This file contains details about extensions that use the `capabilities` option in the manifest file to access the VSCode runtime in untrusted mode.|
|Manifest File Analysis/possible\_external\_link\_creating\_npm\_packages.xlsx|Identified npm packages used in VSCode extension development that may create external connections via the internet.|
|Radar Reports/extension\_dns\_report.json|This file contains the identified extensions that have external links associated with them.|
|Radar Reports/radar\_report\_http\_urls.json|This file contains the Cloudflare Radar report for the HTTP links identified in each extension, as listed in the `Radar Reports/extension\_dns\_report.json` report.|
|Radar Reports/radar\_report\_https\_urls.json|This file contains the Cloudflare Radar report for the HTTPS links identified in each extension, as listed in the `Radar Reports/extension\_dns\_report.json` report.|
|Reported Cases/Dynamic Testing Reported Cases|We reported the identified threats to the VSCode Marketplace, requesting their removal. This folder contains the report we provided concerning the identified threats discovered during our dynamic testing, which involved manually testing the extensions installed in our instrumented VSCode application.|
|Reported Cases/Extension Dependency Installation Cases|We reported the identified threats to the VSCode Marketplace, requesting their removal. This folder contains extensions that depend on such malicious or harmful extensions and will install these problematic extensions along with them.|
|Reported Cases/Static Analysis Reported Cases|We reported identified threats to the VSCode Marketplace, requesting their removal. This folder contains the reports we sent to the VSCode Marketplace team regarding the vulnerable packages used in the extension development process, which are packaged with the extensions without addressing those vulnerabilities.|
|Reported Cases/VT Reported Cases|We reported identified threats to the VSCode Marketplace, requesting their removal. This folder contains screenshots of harmful VSCode extensions that were submitted to VirusTotal and returned with 4 or more VirusTotal engines indicating that the extensions are harmful.|
|Reported Cases/Action Taken Cases|This document contains the extensions that were removed from the marketplace after we reported their malicious behavior to the VSCode Marketplace team.|
|RetireJs Analysis/retirejs\_vulnerability\_report.json|A JSON file containing extension details along with the vulnerable packages used in the extension's development and their associated vulnerabilities with CVE numbers. The JSON file is formatted with the extension ID as the key to hold these details.|
|RetireJs Analysis/CVEs and Details|A folder containing summarized CVE details along with the npm package names. Note that these are raw data files, which include download counts for the extensions but lack keys to identify each extension’s download count.|
|RetireJs Analysis/POC-on-cve-exploits.zip|We verified whether the high CVEs could be exploited. This sample extension addresses the high CVEs we identified based on RetireJS analysis.|
|VirusTotal Analysis/vt\_analysis\_filtered.xlsx|This file contains details about the identified extensions based on VirusTotal analysis. The document has two sheets: one for the VSIX file itself and another for the URLs that are benign and used in the extensions for external communications.|
|VSIX Files|A ZIP file containing the list of extensions selected for dynamic analysis.|


##### How to Work with Instrumented VSCode

1. Install the Application:
   - Download and install the relevant application for either Windows or macOS.
1. Start the Application:
   - Launch the application and grant full permission to trust the workspace.
1. Install Extensions:
   - Manually download the extension(s) from the marketplace and install them via a .vsix file, as access to the extension marketplace is restricted in this version.
1. Monitor Network Traffic (if required):
   - Install mitmproxy to monitor external access.
   - Configure the proxy settings in the instrumented VSCode.
1. View API Access Logs:
   - Access each extension's API access logs in the /tmp/extensionLogs/ folder. Log files are created for each installed extension.
   - **Note:** On a Windows machine, the temporary folder will be located in the disk partition where the application is installed.
