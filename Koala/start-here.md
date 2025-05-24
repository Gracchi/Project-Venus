Koala PS script that is simple yet powerful DFIR script for comprehensive Windows 10/11 and Windows Server 2022 for a quick system analysis, this script collects extensive forensic information including:

•	User Analysis: Local accounts, creation details, current sessions
•	System Status: Uptime, boot time, OS details, memory usage
•	Network Intelligence: Connectivity status, active connections, DNS configuration
•	Security Analysis: Recent security events, suspicious processes/services
•	Artifact Collection: Recent file activity, startup programs, USB history
•	Browser Forensics: Chrome/Edge history file locations and timestamps
•	Process Analysis: Running processes sorted by CPU usage
•	Installation History: Recently installed software

Usage:

.\koala.ps1 -OutputPath "C:\Investigation"
The report will be a text file, created with the date and time format.

![](https://github.com/Gracchi/Project-Venus/blob/main/docs/Koala1.png)

Koala will automatically:

•	Creates timestamped reports
•	Checks for administrator privileges
•	Handles errors gracefully
•	Provides both console output and file logging
•	Focuses on IOCs and suspicious activities

Koala Forensic Value:

•	Timeline reconstruction capabilities
•	Network compromise indicators
•	User activity analysis
•	System integrity checks
•	Artifact preservation paths


The script is designed to be run quickly on live systems while preserving evidence integrity as much as possible, and providing actionable intelligence for your DFIR investigation.

![](https://github.com/Gracchi/Project-Venus/blob/main/docs/Koala2.png)
