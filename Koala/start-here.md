**Koala PS script that is simple yet powerful DFIR script for comprehensive Windows 10/11 and Windows Server 2022 for a quick system analysis, this script collects extensive forensic information including:**
<br>
•	User Analysis: Local accounts, creation details, current sessions
<br>
•	System Status: Uptime, boot time, OS details, memory usage
<br>
•	Network Intelligence: Connectivity status, active connections, DNS configuration
<br>
•	Security Analysis: Recent security events, suspicious processes/services
<br>
•	Artifact Collection: Recent file activity, startup programs, USB history
<br>
•	Browser Forensics: Chrome/Edge history file locations and timestamps
<br>
•	Process Analysis: Running processes sorted by CPU usage
<br>
•	Installation History: Recently installed software
<br>
<br>

Usage:
<br>
.\koala.ps1 -OutputPath "C:\Investigation"
<br>
The report will be a text file, created with the date and time format.
<br>
![](https://github.com/Gracchi/Project-Venus/blob/main/docs/Koala1.png)
<br>
<br>
Koala will automatically:
<br>
•	Creates timestamped reports
<br>
•	Checks for administrator privileges
<br>
•	Handles errors gracefully
<br>
•	Provides both console output and file logging
<br>
•	Focuses on IOCs and suspicious activities
<br>
<br>
Koala Forensic Value:
<br>
•	Timeline reconstruction capabilities
<br>
•	Network compromise indicators
<br>
•	User activity analysis
<br>
•	System integrity checks
<br>
•	Artifact preservation paths
<br>
<br>

The script is designed to be run quickly on live systems while preserving evidence integrity as much as possible, and providing actionable intelligence for your DFIR investigation.
<br>
![](https://github.com/Gracchi/Project-Venus/blob/main/docs/Koala2.png)
