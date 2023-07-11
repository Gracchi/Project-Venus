#!/usr/bin/python3

#Pythagoras - all is numbers


import requests
import pyfiglet as pf

print (pf.figlet_format("Venus-Pythagoras", font="bubble", justify="center")

VIRUSTOTAL_API_KEY = 'Paste Your VirusTotal_API_KEY Here'
HYBRIDANALYSIS_API_KEY = 'Paste Your HybridAnalysis_API_KEY Here'

def check_file_malware(file_path):
    # Uploading the provided file to VT to be analysed 
    vt_url = f'https://www.virustotal.com/vtapi/v2/file/scan'
    vt_params = {'apikey': VIRUSTOTAL_API_KEY}
    with open(file_path, 'rb') as file:
        response = requests.post(vt_url, files={'file': file}, params=vt_params)
    response.raise_for_status()
    vt_report_url = response.json()['permalink']

    # Uploading the provided file to HA to be analysed
    ha_url = f'https://www.hybrid-analysis.com/api/v2/quick-scan/file'
    ha_headers = {'api-key': HYBRIDANALYSIS_API_KEY}
    ha_params = {'scan_type': 'all'}
    response = requests.post(ha_url, headers=ha_headers, files={'file': file}, params=ha_params)
    response.raise_for_status()
    ha_report_url = response.json()['result_url']

    return vt_report_url, ha_report_url

# Prompt the user to enter the file path
file_path = input("Enter the path to the file: ")

# Call the function to check the file for malware
vt_report_url, ha_report_url = check_file_malware(file_path)

print("VirusTotal Report:", vt_report_url)
print("Hybrid Analysis Report:", ha_report_url)
