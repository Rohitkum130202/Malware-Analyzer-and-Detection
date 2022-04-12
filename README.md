
Introduction:

PBL PROJECT CSP_251
Created by: ANMOL GARG,Prakash Chand Thakuri,Rohit Kumar,Shivam Singh Panwar
B-TEch 2nd Year SEM-3
CSG
G2
Submitted to: PREETI MAM
Malware Analysis Using Python Script v1.1
                                          # MAlWARE ANALYZER (STATIC)
# Description

This is a portable script written in python used for "Static Analysis" of malwares. Focus on malware PE Headers, Strings, Image Type, MD5 Hash, VirusTotal Analysis. You can skip VirusTotal API Key if dont want to upload your sample on VirusTotal. Supported wherever python is installed (Tested on Linux, Windows). This tool will generate four output files in the same folder as the script: Strings.txt for the extracted strings, PE Analysis.txt for PE headers, VT Basic Scan.txt and VT Scan.txt for virus total analysis.  

# What is New

You have to enter your Virus Total API Key inside the program at on line number 51.

           key="" # <= Here Enter Your VT API Key between double quotes


Now this tool v1.1 is able to do static malware anaysis in a very deep way, the two new more features has been added.

           1] Header Members
           
                      a] IMAGE_DOS_HEADER
                      b] IMAGE_NT_HEADERS
                      
           2] Optional Headers
           
Now it is able to perform full VT Analysis and store the output as VT Scan.csv which contain how many AV (Name of AV eg Sophos, symantec. etc) are able to detected malware with the respectively malware name. 

# Pre-Requesites

Install the following libraries: requests, pefile and pywin32.

pip install -r requirements.txt

# Usage

tool.py

# Example or Output

    =============Malware Analysis Using Python Script========

This tool will scan the windows EXE files and prepare the following reports:

1.Basic Analysis

2.Portable Executable Analysis

3.DLLS Reports

Enter path of the file  which you want to scan :-

