# Python Security & DFIR Toolkit

A Python-based toolkit that combines security monitoring, network analysis, file integrity checking, and digital forensics tasks in one interactive program.

## Features

The toolkit can:

1. Analyze security log files.
2. Search logs for specific keywords.
3. Extract and count IP addresses.
4. Export matching log entries.
5. Check multiple HTTP endpoints.
6. Read a field from a JSON API.
7. Analyze network-traffic CSV files.
8. Inspect running system processes.
9. Calculate and verify SHA-256 file hashes.
10. Analyze evidence folders.
11. Build file timelines.
12. Find recently modified and largest files.
13. Detect duplicate files using hashes.
14. Analyze forensic artifact CSV files.
15. Export artifact summaries.
16. Scan common TCP ports on an authorized host.
17. Generate a complete DFIR triage report.

## Requirements

- Python 3
- requests
- psutil

Install the required packages with:

```bash
pip install -r requirements.txt


How to Run

Open a terminal in the project folder and run:

python triage.py

The interactive menu will appear. Select an option and enter the requested file path, folder path, URL, or authorized host.

Portable Paths

The program supports:

* Relative paths for files located inside the project folder.
* Complete paths for files located elsewhere on the computer.

Example relative path:

sample_artifacts.csv

Example complete Windows path:

C:\Users\User\Downloads\evidence.csv

Output Files

Depending on the selected option, the toolkit can create output files such as:

* Filtered log files.
* Forensic artifact summary CSV files.
* A complete security and DFIR report displayed in the terminal.

Example output files are included to demonstrate the program results.

Security Notice

Only scan systems and hosts that you own or have explicit permission to test. Unauthorized port scanning may violate laws, policies, or network rules.

Course Work

This project combines practical exercises from three training days covering:

* Python fundamentals for cybersecurity.
* Log and network-traffic analysis.
* HTTP requests and JSON APIs.
* Process inspection and file hashing.
* Digital forensics and evidence analysis.
* Reporting and command-line interaction.