"""Python Security & DFIR Toolkit."""  # Describe the project

import os  # Work with files, folders, paths, and operating-system features
import sys  # Read command-line arguments and Python system information
import time  # Work with timestamps and calculate file ages
import re  # Search text using regular expressions
import csv  # Read and write CSV files
import hashlib  # Calculate secure file hashes such as SHA-256
import socket  # Create network connections and check ports
import subprocess  # Run safe operating-system commands
from collections import Counter  # Count repeated values efficiently

import requests  # Send HTTP requests to websites and APIs

PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__))  # Store the folder containing this script


def resolve_path(path):  # Define a function that resolves portable paths
    """Support both relative and complete file paths."""  # Explain its purpose

    clean_path = path.strip().strip('"')  # Remove spaces and quotation marks

    if os.path.isabs(clean_path):  # Check whether the user entered a complete path
        return os.path.normpath(clean_path)  # Return the complete normalized path

    return os.path.normpath(  # Build a path relative to this script 
        os.path.join(PROJECT_FOLDER, clean_path)  # Join the script folder and supplied path
    )


def find_lines(filename, keyword):  # Define a function for filtering log lines
    """Return lines containing a specified keyword."""  # Explain the function
    matches = []  # Create an empty list for matching lines

    try:  # Attempt to open and process the supplied file
        with open(filename, "r") as file:  # Open the file in reading mode
            for line in file:  # Read the file one line at a time
                clean_line = line.strip()  # Remove surrounding whitespace

                if keyword.lower() in clean_line.lower():  # Check without case sensitivity
                    matches.append(clean_line)  # Save the matching line

    except FileNotFoundError:  # Handle a missing input file
        print(f"Error: '{filename}' was not found.")  # Display a clear error message

    return matches  # Return all matching lines


def count_ip_addresses(lines):  # Define a function for counting IP addresses
    """Extract IP addresses and count their occurrences."""  # Explain the function
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Define an IPv4-shaped pattern
    ip_addresses = []  # Create an empty list for extracted addresses

    for line in lines:  # Examine every supplied log line
        found_ips = re.findall(ip_pattern, line)  # Extract every IP-shaped value
        ip_addresses.extend(found_ips)  # Add the extracted addresses to the main list

    return Counter(ip_addresses)  # Return each IP address and its occurrence count


def analyze_log(filename, keyword="ERROR"):  # Define the main log-analysis function
    """Analyze log levels, keywords, failed logins, and IP addresses."""  # Explain its purpose
    filename = resolve_path(filename)   #Resolve the log path on any computer 

    if not os.path.isfile(filename):  # Check whether the supplied log file exists
        print(f"Error: '{filename}' is not a valid file.")  # Report the missing file
        return {}  # Return an empty result instead of crashing

    with open(filename, "r") as file:  # Open the log file in reading mode
        all_lines = [line.strip() for line in file]  # Read and clean every log line

    level_counts = Counter()  # Create a counter for INFO, WARNING, and ERROR

    for line in all_lines:  # Examine every line in the log file
        fields = line.split()  # Split the line into separate fields

        for level in ("INFO", "WARNING", "ERROR"):  # Check each supported log level
            if level in fields:  # Determine whether the level exists in this line
                level_counts[level] += 1  # Increase that level's count

    keyword_matches = find_lines(filename, keyword)  # Find lines containing the selected keyword
    failed_lines = find_lines(filename, "Failed password")  # Find failed-login entries
    failed_ip_counts = count_ip_addresses(failed_lines)  # Count IPs behind failed logins
    all_ip_counts = count_ip_addresses(all_lines)  # Count every IP found in the file
    unique_ips = set(all_ip_counts.keys())  # Keep one copy of each discovered IP address

    return {  # Return all log-analysis results together
        "total_lines": len(all_lines),  # Store the total number of log lines
        "level_counts": level_counts,  # Store counts for each log level
        "keyword": keyword,  # Store the keyword used during analysis
        "keyword_matches": keyword_matches,  # Store matching log lines
        "failed_login_count": len(failed_lines),  # Store the failed-login total
        "top_failed_ips": failed_ip_counts.most_common(3),  # Store the top three offending IPs
        "unique_ips": sorted(unique_ips),  # Store unique IPs in alphabetical order
    }

def write_filtered_log(input_path, output_path, keyword):  # Define a log-export function
    """Write matching log lines to a separate output file."""  # Explain its purpose
    input_path = resolve_path(input_path)  # Resolve the input path on any computer
    output_path = resolve_path(output_path)  # Resolve the output path on any computer

    if not os.path.isfile(input_path):  # Validate the source log file
        print(f"Error: '{input_path}' is not a valid file.")  # Report an invalid path
        return 0  # Return zero because no lines were written

    matching_lines = find_lines(input_path, keyword)  # Collect lines containing the keyword

    with open(output_path, "w") as output_file:  # Create or overwrite the output file    
         for line in matching_lines:  # Loop over every matching line
            output_file.write(line + "\n")  # Write the line followed by a newline

    return len(matching_lines)  # Return the number of exported lines

def check_url(url):  # Define a function that checks one HTTP endpoint
    """Return useful information about an HTTP response."""  # Explain its purpose

    try:  # Attempt to contact the supplied URL
        response = requests.get(url, timeout=5)  # Send a GET request with a five-second timeout

        return {  # Return the important response information
            "url": url,  # Store the checked URL
            "status_code": response.status_code,  # Store the HTTP status code
            "content_type": response.headers.get("Content-Type", "Unknown"),  # Read the content type
            "body_preview": response.text[:100],  # Keep the first 100 response characters
            "is_successful": response.status_code == 200,  # Check whether the response is HTTP 200
        }

    except requests.RequestException as error:  # Catch connection and HTTP request problems
        return {  # Return an error result instead of crashing
            "url": url,  # Store the URL that failed
            "error": str(error),  # Store the error message
            "is_successful": False,  # Mark the request as unsuccessful
        }

def check_multiple_urls(urls):  # Define a function for checking several URLs
    """Check multiple URLs and return all response results."""  # Explain its purpose
    results = []  # Create an empty list for the HTTP results

    for url in urls:  # Loop over every supplied URL
            result = check_url(url)  # Check the current URL using the previous function
            results.append(result)  # Add its result to the results list
   
    return results  # Return the complete list of HTTP results

def fetch_json_field(url, field_name):  # Define a function for reading one JSON field
    """Fetch JSON data and return the requested field value."""  # Explain its purpose

    try:  # Attempt to contact and read the endpoint
        response = requests.get(url, timeout=5)  # Send an HTTP GET request
        response.raise_for_status()  # Raise an error for unsuccessful HTTP responses
        data = response.json()  # Convert the JSON response into a Python dictionary
        return data.get(field_name)  # Return the requested field or None if it is absent

    except (requests.RequestException, ValueError) as error:  # Handle HTTP or JSON errors
        print(f"JSON request error: {error}")  # Display a clear error message
        return None  # Return no value when the request fails

def analyze_traffic_csv(filename, suspicious_ports=None):  # Define the traffic-analysis function
    """Analyze ports, protocols, transferred bytes, and suspicious traffic."""  # Explain its purpose

    filename = resolve_path(filename)  # Resolve the traffic CSV path on any computer

    if suspicious_ports is None:  # Check whether a custom watchlist was supplied
        suspicious_ports = {"4444", "31337"}  # Use the course watchlist by default

    if not os.path.isfile(filename):  # Validate the supplied CSV path
        print(f"Error: '{filename}' is not a valid file.")  # Report an invalid file
        return {}  # Return an empty result instead of crashing

    port_counts = Counter()  # Count connections made to each destination port
    protocol_counts = Counter()  # Count the use of each network protocol
    bytes_by_ip = Counter()  # Add the transferred bytes for each source IP
    suspicious_rows = []  # Store traffic rows matching the port watchlist

    try:  # Attempt to read and analyze the CSV file
        with open(filename, "r", newline="") as file:  # Open the CSV in reading mode
            reader = csv.DictReader(file)  # Convert each CSV row into a dictionary

            for row in reader:  # Process every network-traffic row
                port = row["dst_port"]  # Read the destination port
                protocol = row["protocol"]  # Read the network protocol
                source_ip = row["src_ip"]  # Read the source IP address
                transferred_bytes = int(row["bytes"])  # Convert the byte value to an integer

                port_counts[port] += 1  # Increase the connection count for this port
                protocol_counts[protocol] += 1  # Increase the count for this protocol
                bytes_by_ip[source_ip] += transferred_bytes  # Add bytes to this IP's total

                if port in suspicious_ports:  # Check whether the port is suspicious
                    suspicious_rows.append(row)  # Save the complete suspicious traffic row

    except (OSError, KeyError, ValueError, csv.Error) as error:  # Handle file or CSV problems
        print(f"Traffic analysis error: {error}")  # Display a clear error message
        return {}  # Return an empty result when analysis fails

    top_talker = bytes_by_ip.most_common(1)  # Find the IP that transferred the most bytes

    return {  # Return all network-analysis results together
        "top_ports": port_counts.most_common(5),  # Store the five most-used ports
        "protocol_counts": protocol_counts,  # Store the protocol totals
        "suspicious_traffic": suspicious_rows,  # Store traffic matching the watchlist
        "bytes_by_ip": bytes_by_ip,  # Store total bytes transferred by every IP
        "top_talker": top_talker[0] if top_talker else None,  # Store the busiest IP
    }

def check_processes(limit=5):  # Define a function that lists running processes
    """Return a small sample of running process names and IDs."""  # Explain its purpose

    try:  # Attempt to use the cross-platform psutil library
        import psutil  # Import psutil only when this function is called
        processes = []  # Create an empty list for process information

        for process in psutil.process_iter(["pid", "name"]):  # Read process IDs and names safely
            process_info = process.info  # Get the current process information
            processes.append(process_info)  # Add the process to the result list

            if len(processes) >= limit:  # Stop after reaching the requested limit
                break  # Exit the process loop

        return processes  # Return the collected process dictionaries

    except ImportError:  # Use a system command if psutil is unavailable
        if os.name == "nt":  # Check whether Python is running on Windows
            command = ["tasklist"]  # Select the Windows process-listing command
        else:  # Handle Linux and macOS systems
            command = ["ps", "aux"]  # Select the Unix process-listing command

        result = subprocess.run(  # Run the selected read-only command
            command,  # Supply the command and its arguments
            capture_output=True,  # Save the command output
            text=True,  # Return the output as text
            check=False,  # Prevent a command error from crashing the program
        )

        return result.stdout.splitlines()[:limit]  # Return only the requested number of lines

def get_current_user():  # Define a function that runs a safe system command
    """Return the name of the current operating-system user."""  # Explain its purpose

    result = subprocess.run(  # Run the read-only whoami command
        ["whoami"],  # Supply the fixed safe command
        capture_output=True,  # Capture the command output
        text=True,  # Return the output as a string
        check=False,  # Prevent command failure from crashing the program
    )

    if result.returncode == 0:  # Check whether the command completed successfully
        return result.stdout.strip()  # Return the cleaned username

    return f"Command error: {result.stderr.strip()}"  # Return a readable error message


def calculate_sha256(file_path):  # Define a function that hashes one file
    """Calculate and return the SHA-256 hash of a file."""  # Explain its purpose
    file_path = resolve_path(file_path)  # Resolve the file path on any computer

    if not os.path.isfile(file_path):  # Check whether the supplied path is a file
        print(f"Error: '{file_path}' is not a valid file.")  # Report an invalid path
        return None  # Return no hash when the file is unavailable

    with open(file_path, "rb") as file:  # Open the file in binary reading mode
        file_content = file.read()  # Read the complete file content as bytes
        digest = hashlib.sha256(file_content).hexdigest()  # Calculate the SHA-256 digest

    return digest  # Return the complete hexadecimal hash


def verify_file_hash(file_path, expected_hash):  # Define a file-integrity verification function
    """Compare a file's current hash with an expected SHA-256 hash."""  # Explain its purpose
    current_hash = calculate_sha256(file_path)  # Calculate the file's current hash

    if current_hash is None:  # Check whether hash calculation failed
        return {  # Return a clear failed-verification result
            "file": file_path,  # Store the supplied file path
            "current_hash": None,  # Record that no current hash was calculated
            "expected_hash": expected_hash,  # Store the expected hash
            "match": False,  # Mark the verification as unsuccessful
        }

    hashes_match = current_hash.lower() == expected_hash.lower()  # Compare hashes safely

    return {  # Return all verification information together
        "file": file_path,  # Store the checked file path
        "current_hash": current_hash,  # Store the calculated hash
        "expected_hash": expected_hash,  # Store the known-good hash
        "match": hashes_match,  # Store whether the two hashes match
    }


def hash_directory(folder_path):  # Define a function that hashes every file in a folder
    """Return a dictionary containing each filename and its SHA-256 hash."""  # Explain its purpose
    folder_path = resolve_path(folder_path)  # Resolve the folder path on any computer

    if not os.path.isdir(folder_path):  # Check whether the supplied path is a directory
        print(f"Error: '{folder_path}' is not a valid folder.")  # Report an invalid folder
        return {}  # Return an empty dictionary instead of crashing

    file_hashes = {}  # Create a dictionary for filename-to-hash mappings

    for filename in os.listdir(folder_path):  # Loop over every item in the folder
        file_path = os.path.join(folder_path, filename)  # Build the complete file path

        if os.path.isfile(file_path):  # Process files and ignore subfolders
            digest = calculate_sha256(file_path)  # Calculate the current file's hash

            if digest is not None:  # Confirm that hash calculation succeeded
                file_hashes[filename] = digest  # Store the filename and its hash

    return file_hashes  # Return all calculated hashes

def verify_directory_hashes(folder_path, expected_hashes):  # Verify multiple known file hashes
    """Compare directory files against expected SHA-256 hashes."""  # Explain its purpose
    current_hashes = hash_directory(folder_path)  # Calculate current hashes
    results = {}  # Create a dictionary for verification results

    for filename, expected_hash in expected_hashes.items():  # Check every expected file
        current_hash = current_hashes.get(filename)  # Get its current hash

        if current_hash is None:  # Check whether the file is missing
            status = "missing"  # Mark the file as missing
        elif current_hash.lower() == expected_hash.lower():  # Compare both hashes
            status = "match"  # Mark the file as unchanged
        else:  # Handle a changed file
            status = "mismatch"  # Mark the file as modified

        results[filename] = {  # Store this file's verification result
            "current_hash": current_hash,  # Store its current hash
            "expected_hash": expected_hash,  # Store its expected hash
            "status": status,  # Store the final verification status
        }

    return results  # Return all directory verification results


def find_duplicate_files(folder_path):  # Define a function for detecting duplicate files
    """Return hashes shared by more than one filename."""  # Explain its purpose
    file_hashes = hash_directory(folder_path)  # Calculate every file's SHA-256 hash
    files_by_hash = {}  # Create a dictionary that groups filenames by hash

    for filename, digest in file_hashes.items():  # Examine every filename and hash
        if digest not in files_by_hash:  # Check whether this hash is new
            files_by_hash[digest] = []  # Create an empty filename list for this hash

        files_by_hash[digest].append(filename)  # Add the filename to its hash group

    duplicate_files = {}  # Create a dictionary for duplicate groups only

    for digest, filenames in files_by_hash.items():  # Examine every hash group
        if len(filenames) > 1:  # Keep hashes shared by multiple files
            duplicate_files[digest] = filenames  # Store the duplicated filenames

    return duplicate_files  # Return all detected duplicate groups


def build_file_timeline(folder_path):  # Define a function that builds a file timeline
    """Collect file metadata and sort files by modification time."""  # Explain its purpose
    folder_path = resolve_path(folder_path)  # Resolve the folder path on any computer

    if not os.path.isdir(folder_path):  # Validate the supplied folder path
        print(f"Error: '{folder_path}' is not a valid folder.")  # Report an invalid folder
        return []  # Return an empty list instead of crashing

    timeline = []  # Create an empty list for file timeline entries

    for filename in os.listdir(folder_path):  # Loop over every item in the folder
        file_path = os.path.join(folder_path, filename)  # Build the complete item path

        if os.path.isfile(file_path):  # Process files and ignore subfolders
            file_stats = os.stat(file_path)  # Read the file's system metadata
            file_hash = calculate_sha256(file_path)  # Calculate the file's SHA-256 hash

            timeline_entry = {  # Create one structured timeline entry
                "filename": filename,  # Store the filename
                "size_bytes": file_stats.st_size,  # Store the file size in bytes
                "created_time": time.ctime(file_stats.st_ctime),  # Store a readable creation time
                "modified_time": time.ctime(file_stats.st_mtime),  # Store a readable modification time
                "modified_timestamp": file_stats.st_mtime,  # Store the timestamp for sorting
                "sha256": file_hash,  # Store the complete SHA-256 hash
            }

            timeline.append(timeline_entry)  # Add the file information to the timeline

    timeline.sort(key=lambda entry: entry["modified_timestamp"])  # Sort oldest to newest

    return timeline  # Return the sorted file timeline

 

def find_recent_files(timeline, window_seconds=600):  # Find files modified within a time window
    """Return timeline files modified within the selected number of seconds."""  # Explain its purpose
    current_time = time.time()  # Capture the current Unix timestamp
    recent_files = []  # Create an empty list for recently modified files

    for entry in timeline:  # Examine every file in the timeline
        file_age = int(current_time - entry["modified_timestamp"])  # Calculate the file's age

        if 0 <= file_age <= window_seconds:  # Check whether the age is inside the selected window
            recent_files.append({  # Add a structured recent-file result
                "filename": entry["filename"],  # Store the filename
                "age_seconds": file_age,  # Store how many seconds ago it changed
                "size_bytes": entry["size_bytes"],  # Store the file size
                "sha256": entry["sha256"],  # Store the file hash
            })

    return recent_files  # Return all recently modified files


def find_largest_file(timeline):  # Define a function that finds the largest file
    """Return the timeline entry with the greatest file size."""  # Explain its purpose

    if not timeline:  # Check whether the timeline is empty
        return None  # Return no result when there are no files

    largest_file = max(  # Find the entry with the greatest value
        timeline,  # Search inside the complete file timeline
           key=lambda entry: entry["size_bytes"],  # Compare entries using their file sizes
    )

    return largest_file  # Return all information about the largest file


def analyze_artifact_csv(filename):  # Define a function for analyzing forensic artifact data
    """Analyze artifact events by type, hour, and path."""  # Explain its purpose
    filename = resolve_path(filename)  # Resolve the input path on any computer
    if not os.path.isfile(filename):  # Check whether the CSV file exists
      print(f"Error: '{filename}' is not a valid file.")  # Display a clear error message
      return {}  # Return an empty dictionary instead of crashing

    try:  # Attempt to read and analyze the artifact file
        with open(filename, "r", newline="") as file:  # Open the CSV file for reading
            reader = csv.DictReader(file)  # Read every CSV row as a dictionary
            rows = list(reader)  # Convert all CSV rows into a list

        created_files = []  # Create a list for file-created events
        event_type_counts = Counter()  # Count each type of forensic event
        event_hour_counts = Counter()  # Count events occurring during each hour
        path_counts = Counter()  # Count how often each artifact path appears

        for row in rows:  # Examine every artifact event
            timestamp = row["timestamp"]  # Read the event timestamp
            event_type = row["event_type"]  # Read the event type
            path = row["path"]  # Read the affected file or process path

            event_type_counts[event_type] += 1  # Increase this event type's count
            event_hour_counts[timestamp[11:13]] += 1  # Extract and count the event hour
            path_counts[path] += 1  # Increase this path's occurrence count

            if event_type == "file_created":  # Check whether a file was created
                created_files.append(row)  # Store the complete file-created event

        busiest_path = path_counts.most_common(1)  # Find the most frequently used path

        return {  # Return all artifact-analysis results together
            "total_events": len(rows),  # Store the total number of events
            "file_created_events": created_files,  # Store all file-created events
            "event_type_counts": event_type_counts,  # Store counts by event type
            "event_hour_counts": event_hour_counts,  # Store counts by hour
            "busiest_path": busiest_path[0] if busiest_path else None,  # Store the busiest path
        }

    except (OSError, KeyError, csv.Error) as error:  # Handle file and CSV problems
        print(f"Artifact analysis error: {error}")  # Display a readable error message
        return {}  # Return an empty result when analysis fails


def write_artifact_summary(output_path, event_type_counts):  # Define a CSV summary-export function
    """Write forensic event-type counts to a new CSV file."""  # Explain its purpose
    output_path = resolve_path(output_path)  #Resolve the output path on any computer

    if not event_type_counts:  # Check whether there are results to export
        print("Error: No artifact results are available.")  # Explain why nothing was written
        return 0  # Return zero because no rows were exported

    try:  # Attempt to create and write the summary file
        with open(output_path, "w", newline="") as file:  # Create or overwrite the output CSV
            writer = csv.writer(file)  # Create a CSV writer object
            writer.writerow(["event_type", "count"])  # Write the column headings

            for event_type, count in event_type_counts.items():  # Examine every event type and count
                writer.writerow([event_type, count])  # Write one summary row

        return len(event_type_counts)  # Return the number of exported event types

    except OSError as error:  # Handle problems creating or writing the file
        print(f"Summary export error: {error}")  # Display a readable error message
        return 0  # Return zero when the export fails


def check_port(host, port, timeout=0.2):  # Define a function that checks one TCP port
    """Check whether one TCP port is open or closed.""" 

    try:  # Attempt to connect to the selected port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:  # Create a TCP socket
            client_socket.settimeout(timeout)  # Set the maximum connection waiting time
            connection_result = client_socket.connect_ex((host, port))  # Try connecting to the port

        if connection_result == 0:  # Check whether the connection succeeded
            status = "open"  # Mark the port as open
        else:  # Handle an unsuccessful connection
            status = "closed"  # Mark the port as closed

        return {  # Return the port-check information
            "host": host,  # Store the checked host
            "port": port,  # Store the checked port
            "status": status,  # Store whether the port is open or closed
        }

    except socket.error as error:  # Handle socket-related problems
        return {  # Return an error result instead of crashing
            "host": host,  # Store the checked host
            "port": port,  # Store the checked port
            "status": "error",  # Mark the check as unsuccessful
            "error": str(error),  # Store the socket error message
        }

def scan_common_ports(host="127.0.0.1", timeout=0.2):  # Define a common-port scanner
    """Check commonly used TCP ports on a permitted host."""  # Explain its purpose

    common_ports = {  # Map common TCP ports to their typical services

        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
    }

    results = []  # Create an empty list for all scan results

    for port, service in common_ports.items():  # Examine each common port and service
        result = check_port(host, port, timeout)  # Check the current TCP port
        result["service"] = service  # Add the expected service name to the result
        results.append(result)  # Store the complete port result

        print(f"{port}/{service}: {result['status']}")  # Display the port, service, and status

    return results  # Return all common-port scan results   



def run_full_triage(log_path, traffic_path, artifact_path, evidence_folder, urls):  # Define the complete triage workflow
    """Run all security and DFIR checks and return one combined report."""  # Explain its purpose

    report = {}  # Create a dictionary for the complete report

    report["current_user"] = get_current_user()  # Collect the current operating-system user
    report["running_processes"] = check_processes()  # Collect a sample of running processes
    report["log_analysis"] = analyze_log(log_path, "ERROR")  # Analyze the supplied security log

    exported_lines = write_filtered_log(  # Export ERROR lines into a separate file
        log_path,  # Supply the original security log
        "filtered_errors.log",  # Select the filtered output filename
        "ERROR",  # Select the keyword that will be exported
    )
    report["exported_error_lines"] = exported_lines  # Store the number of exported lines

    report["http_checks"] = check_multiple_urls(urls)  # Check all supplied HTTP endpoints
    report["traffic_analysis"] = analyze_traffic_csv(traffic_path)  # Analyze the network-traffic CSV

    artifact_results = analyze_artifact_csv(artifact_path)  # Analyze the forensic-artifact CSV
    report["artifact_analysis"] = artifact_results  # Store the artifact-analysis results

    if artifact_results:  # Check whether artifact analysis succeeded
        summary_rows = write_artifact_summary(  # Export event counts into a summary CSV
            "summary_report.csv",  # Select the summary output filename
            artifact_results["event_type_counts"],  # Supply the calculated event counts
        )
        report["artifact_summary_rows"] = summary_rows  # Store the exported summary-row count

    timeline = build_file_timeline(evidence_folder)  # Build a chronological file timeline
    report["file_timeline"] = timeline  # Store the complete file timeline
    report["recent_files"] = find_recent_files(timeline, 3600)  # Find files changed within one hour
    report["largest_file"] = find_largest_file(timeline)  # Find the largest evidence file
    report["file_hashes"] = hash_directory(evidence_folder)  # Calculate all evidence-file hashes
    report["duplicate_files"] = find_duplicate_files(evidence_folder)  # Detect identical files
    report["common_port_scan"] = scan_common_ports()  # Scan common TCP ports on this computer

    return report  # Return all collected security and DFIR results together


def print_full_report(report):  # Define a function for displaying the combined report
    """Print every section of the security and DFIR report."""  # Explain its purpose

    print("\n" + "=" * 60)  # Print the upper report border
    print("PYTHON SECURITY & DFIR TRIAGE REPORT")  # Print the report title
    print("=" * 60)  # Print the lower title border

    for section_name, section_result in report.items():  # Examine every report section
        readable_name = section_name.replace("_", " ").upper()  # Create a readable section name
        print(f"\n[{readable_name}]")  # Print the current section heading
        print(section_result)  # Print the current section result

    print("\n" + "=" * 60)  # Print the final report border
    print("TRIAGE COMPLETED")  # Confirm that all checks finished
    print("=" * 60)  # Close the displayed report


def show_menu():  # Define a function that displays the toolkit options
    """Display the main security and DFIR toolkit menu."""  # Explain its purpose

    print("\n" + "=" * 60)  # Print the upper menu border
    print("PYTHON SECURITY & DFIR TOOLKIT")  # Print the project title
    print("=" * 60)  # Print the lower title border
    print("1. Analyze a security log")  # Display the log-analysis option
    print("2. Check HTTP endpoints")  # Display the website-checking option
    print("3. Read a field from a JSON API")  # Display the JSON API option
    print("4. Analyze a network-traffic CSV")  # Display the traffic-analysis option
    print("5. Inspect running processes")  # Display the process-checking option
    print("6. Verify a file hash")  # Display the file-integrity option
    print("7. Analyze an evidence folder")  # Display the folder-analysis option
    print("8. Analyze a forensic artifact CSV")  # Display the artifact-analysis option
    print("9. Scan common TCP ports")  # Display the common-port option
    print("10. Run the complete triage report")  # Display the complete-report option
    print("0. Exit")  # Display the program-exit option



def main():  # Define the main program controller
    """Run the interactive security and DFIR toolkit menu."""  # Explain its purpose

    while True:  # Keep displaying the menu until the user exits
        show_menu()  # Display all available toolkit options
        choice = input("\nSelect an option: ").strip()  # Read and clean the user's choice

        if choice == "1":  # Handle security-log analysis
            log_path = input("Enter the log file path: ").strip()  # Read the log path
            keyword = input("Enter a keyword [ERROR]: ").strip() or "ERROR"  # Read the search keyword
            log_result = analyze_log(log_path, keyword)  # Analyze the selected log file
            print(log_result)  # Display the log-analysis result

            if log_result:  # Check whether log analysis succeeded
                output_path = input("Enter the filtered output filename: ").strip()  # Read the output path
                written_lines = write_filtered_log(log_path, output_path, keyword)  # Export matching lines
                print(f"Exported lines: {written_lines}")  # Display the exported-line count

        elif choice == "2":  # Handle HTTP endpoint checks
            url_text = input("Enter URLs separated by commas: ").strip()  # Read one or more URLs
            urls = [url.strip() for url in url_text.split(",") if url.strip()]  # Build a clean URL list
            print(check_multiple_urls(urls))  # Check and display all HTTP results

        elif choice == "3":  # Handle JSON API analysis
            url = input("Enter the JSON API URL: ").strip()  # Read the API URL
            field_name = input("Enter the JSON field name: ").strip()  # Read the requested field
            print(fetch_json_field(url, field_name))  # Fetch and display the field value

        elif choice == "4":  # Handle network-traffic CSV analysis
            traffic_path = input("Enter the traffic CSV path: ").strip()  # Read the traffic file path
            print(analyze_traffic_csv(traffic_path))  # Analyze and display the traffic results

        elif choice == "5":  # Handle operating-system process inspection
            print(f"Current user: {get_current_user()}")  # Display the current system user
            print(check_processes())  # Display a sample of running processes

        elif choice == "6":  # Handle single-file integrity verification
            file_path = input("Enter the file path: ").strip()  # Read the file path
            expected_hash = input("Enter the expected SHA-256 hash: ").strip()  # Read the known hash
            print(verify_file_hash(file_path, expected_hash))  # Compare and display both hashes

        elif choice == "7":  # Handle evidence-folder analysis
            folder_path = input("Enter the evidence folder path: ").strip()  # Read the folder path
            timeline = build_file_timeline(folder_path)  # Build the forensic file timeline
            print(f"Timeline: {timeline}")  # Display the sorted timeline
            print(f"Recent files: {find_recent_files(timeline)}")  # Display recently modified files
            print(f"Largest file: {find_largest_file(timeline)}")  # Display the largest file
            print(f"File hashes: {hash_directory(folder_path)}")  # Display all file hashes
            print(f"Duplicate files: {find_duplicate_files(folder_path)}")  # Display duplicate files

        elif choice == "8":  # Handle forensic artifact CSV analysis
            artifact_path = input("Enter the artifact CSV path: ").strip()  # Read the artifact path
            artifact_result = analyze_artifact_csv(artifact_path)  # Analyze the artifact events
            print(artifact_result)  # Display the artifact-analysis result

            if artifact_result:  # Check whether artifact analysis succeeded
                output_path = input("Enter the summary CSV filename: ").strip()  # Read the output path
                event_counts = artifact_result["event_type_counts"]  # Read the event-type totals
                written_rows = write_artifact_summary(output_path, event_counts)  # Export the summary
                print(f"Exported summary rows: {written_rows}")  # Display the exported-row count

        elif choice == "9":  # Handle common TCP port scanning
            host = input("Enter an authorized host [127.0.0.1]: ").strip() or "127.0.0.1"  # Read the host
            print(scan_common_ports(host))  # Scan and display common TCP port results

        elif choice == "10":  # Handle the complete security and DFIR workflow
            log_path = input("Enter the log file path: ").strip()  # Read the security-log path
            traffic_path = input("Enter the traffic CSV path: ").strip()  # Read the traffic path
            artifact_path = input("Enter the artifact CSV path: ").strip()  # Read the artifact path
            evidence_folder = input("Enter the evidence folder path: ").strip()  # Read the evidence folder
            url_text = input("Enter URLs separated by commas: ").strip()  # Read HTTP endpoints
            urls = [url.strip() for url in url_text.split(",") if url.strip()]  # Build a clean URL list

            report = run_full_triage(  # Run every major security and DFIR check
                log_path,  # Supply the security-log path
                traffic_path,  # Supply the network-traffic CSV path
                artifact_path,  # Supply the forensic artifact CSV path
                evidence_folder,  # Supply the evidence-folder path
                urls,  # Supply the HTTP endpoint list
            )
            print_full_report(report)  # Display the complete combined report

        elif choice == "0":  # Handle the exit option
            print("Goodbye.")  # Display an exit message
            break  #  # Stop the menu loop

        else:  # Handle an unsupported menu choice
            print("Invalid option. Please try again.")  # Ask the user to select a valid option


if __name__ == "__main__":  # Run the program only when this file is executed directly
    main()  # Start the interactive toolkit menu