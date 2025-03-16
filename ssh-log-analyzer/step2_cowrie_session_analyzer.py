"""
Cowrie Session Analyzer
======================

import json
import datetime
#from cowrie_log_analyzer import get_ip_location
import geoip2.database

This script provides detailed analysis of individual Cowrie honeypot sessions, including command
execution, login attempts, and file download activities.

Feature: Cowrie Session Analysis
    As a security analyst
    I want to analyze specific Cowrie honeypot sessions in detail
    In order to understand attacker behavior and techniques within individual sessions

    Scenario: Analyze a specific session
        Given a Cowrie JSON log file exists
        And a valid session ID is provided
        When I run the session analyzer
        Then it should provide detailed session information including:
            * Connection details
            * Login attempts and credentials
            * Command execution history
            * File download activities
            * Session duration and timing

Usage:
    python cowrie_session_analyzer.py <path_to_log_file> <session_id>
    Ex.: python3 cowrie_session_analyzer.py cowrie.json.2025-01-16 c569362ab730 > attack_session1.txt

Arguments:
    path_to_log_file : Path to the Cowrie JSON log file
    session_id      : The specific session ID to analyze

Requirements:
    - Python 3.6+
    - JSON formatted Cowrie logs

Example:
    python cowrie_session_analyzer.py /var/log/cowrie/cowrie.json 1234567890
"""

import json
import sys
from datetime import datetime
from collections import defaultdict


def analyze_session_log(filename, session_id, geoip_db_path="GeoLite2-City.mmdb"):
    """
    Analyze a single session log file from Cowrie honeypot for a specific session ID.
    
    This function processes a Cowrie log file to extract detailed information about a specific
    session, including connection details, login attempts, command execution, and file downloads.
    
    Args:
        filename (str): Path to the Cowrie log file
        session_id (str): Session ID to analyze
        
    Returns:
        dict: A dictionary containing comprehensive session information including:
            - start_time: Session start timestamp
            - end_time: Session end timestamp
            - duration: Session duration in seconds
            - src_ip: Source IP address
            - src_port: Source port number
            - dst_port: Destination port number
            - protocol: Connection protocol
            - client_version: SSH client version
            - commands: List of commands executed during session
            - login_attempts: List of login attempts with credentials
            - successful_login: Successful login credentials if any
            - command_success_count: Number of successful commands
            - command_failed_count: Number of failed commands
            - downloads: List of files downloaded during session
            
    Note:
        Returns None if the specified session ID is not found in the log file.
    """
    
    # Initialize dictionary to store comprehensive session information
    # This will hold all details about the session including timing, commands, and activities
    session_info = {
        'start_time': None,
        'end_time': None,
        'duration': None,
        'src_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'client_version': None,
        'commands': [],
        'login_attempts': [],
        'successful_login': None,
        'command_success_count': 0,
        'command_failed_count': 0,
        'downloads': [],  # Added from download analyzer
        'location': {
            'country': None,
            'city': None,
            'latitude': None,
            'longitude': None
        }
    }
    
    # Initialize list to track commands chronologically with their execution status
    # This helps analyze attacker behavior patterns and command success rates
    command_sequence = []
    
    try:
        found_session = False
        with open(filename, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('session', '') != session_id:
                        continue
                    found_session = True
                    eventid = event.get('eventid', '')
                    
                    # Process initial SSH/Telnet connection event
                    # Captures source/destination information and protocol details
                    if eventid == 'cowrie.session.connect':
                        session_info['start_time'] = event.get('timestamp', '')
                        session_info['src_ip'] = event.get('src_ip', '')
                        # Get location information for the source IP
                        #with geoip2.database.Reader(geoip_db_path) as reader:
                        #    session_info['location'] = get_ip_location(session_info['src_ip'], reader)
                        session_info['src_port'] = event.get('src_port', '')
                        session_info['dst_port'] = event.get('dst_port', '')
                        session_info['protocol'] = event.get('protocol', '')
                    
                    # Client version information
                    elif eventid == 'cowrie.client.version':
                        session_info['client_version'] = event.get('version', '')
                    
                    # Login attempts
                    elif eventid == 'cowrie.login.failed':
                        session_info['login_attempts'].append({
                            'timestamp': event.get('timestamp', ''),
                            'username': event.get('username', ''),
                            'password': event.get('password', ''),
                            'success': False
                        })
                    
                    elif eventid == 'cowrie.login.success':
                        session_info['login_attempts'].append({
                            'timestamp': event.get('timestamp', ''),
                            'username': event.get('username', ''),
                            'password': event.get('password', ''),
                            'success': True
                        })
                        session_info['successful_login'] = {
                            'username': event.get('username', ''),
                            'password': event.get('password', '')
                        }
                    
                    # Command execution
                    elif eventid == 'cowrie.command.input':
                        command_sequence.append({
                            'timestamp': event.get('timestamp', ''),
                            'command': event.get('input', ''),
                            'success': None
                        })
                    
                    elif eventid == 'cowrie.command.success':
                        session_info['command_success_count'] += 1
                        if command_sequence:
                            command_sequence[-1]['success'] = True
                    
                    elif eventid == 'cowrie.command.failed':
                        session_info['command_failed_count'] += 1
                        if command_sequence:
                            command_sequence[-1]['success'] = False
                    
                    # File downloads
                    elif eventid == 'cowrie.session.file_download':
                        download_info = {
                            'timestamp': event.get('timestamp', ''),
                            'url': event.get('url', ''),
                            'shasum': event.get('shasum', ''),
                            'outfile': event.get('outfile', ''),
                            'size': event.get('size', 0)
                        }
                        session_info['downloads'].append(download_info)
                    
                    # Session closure
                    elif eventid == 'cowrie.session.closed':
                        session_info['end_time'] = event.get('timestamp', '')
                        session_info['duration'] = event.get('duration', 0)
                
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON line: {e}")
    
    except FileNotFoundError:
        print(f"File {filename} not found")
        return
    
    session_info['commands'] = command_sequence
    
    # Return session info for processing in main
    
    return session_info if found_session else None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python cowrie_session_analyzer.py <log_file> <session_id>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    session_id = sys.argv[2]
    session_info = analyze_session_log(log_file, session_id)
    
    if not session_info:
        print("No session information found for the given session ID")
        sys.exit(1)

    # All session info printing happens after the None check
    print("\n=== Session Analysis ===")
    print(f"\nConnection Details:")
    print(f"Source IP: {session_info.get('src_ip', 'Unknown')}")
    print(f"Source Port: {session_info.get('src_port', 'Unknown')}")
    print(f"Destination Port: {session_info.get('dst_port', 'Unknown')}")
    print(f"Protocol: {session_info.get('protocol', 'Unknown')}")
    print(f"Client Version: {session_info.get('client_version', 'Unknown')}")
    
    start_time = session_info.get('start_time')
    end_time = session_info.get('end_time')
    if start_time and end_time:
        print(f"\nTiming:")
        print(f"Start Time: {start_time}")
        print(f"End Time: {end_time}")
        duration = session_info.get('duration', 0)
        print(f"Duration: {duration:.2f} seconds")
    
    login_attempts = session_info.get('login_attempts', [])
    print(f"\nLogin Attempts: {len(login_attempts)}")
    for attempt in login_attempts:
        status = "Success" if attempt.get('success') else "Failed"
        print(f"- {status}: username='{attempt.get('username', 'Unknown')}' password='{attempt.get('password', 'Unknown')}'")

    commands = session_info.get('commands', [])
    if commands:
        print(f"\nCommand Execution:")
        print(f"Total Commands: {len(commands)}")
        print(f"Successful Commands: {session_info.get('command_success_count', 0)}")
        print(f"Failed Commands: {session_info.get('command_failed_count', 0)}")
        
        print("\nCommand Sequence:")
        for cmd in commands:
            success = cmd.get('success')
            status = "Success" if success else "Failed" if success is False else "Unknown"
            print(f"- [{status}] {cmd.get('command', 'Unknown')}")

        # Calculate unique command statistics
        unique_commands = set(cmd.get('command', 'Unknown') for cmd in commands)
        print(f"\nUnique Commands Used: {len(unique_commands)}")
        print("\nUnique Commands List:")
        for cmd in unique_commands:
            print(f"- {cmd}")
    
    # Print download analysis
    downloads = session_info.get('downloads', [])
    if downloads:
        print("\nFile Downloads:")
        print(f"Total Downloads: {len(downloads)}")
        for idx, download in enumerate(downloads, 1):
            print(f"\nDownload #{idx}:")
            print(f"Timestamp: {download.get('timestamp', 'Unknown')}")
            print(f"URL: {download.get('url', 'Unknown')}")
            print(f"SHA256: {download.get('shasum', 'Unknown')}")
            print(f"Saved as: {download.get('outfile', 'Unknown')}")
            print(f"Size: {download.get('size', 'Unknown')} bytes")
            
        # Calculate total downloaded bytes
        total_bytes = sum(d.get('size', 0) for d in downloads)
        print(f"\nTotal Downloaded Bytes: {total_bytes:,} bytes")
        
        # Get unique download sources
        unique_sources = set(d.get('url', 'Unknown') for d in downloads)
        print(f"Unique Download Sources: {len(unique_sources)}")
        print("\nDownload Sources:")
        for source in unique_sources:
            print(f"- {source}")
