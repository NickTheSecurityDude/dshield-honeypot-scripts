"""
Cowrie Log Analyzer
==================

This script analyzes Cowrie honeypot log files to generate comprehensive statistics and insights
about attacker behavior, geographic distributions, and attack patterns.

Feature: Cowrie Log Analysis
    As a security analyst
    I want to analyze Cowrie honeypot logs
    In order to understand attack patterns and attacker behavior

    Scenario: Analyze a Cowrie log file
        Given a Cowrie JSON log file exists
        When I run the log analyzer with the file
        Then it should provide detailed statistics about:
            * Basic connection information
            * Geographic attack origins
            * Session details and durations
            * Login attempts and success rates
            * Command execution patterns
            * Port usage statistics

Usage:
    python cowrie_log_analyzer.py <path_to_log_file> [--geoip-db <path_to_geoip_database>]
    Ex: python3 cowrie_log_analyzer.py cowrie.json.2025-01-16

Arguments:
    path_to_log_file      : Path to the Cowrie JSON log file
    --geoip-db           : Optional path to GeoIP database (default: GeoLite2-City.mmdb)

Requirements:
    - Python 3.6+
    - geoip2 package
    - GeoLite2 City database

Example:
    python cowrie_log_analyzer.py /var/log/cowrie/cowrie.json
"""

import json
from collections import Counter, defaultdict
import statistics
import geoip2.database
from geoip2.errors import AddressNotFoundError
from pathlib import Path
from datetime import datetime
from itertools import zip_longest
import argparse

def get_ip_location(ip, reader):
    """
    Get geographic location information for an IP address using GeoIP2 database.
    
    Args:
        ip (str): IP address to look up
        reader (geoip2.database.Reader): Initialized GeoIP2 database reader
        
    Returns:
        dict: Dictionary containing country, city, latitude, and longitude information
              Returns default values if IP is not found in database
    """
    try:
        response = reader.city(ip)
        return {
            'country': response.country.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except AddressNotFoundError:
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None
        }

def analyze_cowrie_logs(filename, geoip_db_path="GeoLite2-City.mmdb"):
    """
    Analyze Cowrie honeypot logs to generate comprehensive attack statistics.
    
    Args:
        filename (str): Path to Cowrie JSON log file
        geoip_db_path (str, optional): Path to GeoIP2 database. Defaults to "GeoLite2-City.mmdb"
        
    The analysis includes:
        - Event type statistics
        - Protocol usage
        - Geographic attack origin distribution
        - Session duration analysis
        - Login attempt patterns
        - Command execution statistics
        - Port usage analysis
        - Command sequence analysis
        
    The function prints detailed statistics to stdout.
    """
    # Initialize counters and data structures to store analysis results
    # Counter objects automatically track frequency of items
    # defaultdict objects provide default values for missing keys
    event_types = Counter()
    protocols = Counter()
    connection_durations = {}  # session_id -> duration
    unique_ips = set()
    ip_locations = {}
    successful_logins = Counter()
    command_stats = defaultdict(Counter)  # command -> session_ids
    command_success = defaultdict(int)  # session_id -> success_count
    session_commands = defaultdict(list)  # track commands per session in order
    ip_countries = Counter()
    ip_total_events = Counter()  # ip -> total events
    failed_login_ips = Counter()  # ip -> failed login attempts
    session_start_times = {}  # session_id -> start time
    source_ports = Counter()
    destination_ports = Counter()  # New counter for destination ports
    
    # Initialize GeoIP database reader for IP geolocation lookups
    # This will be used to map IP addresses to geographic locations
    reader = geoip2.database.Reader(geoip_db_path)
    
    with open(filename, 'r') as f:
        for line in f:
            try:
                # Parse each line as a JSON object
                # Each line represents a single event in the Cowrie logs
                log_entry = json.loads(line)
                
                # Count event types
                event_types[log_entry['eventid']] += 1
                
                # Process IP information and timing
                if 'src_ip' in log_entry:
                    ip = log_entry['src_ip']
                    unique_ips.add(ip)
                    ip_total_events[ip] += 1
                    
                    if ip not in ip_locations:
                        ip_locations[ip] = get_ip_location(ip, reader)
                        ip_countries[ip_locations[ip]['country']] += 1
                
                # Track session information
                session_id = log_entry.get('session', 'unknown')
                
                # Count protocols, source ports and destination ports for connect events
                if log_entry['eventid'] == 'cowrie.session.connect':
                    protocols[log_entry.get('protocol', 'unknown')] += 1
                    source_ports[log_entry.get('src_port', 'unknown')] += 1
                    destination_ports[log_entry.get('dst_port', 'unknown')] += 1
                    session_start_times[session_id] = log_entry.get('timestamp', 0)
                
                # Track connection durations
                if log_entry['eventid'] == 'cowrie.session.closed':
                    connection_durations[session_id] = log_entry['duration']
                
                # Track login attempts
                if log_entry['eventid'] == 'cowrie.login.success':
                    successful_logins[log_entry['src_ip']] += 1
                elif log_entry['eventid'] == 'cowrie.login.failed':
                    failed_login_ips[log_entry['src_ip']] += 1
                
                # Track command execution
                if log_entry['eventid'] == 'cowrie.command.input':
                    input_parts = log_entry.get('input', '').split()
                    if len(input_parts) >= 2:
                        command = ' '.join(input_parts[:2])
                    else:
                        command = log_entry.get('input', 'unknown')
                    command_stats[command][session_id] += 1
                    session_commands[session_id].append(command)
                elif log_entry['eventid'] == 'cowrie.command.success':
                    command_success[session_id] += 1
                    
            except json.JSONDecodeError:
                print(f"Failed to parse line: {line}")
    
    # Close the GeoIP reader
    reader.close()
    
    # Print analysis
    print("\n=== Basic Statistics ===")
    print(f"\nUnique Source IPs: {len(unique_ips)}")
    
    print("\nTop 10 Event Types:")
    for event, count in event_types.most_common(10):
        print(f"{event}: {count}")
    
    print("\nTop 10 Protocols:")
    for protocol, count in protocols.most_common(10):
        print(f"{protocol}: {count}")
    
    print("\n=== Geographic Information ===")
    print("\nTop 10 Countries:")
    for country, count in ip_countries.most_common(10):
        print(f"{country}: {count}")
    
    print("\n=== Session Information ===")
    print("\nTop 10 Longest Sessions:")
    for session_id, duration in sorted(connection_durations.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"Session {session_id}: {duration:.2f} seconds")
    
    print("\nTop 10 Source Ports:")
    for port, count in source_ports.most_common(10):
        print(f"Port {port}: {count}")

    print("\nTop 10 Destination Ports:")
    for port, count in destination_ports.most_common(10):
        print(f"Port {port}: {count}")
    
    print("\n=== Login Information ===")
    print("\nTop 10 Successful Login IPs:")
    for ip, count in successful_logins.most_common(10):
        location = ip_locations[ip]
        print(f"{ip} ({location['country']}, {location['city']}): {count}")
    
    print("\n=== Command Statistics ===")
    print("\nTop 10 Command Success Session IDs:")
    for session_id, count in sorted(command_success.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"Session {session_id}: {count} successful commands")
    
    print("\nTop 10 Commands By Unique Sessions:")
    command_session_counts = {cmd: len(sessions) for cmd, sessions in command_stats.items()}
    for command, unique_sessions in sorted(command_session_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{command}: {unique_sessions} unique sessions")
    
    print("\nTop 10 Sessions by Unique Commands:")
    for session_id, commands in sorted(session_commands.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        print(f"Session {session_id}: {len(commands)} unique commands")
        
    if connection_durations:
        durations = list(connection_durations.values())
        print("\nOverall Session Statistics:")
        print(f"Average duration: {statistics.mean(durations):.2f} seconds")
        print(f"Max duration: {max(durations):.2f} seconds")
        print(f"Min duration: {min(durations):.2f} seconds")
        
        # Additional Statistics            
        print("\n=== Additional IP Statistics ===")
        print("\nTop 10 Most Active IPs (Total Events):")
        for ip, count in ip_total_events.most_common(10):
            location = ip_locations[ip]
            print(f"{ip} ({location['country']}, {location['city']}): {count} events")
            
        print("\nTop 10 IPs with Failed Login Attempts:")
        for ip, count in failed_login_ips.most_common(10):
            location = ip_locations[ip]
            success = successful_logins[ip]
            print(f"{ip} ({location['country']}, {location['city']}): {count} failures, {success} successes")
            
        print("\n=== Command Sequence Analysis ===")
        # Analyze common command sequences (pairs)
        command_pairs = Counter()
        for commands in session_commands.values():
            if len(commands) >= 2:
                for cmd1, cmd2 in zip(commands, commands[1:]):
                    command_pairs[(cmd1, cmd2)] += 1
                    
        print("\nTop 10 Command Sequences:")
        for (cmd1, cmd2), count in command_pairs.most_common(10):
            print(f"'{cmd1}' followed by '{cmd2}': {count} times")
            
        # Calculate average commands per session
        sessions_with_commands = sum(1 for cmds in session_commands.values() if cmds)
        total_commands = sum(len(cmds) for cmds in session_commands.values())
        if sessions_with_commands > 0:
            print(f"\nAverage Commands Per Session: {total_commands / sessions_with_commands:.2f}")
            
        # Session success rate analysis
        sessions_with_success = sum(1 for success in command_success.values() if success > 0)
        if len(session_commands) > 0:
            success_rate = (sessions_with_success / len(session_commands)) * 100
            print(f"\nSession Success Rate: {success_rate:.1f}% ({sessions_with_success}/{len(session_commands)})")

# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Analyze Cowrie honeypot logs.')
parser.add_argument('logfile', help='Path to the JSON log file to analyze')
parser.add_argument('--geoip-db', default='GeoLite2-City.mmdb',
                    help='Path to the GeoIP database file (default: GeoLite2-City.mmdb)')

args = parser.parse_args()
analyze_cowrie_logs(args.logfile, args.geoip_db)