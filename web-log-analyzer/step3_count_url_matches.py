#!/usr/bin/env python3
"""
Count URL Matches Tool

This script analyzes JSON log files to find and count URLs containing specific search terms.
It helps identify patterns in URL access and potential security concerns.

Usage:
    ./count_url_matches.py <logfile> <search_key>
    Ex. python3 count_url_matches.py webhoneypot-2025-01-24.json "wp-"

Arguments:
    logfile    : Path to the JSON log file to analyze
    search_key : String to search for in URLs

Example:
    ./count_url_matches.py access.log admin

Feature: URL Pattern Analysis
    As a security analyst
    I want to analyze URL patterns in log files
    So that I can identify potential security threats

    Scenario: Count URL matches in log file
        Given a JSON log file with URL access records
        When I search for a specific term in URLs
        Then I should get a count of matching URLs
        And see timestamps of URL access attempts
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

def count_url_matches(logfile, search_key):
    """
    Read JSON log file and analyze URLs containing the search key.
    
    Args:
        logfile (str): Path to the JSON log file
        search_key (str): Key to search for in URLs
        
    Returns:
        tuple: Contains:
            - dict of IP addresses and their counts
            - dict of user agents and their counts
            - datetime of first access
            - datetime of last access
            - count of GET requests
            - count of POST requests
    """
    ip_counter = Counter()
    ua_counter = Counter()
    url_counter = Counter()  # Add URL counter
    first_access = None
    last_access = None
    method_counts = defaultdict(int)
    
    try:
        with open(logfile, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line)
                    if 'url' in log_entry and search_key.lower() in log_entry['url'].lower():
                        # Count URLs
                        url_counter[log_entry['url']] += 1
                        
                        # Count IP addresses
                        if 'sip' in log_entry:
                            ip_counter[log_entry['sip']] += 1
                            
                        # Count user agents
                        if 'headers' in log_entry and 'user-agent' in log_entry['headers']:
                            ua_counter[log_entry['headers']['user-agent']] += 1
                            
                        # Track timestamps
                        if 'time' in log_entry:
                            current_time = datetime.fromisoformat(log_entry['time'].replace('Z', '+00:00'))
                            if first_access is None or current_time < first_access:
                                first_access = current_time
                            if last_access is None or current_time > last_access:
                                last_access = current_time
                                
                        # Count HTTP methods
                        if 'method' in log_entry:
                            method_counts[log_entry['method']] += 1
                            
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Error: File {logfile} not found")
        sys.exit(1)
        
    return ip_counter, ua_counter, url_counter, first_access, last_access, method_counts.get('GET', 0), method_counts.get('POST', 0)

def main():
    if len(sys.argv) != 3:
        print("Usage: python count_url_matches.py <logfile> <search_key>")
        sys.exit(1)
        
    logfile = sys.argv[1]
    search_key = sys.argv[2]
    
    ip_counter, ua_counter, url_counter, first_access, last_access, get_count, post_count = count_url_matches(logfile, search_key)
    
    print(f"\nAnalysis for URLs containing '{search_key}':")
    print("\nTop 25 IP addresses:")
    for ip, count in ip_counter.most_common(25):
        print(f"  {ip}: {count} requests")
        
    print("\nTop 25 URLs:")
    for url, count in url_counter.most_common(25):
        print(f"  {url}: {count} requests")
        
    print("\nTop 25 User Agents:")
    for ua, count in ua_counter.most_common(25):
        print(f"  {ua}: {count} requests")
        
    print("\nTimestamp Analysis:")
    if first_access and last_access:
        print(f"  First accessed: {first_access}")
        print(f"  Last accessed: {last_access}")
    else:
        print("  No timestamp data available")
        
    print("\nHTTP Method Counts:")
    print(f"  GET requests: {get_count}")
    print(f"  POST requests: {post_count}")

if __name__ == "__main__":
    main()