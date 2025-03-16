#!/usr/bin/env python3

"""
Description:
This script analyzes JSON log files to track and analyze the behavior of specific IP addresses.
It provides detailed information about an IP address's activity patterns including:
- Session duration and timing
- Most frequently accessed GET URLs
- Most frequently accessed POST URLs
- URL filename statistics for both GET and POST requests

Usage:
    python parse_ip_logs.py <logfile> <ip_address>
    Ex. python3 parse_ip_logs.py webhoneypot-2025-01-24.json 194.146.12.252

Arguments:
    logfile     - Path to the JSON log file to analyze
    ip_address  - Target IP address to analyze activity for

The script is particularly useful for investigating suspicious IP addresses and understanding
their behavior patterns over time.

Feature: IP Address Activity Analysis
  As a security investigator
  I want to analyze the activity of specific IP addresses
  So that I can understand their behavior patterns and potential threats

  Scenario: Analyze IP session information
    Given I have a log file and target IP address
    When I analyze the logs
    Then I should see the first and last activity timestamps
    And I should see the total session duration

  Scenario: Analyze GET request patterns
    Given I have filtered logs for a specific IP
    When I analyze GET requests
    Then I should see the top 25 requested GET URLs
    And I should see filename statistics for GET requests

  Scenario: Analyze POST request patterns
    Given I have filtered logs for a specific IP
    When I analyze POST requests
    Then I should see the top 25 POST URLs
    And I should see filename statistics for POST requests
"""

import json
from collections import Counter
from datetime import datetime

def read_json_file(filename):
    with open(filename) as f:
        return [json.loads(line) for line in f]

def main():
    import sys
    if len(sys.argv) != 3:
        print("Usage: python parse_ip_logs.py <logfile> <ip_address>")
        sys.exit(1)

    LOGFILE = sys.argv[1]
    TARGET_IP = sys.argv[2]
    
    logs = read_json_file(LOGFILE)
    
    # Filter logs for specific IP
    ip_logs = [log for log in logs if log['sip'] == TARGET_IP]
    
    if not ip_logs:
        print(f"No entries found for IP: {TARGET_IP}")
        sys.exit(0)
    
    # Get session timing information
    timestamps = [log['time'] for log in ip_logs]
    first_entry = min(timestamps)
    last_entry = max(timestamps)
    
    # Convert timestamps to datetime objects for duration calculation
    first_dt = datetime.strptime(first_entry, "%Y-%m-%dT%H:%M:%S.%f")
    last_dt = datetime.strptime(last_entry, "%Y-%m-%dT%H:%M:%S.%f")
    duration = last_dt - first_dt
    
    print(f"\nSession Information for IP: {TARGET_IP}")
    print(f"First Entry: {first_entry}")
    print(f"Last Entry:  {last_entry}")
    print(f"Duration:    {duration}\n")
    
    # Display top 25 GET URLs for this IP
    get_urls = [log['url'] for log in ip_logs if log['method'] == 'GET']
    url_counter = Counter(get_urls)
    print("\nTop 25 GET URLs:")
    for url, count in url_counter.most_common(25):
        print(f"GET  {url} ({count} times)")
        
    # Display GET URL filenames with counts
    get_filenames = [url.split('/')[-1] for url in get_urls]
    filename_counter = Counter(get_filenames)
    print("\nGET URL Filenames and Counts:")
    for filename, count in filename_counter.most_common():
        print(f"{filename}: {count} times")
    
    # Display top 25 POST URLs for this IP
    post_urls = [log['url'] for log in ip_logs if log['method'] == 'POST']
    post_url_counter = Counter(post_urls)
    print("\nTop 25 POST URLs:")
    for url, count in post_url_counter.most_common(25):
        print(f"POST {url} ({count} times)")
        
    # Display POST URL filenames with counts
    post_filenames = [url.split('/')[-1] for url in post_urls]
    post_filename_counter = Counter(post_filenames)
    print("\nPOST URL Filenames and Counts:")
    for filename, count in post_filename_counter.most_common():
        print(f"{filename}: {count} times")

if __name__ == "__main__":
    main()