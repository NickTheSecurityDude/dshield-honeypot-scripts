#!/usr/bin/env python3

import argparse

"""
Web Honeypot Log Analysis Tool

This script analyzes JSON log files from a web honeypot system to provide detailed statistics
about incoming traffic patterns and potential security threats.

Usage:
    ./parse_logs.py <logfile>
    Ex. python3 parse_logs.py webhoneypot-2025-01-24.json

Arguments:
    logfile : Path to the JSON log file to analyze

Example:
    ./parse_logs.py honeypot.log

Features:
- Common GET and POST URLs analysis
- User agent statistics
- Source IP geolocation tracking
- HTTP request pattern analysis
- Traffic anomaly detection

Dependencies:
- geoip2: For IP geolocation lookup
- GeoLite2-City.mmdb database file in the same directory

Feature: Web Honeypot Log Analysis
  As a security analyst
  I want to analyze web honeypot logs
  So that I can identify and track potential security threats

  Scenario: Analyze common attack patterns
    Given I have a JSON log file from the web honeypot
    When I process the log file
    Then I should see the most common GET and POST URLs
    And I should see user agent statistics
    And I should see source IP addresses with geolocation data

  Scenario: Filter out normal traffic
    Given I have a JSON log file
    When I analyze the URLs
    Then I should exclude root URL (/) from GET statistics
    And I should see both most and least common URLs

  Scenario: Geolocate attack sources
    Given I have source IP addresses
    When I look up their locations
    Then I should see city, state, and country information
    And I should handle unknown locations gracefully
"""

import geoip2.database
from collections import Counter

import json
from collections import Counter
from operator import itemgetter

# Number of results to show in statistics
TOP_N_RESULTS = 100

def read_json_file(filename):
    with open(filename) as f:
        return [json.loads(line) for line in f]

def main():
    parser = argparse.ArgumentParser(description='Analyze web honeypot JSON log files')
    parser.add_argument('logfile', help='Path to the JSON log file to analyze')
    args = parser.parse_args()
    
    logs = read_json_file(args.logfile)
    
    # Display keys in the JSON
    all_keys = set()
    for log in logs:
        all_keys.update(log.keys())
    print("Keys in JSON:")
    print(sorted(all_keys))
    print()
    
    # Display the 25 most common GET URLs (excluding root URL)
    get_urls = Counter(log['url'] for log in logs if log['url'] != '/' and log['method'] == 'GET')
    print(f"{TOP_N_RESULTS} most common GET URLs (excluding root URL):")
    for url, count in get_urls.most_common(TOP_N_RESULTS):
        print(f"{count:>5} {url}")
    print()

    # Display the 25 most common POST URLs
    post_urls = Counter(log['url'] for log in logs if log['method'] == 'POST')
    print(f"{TOP_N_RESULTS} most common POST URLs:")
    for url, count in post_urls.most_common(TOP_N_RESULTS):
        print(f"{count:>5} {url}")
    print()
    
    # Combine GET and POST URLs
    url_counts = get_urls + post_urls
    
    # Display the 25 least common URLs
    print("25 least common URLs:")
    for url, count in sorted(url_counts.items(), key=itemgetter(1))[:25]:
        print(f"{count:>5} {url}")
    print()
    
    # Display entries for second most common URL
    #print("Entries for second most common URL:")
    #second_most_common_url = url_counts.most_common(2)[1][0]
    #for log in logs:
    #    if log['url'] == second_most_common_url:
    #        print(json.dumps(log, indent=2))
    #print()
    
    # Display all URLs
    #print("All URLs:")
    #for log in logs:
    #    print(log['url'])
    #print()
    
    # Get sorted list of user agent strings
    user_agents = Counter()
    for log in logs:
        if 'headers' in log and 'user-agent' in log['headers']:
            user_agents[log['headers']['user-agent']] += 1
            
    print(f"{TOP_N_RESULTS} most common User agents:")
    for agent, count in user_agents.most_common(TOP_N_RESULTS):
        print(f"{count:>5} {agent}")
    print()

    # Display the 25 most common Source IPs
    sip_counts = Counter(log['sip'] for log in logs)
    print("25 most common Source IPs:")
    # Initialize GeoIP reader
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    
    for sip, count in sip_counts.most_common(25):
        try:
            # Look up location info
            response = reader.city(sip)
            city = response.city.name or 'Unknown'
            state = response.subdivisions.most_common.name if response.subdivisions else 'Unknown'
            country = response.country.name or 'Unknown'
            print(f"{count:>5} {sip} - {city}, {state}, {country}")
        except:
            # Handle IPs that can't be located
            print(f"{count:>5} {sip} - Location unknown")
            
    # Close the reader
    reader.close()
    print()

if __name__ == "__main__":
    main()