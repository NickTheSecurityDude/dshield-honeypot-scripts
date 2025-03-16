#!/usr/bin/env python3

"""
Feature: IP Address Cross-Log Analysis
  As a security analyst
  I want to analyze IP addresses across multiple log files
  So that I can identify persistent attackers and attack patterns

  Background:
    Given a directory containing JSON log files
    And each log file contains entries with source IP addresses

  Scenario: Analyzing top IP addresses across log files
    When I run the analysis on the log directory
    Then I should get a list of the top 25 IPs by frequency
    And each IP should show the number of files it appears in
    And the results should be sorted in descending order

  Scenario: Generating detailed IP analysis report
    When I analyze the log files
    Then I should get a detailed breakdown of the top 5 IPs
    And for each IP I should see all files it appears in
    And the results should be saved to an output file

  Scenario: Handling invalid log files
    Given a directory with some invalid JSON files
    When I run the analysis
    Then the script should skip invalid files
    And continue processing the remaining valid files
    And report any errors encountered

Usage:
    ./analyze_ip_across_logs.py <log_directory> <output_file>

Arguments:
    log_directory : Directory containing JSON log files to analyze
    output_file   : Path to write the analysis results
"""

import json
import os
from collections import Counter, defaultdict
from pathlib import Path

def read_json_file(filename):
    with open(filename) as f:
        return [json.loads(line) for line in f]

def analyze_ips_across_files(log_directory):
    ip_file_counter = defaultdict(set)  # Maps IP -> set of files it appears in
    
    # Process each JSON file in the directory
    print(f"\nSearching for JSON files in: {Path(log_directory).absolute()}")
    json_files = list(Path(log_directory).glob('*.json'))
    print(f"Found {len(json_files)} JSON files")
    
    for json_file in json_files:
        print(f"Processing file: {json_file}")
        try:
            logs = read_json_file(json_file)
            print(f"Found {len(logs)} log entries in {json_file}")
            for log in logs:
                if 'sip' in log:
                    ip_file_counter[log['sip']].add(str(json_file))
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue

    # Convert to (ip, count) pairs and sort by count
    ip_counts = [(ip, len(files)) for ip, files in ip_file_counter.items()]
    ip_counts.sort(key=lambda x: x[1], reverse=True)
    
    return ip_counts, ip_file_counter

def main():
    log_dir = "./webhoneypot-logs"
    output_file = "ip_analysis_results.txt"
    print(f"Starting analysis...")
    if not Path(log_dir).exists():
        print(f"Error: Directory '{log_dir}' does not exist")
        return
    
    print("Analyzing IP appearances across log files...")
    ip_counts, ip_file_mapping = analyze_ips_across_files(log_dir)
    
    # Function to write output to both console and file
    def write_output(file, text):
        print(text)
        file.write(text + '\n')
    
    with open(output_file, 'w') as f:
        write_output(f, "\nTop 25 IPs by number of files they appear in:")
        write_output(f, "IP Address".ljust(20) + "Number of Files")
        write_output(f, "-" * 40)
        
        for ip, count in ip_counts[:25]:
            write_output(f, f"{ip.ljust(20)}{count}")
        
        write_output(f, "\nDetailed breakdown of files for top 5 IPs:")
        for ip, _ in ip_counts[:5]:
            files = ip_file_mapping[ip]
            write_output(f, f"\n{ip} appears in {len(files)} files:")
            for file in sorted(files):
                write_output(f, f"  - {file}")
    
    print(f"\nResults have been saved to {output_file}")

if __name__ == "__main__":
    main()