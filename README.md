# Log Analysis Tools Overview

This repository contains three groups of log analysis tools, each focused on different aspects of log processing and security analysis.

## 1. SSH Log Analyzer

Tools for analyzing SSH honeypot logs from Cowrie.

Execution order:
1. `step1_cowrie_log_analyzer.py`: Processes raw Cowrie SSH honeypot logs and extracts IP addresses, geolocation data, and attack patterns.
2. `step2_cowrie_session_analyzer.py`: Performs detailed analysis of specific SSH sessions identified in step 1, providing deeper insights into attacker behavior.

## 2. Web Log Analyzer

Tools for analyzing web server logs and identifying potential security threats.

Execution order:
1. `step1_parse_logs.py`: Parses raw web server logs and converts them into a structured JSON format.
2. `step2_parse_ip_logs.py`: Analyzes the parsed logs to extract and analyze IP-based patterns and potential threats.
3. `step3_count_url_matches.py`: Identifies and counts specific URL patterns in the logs to detect potential attack vectors.

## 3. Web Log Attack Correlator

Tools for correlating attack patterns across different log sources and enriching with geolocation data.

Execution order:
1. `step1_analyze_ip_across_logs.py`: Correlates IP addresses across different log files to identify coordinated attacks or persistent threats.
2. `step2_ip_geolocation.py`: Enriches the identified IP addresses with geolocation data using multiple services (IP-API, IPinfo, MaxMind).

## Script Details

### SSH Log Analyzer
- `step1_cowrie_log_analyzer.py`
  - Analyzes Cowrie SSH honeypot logs
  - Extracts IP addresses and attack patterns
  - Performs geolocation lookups using MaxMind GeoIP database
  - Generates statistical analysis of attack attempts

- `step2_cowrie_session_analyzer.py`
  - Analyzes specific SSH sessions in detail
  - Tracks attacker commands and behavior
  - Provides deep insights into attack methodologies
  - Uses geolocation data for attack source analysis

### Web Log Analyzer
- `step1_parse_logs.py`
  - Parses raw web server logs
  - Converts logs to structured JSON format
  - Extracts key information like IP addresses, URLs, and timestamps

- `step2_parse_ip_logs.py`
  - Analyzes IP-based patterns in parsed logs
  - Identifies potential security threats
  - Groups related activities by IP address

- `step3_count_url_matches.py`
  - Scans logs for specific URL patterns
  - Counts occurrences of potential attack vectors
  - Helps identify automated attacks or scanning attempts

### Web Log Attack Correlator
- `step1_analyze_ip_across_logs.py`
  - Cross-references IP addresses across multiple log files
  - Identifies coordinated attacks
  - Generates reports of suspicious activity patterns

- `step2_ip_geolocation.py`
  - Enriches IP data with geolocation information
  - Supports multiple geolocation services:
    - IP-API
    - IPinfo
    - MaxMind GeoIP2
  - Provides geographical context for attack sources

## Dependencies
- Python 3.x
- MaxMind GeoIP2 database
- Various Python packages for HTTP requests and JSON processing
