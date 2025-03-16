#!/usr/bin/env python3
"""
IP Geolocation Script

This script reads IP addresses from a file named 'ips.txt' and provides geolocation
information for each IP using multiple geolocation services.

Usage:
    1. Create a text file named 'ips.txt' with one IP address per line
    2. Ensure you have the required API keys set up for IP geolocation services
    3. Run the script: python3 step2_ip_geolocation.py
    4. Results will be displayed showing location data from multiple services

Required Dependencies:
    - requests
    - geoip2
    - MaxMind GeoLite2 database (place GeoLite2-City.mmdb in the same directory)

Feature: IP Geolocation
    As a security analyst
    I want to get geolocation data for IP addresses
    So that I can identify the geographical origin of potential threats

    Scenario: Lookup IP address location from file
        Given I have a file containing IP addresses
        When I run the geolocation script
        Then I should receive location data from multiple services
        And the results should include country, city, and coordinates

    Scenario: Handle invalid IP addresses
        Given I have an invalid IP address in the input file
        When I run the geolocation script
        Then the script should handle the error gracefully
        And continue processing remaining IP addresses
"""

import requests
import json
import sys
import os.path
import time
import socket
from geoip2 import database
from geoip2.errors import AddressNotFoundError

def geolocate_ip_ipapi(ip):
    """
    Geolocate IP address using ip-api.com service (first source)
    Returns city, state/region, and country information
    """
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                'city': data.get('city', 'Unknown'),
                'state': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'source': 'ip-api.com'
            }
        else:
            return {'error': data.get('message', 'Unknown error'), 'source': 'ip-api.com'}
            
    except Exception as e:
        return {'error': str(e), 'source': 'ip-api.com'}

def geolocate_ip_ipinfo(ip):
    """
    Geolocate IP address using ipinfo.io service (second source)
    Returns city, state/region, and country information
    """
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        
        if 'bogon' not in data:
            # Parse location from region field which might be in format "California, CA"
            region = data.get('region', 'Unknown')
            
            return {
                'city': data.get('city', 'Unknown'),
                'state': region,
                'country': data.get('country', 'Unknown'),
                'source': 'ipinfo.io'
            }
        else:
            return {'error': 'Private/Reserved IP', 'source': 'ipinfo.io'}
            
    except Exception as e:
        return {'error': str(e), 'source': 'ipinfo.io'}
        
def geolocate_ip_maxmind(ip):
    """
    Geolocate IP address using MaxMind's GeoLite2 database (GeoLocate)
    Returns city, state/region, and country information
    """
    # Path to GeoLite2 database file - user needs to download this file separately
    # from https://dev.maxmind.com/geoip/geoip2/geolite2/
    db_path = 'GeoLite2-City.mmdb'
    
    try:
        # Check if database file exists
        if not os.path.isfile(db_path):
            return {
                'error': f'GeoLite2 database file not found at {db_path}. Please download from MaxMind.',
                'source': 'MaxMind GeoLite2'
            }
            
        # Open connection to the database
        with database.Reader(db_path) as reader:
            # Look up IP address in the database
            response = reader.city(ip)
            
            return {
                'city': response.city.name or 'Unknown',
                'state': response.subdivisions.most_specific.name if response.subdivisions else 'Unknown',
                'country': response.country.name or 'Unknown',
                'source': 'MaxMind GeoLite2'
            }
                
    except AddressNotFoundError:
        return {'error': 'IP address not found in the database', 'source': 'MaxMind GeoLite2'}
    except Exception as e:
        return {'error': str(e), 'source': 'MaxMind GeoLite2'}

def read_ip_file(file_path):
    """
    Read IP addresses from a file
    Returns a list of IP addresses
    """
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        return []
        
    with open(file_path, 'r') as file:
        # Strip whitespace and empty lines
        ips = [line.strip() for line in file if line.strip()]
    
    return ips

def main():
    # Input file containing IP addresses
    ip_file = 'ips.txt'
    
    # Read IPs from file
    ip_addresses = read_ip_file(ip_file)
    
    if not ip_addresses:
        print("No IP addresses found in the file.")
        sys.exit(1)
    
    # Process each IP address
    for ip in ip_addresses:
        print(f"\nGeolocating IP: {ip}")
        print("-" * 40)
        
        # Get information from first source (ip-api.com)
        source1_data = geolocate_ip_ipapi(ip)
        print(f"Source 1 ({source1_data.get('source')}):")
        if 'error' not in source1_data:
            print(f"  City: {source1_data.get('city')}")
            print(f"  State/Region: {source1_data.get('state')}")
            print(f"  Country: {source1_data.get('country')}")
        else:
            print(f"  Error: {source1_data.get('error')}")
        
        # Add a small delay to avoid rate limiting
        time.sleep(0.5)
        
        # Get information from second source (ipinfo.io)
        source2_data = geolocate_ip_ipinfo(ip)
        print(f"Source 2 ({source2_data.get('source')}):")
        if 'error' not in source2_data:
            print(f"  City: {source2_data.get('city')}")
            print(f"  State/Region: {source2_data.get('state')}")
            print(f"  Country: {source2_data.get('country')}")
        else:
            print(f"  Error: {source2_data.get('error')}")
            
        # Add a small delay to avoid rate limiting
        time.sleep(0.5)
        
        # Get information from third source (MaxMind GeoLite2/GeoLocate)
        source3_data = geolocate_ip_maxmind(ip)
        print(f"Source 3 ({source3_data.get('source')}):")
        if 'error' not in source3_data:
            print(f"  City: {source3_data.get('city')}")
            print(f"  State/Region: {source3_data.get('state')}")
            print(f"  Country: {source3_data.get('country')}")
        else:
            print(f"  Error: {source3_data.get('error')}")

if __name__ == "__main__":
    main()