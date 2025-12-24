#!/bin/bash
# Basic scanning examples

echo "=== Basic Port Scanner Examples ==="

# Example 1: Fast scan on localhost
echo -e "\n1. Fast scan on localhost"
python main.py -t 127.0.0.1 --port-range fast --accept-disclaimer

# Example 2: Common ports on private IP
echo -e "\n2. Common ports scan"
python main.py -t 192.168.1.1 --port-range common --accept-disclaimer

# Example 3: Specific ports with service detection
echo -e "\n3. Specific ports with service detection"
python main.py -t 192.168.1.1 -p 22,80,443 -sV --accept-disclaimer

# Example 4: Scan with JSON output
echo -e "\n4. Scan with JSON export"
python main.py -t 192.168.1.1 --port-range fast -oJ results.json --accept-disclaimer

echo -e "\n=== Examples Complete ==="