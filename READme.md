# Advanced Buffer Checker

## Overview
Advanced Buffer Checker is a powerful Python-based tool that helps users analyze various network and domain parameters of websites. It provides insights such as maximum buffer size, latency, packet loss, TTL hops, geographical location, and WHOIS domain details. The tool also generates a visually stunning HTML report with search, pagination, and data visualization features.

## Features
- Buffer Size Analysis: Finds the maximum buffer size for a given website.
- Latency Measurement: Calculates the average response time.
- Packet Loss Detection: Checks the percentage of lost packets.
- TTL Hops Calculation: Determines the number of hops required to reach the target.
- Geolocation Lookup: Fetches the city and country of the website's IP address.
- WHOIS Domain Details: Retrieves domain registration details via API.
- Interactive Reports: Generates a feature-rich HTML report with charts and filtering options.

## Installation
### Prerequisites
- Python 3.7+
- Required Python libraries:
  ```sh
  pip install requests tqdm tabulate colorama
  ```

## Usage
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/advanced-buffer-checker.git
   cd advanced-buffer-checker
   ```
2. Open `buffer_checker.py` and replace `WHOIS_API_KEY` with your actual API key:
   ```python
   WHOIS_API_KEY = "your_api_key_here"
   ```
3. Run the script:
   ```sh
   python buffer_checker.py
   ```
4. Enter website URLs (comma-separated) when prompted.

## Output
- Terminal output displays network and domain details in tabular format.
- HTML reports are saved in the `reports/` directory.

## Example
```sh
Enter websites (comma-separated): example.com, google.com
```
_Output:_
```
Website        | Max Buffer | TTL Hops | Latency | Packet Loss | Geo Location  
--------------|-----------|----------|---------|-------------|---------------
example.com   | 1464 B    | 12       | 30ms    | 0%          | New York, US  
google.com    | 1480 B    | 15       | 25ms    | 0%          | Mountain View, US  
```

## Disclaimer
This tool is intended for educational and research purposes only. Unauthorized use against third-party domains is strictly prohibited.

## Author
Created by Mr. Sami 🚀