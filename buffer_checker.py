import json
import subprocess
import platform
import concurrent.futures
import time
import requests
from tqdm import tqdm
from tabulate import tabulate
from colorama import Fore, Style, init
import re
import os

# Initialize colorama for colored terminal output
init(autoreset=True)

# WHOIS API key (replace with your actual API key)
WHOIS_API_KEY = ""

# Ensure the reports directory exists
if not os.path.exists("reports"):
    os.makedirs("reports")

def print_banner():
    """Print the program banner."""
    banner = f"""
    {Fore.GREEN}{Style.BRIGHT}
    ██████╗ ██╗██████╗ ███████╗███████╗██████╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗
    ██╔══██╗██║██╔══██╗██╔════╝██╔════╝██╔══██╗    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
    ██████╔╝██║██████╔╝█████╗  █████╗  ██████╔╝    ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
    ██╔═══╝ ██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔═══╝     ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ██║     ██║██║     ███████╗███████╗██║         ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
    ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝          ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    {Style.RESET_ALL}
    🚀 Advanced Buffer Checker - Created by Mr. Sami 🔥
    """
    print(banner)

def get_geo_location(website_name):
    """Get the geographical location of the website's IP address."""
    try:
        ip = subprocess.run(["nslookup", website_name], capture_output=True, text=True).stdout.split()[-1]
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return f"{response.get('city', 'Unknown')}, {response.get('country', 'Unknown')}"
    except Exception:
        return "Unknown"

def get_latency(website_name):
    """Calculate the average latency to the website."""
    command = ["ping", "-c", "4", website_name] if platform.system().lower() != "windows" else ["ping", "-n", "4", website_name]
    result = subprocess.run(command, capture_output=True, text=True)
    output = result.stdout

    match = re.findall(r'time=([0-9.]+) ms', output)
    if match:
        latencies = [float(time) for time in match]
        return round(sum(latencies) / len(latencies), 2)
    return "N/A"

def get_packet_loss(website_name):
    """Calculate the packet loss percentage to the website."""
    command = ["ping", "-c", "4", website_name] if platform.system().lower() != "windows" else ["ping", "-n", "4", website_name]
    result = subprocess.run(command, capture_output=True, text=True)
    output = result.stdout

    match = re.search(r'(\d+)% packet loss', output)
    return f"{match.group(1)}%" if match else "N/A"

def get_ttl_hops(website_name):
    """Determine the TTL (Time to Live) hops to the website."""
    ttl = 1
    while True:
        command = ["ping", website_name, "-c", "1", "-t", str(ttl)] if platform.system().lower() != "windows" else ["ping", website_name, "-n", "1", "-i", str(ttl)]
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        if "TTL expired in transit" in output or "Time to live exceeded" in output:
            ttl += 1
        elif match := re.search(r'TTL=(\d+)', output):
            return ttl
        elif "Request timed out" in output or "100% packet loss" in output:
            ttl += 1
        else:
            return ttl

def get_domain_details(website_name):
    """Fetch domain details using the WHOIS API."""
    try:
        response = requests.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={website_name}&apiKey={WHOIS_API_KEY}&outputFormat=json"
        )
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()

        if data.get("WhoisRecord"):
            record = data["WhoisRecord"]
            registrant = record.get("registrant", {})
            administrative_contact = record.get("administrativeContact", {})
            technical_contact = record.get("technicalContact", {})
            registry_data = record.get("registryData", {})

            domain_details = {
                "registrar": record.get("registrarName", "N/A"),
                "created_date": record.get("createdDate", "N/A"),
                "updated_date": record.get("updatedDate", "N/A"),
                "expires_date": record.get("expiresDate", "N/A"),
                "name_servers": ", ".join(record.get("nameServers", {}).get("hostNames", ["N/A"])),
                "status": ", ".join(record.get("status", ["N/A"])),
                "registrant": {
                    "organization": registrant.get("organization", "N/A"),
                    "state": registrant.get("state", "N/A"),
                    "country": registrant.get("country", "N/A"),
                    "country_code": registrant.get("countryCode", "N/A"),
                },
                "administrative_contact": {
                    "organization": administrative_contact.get("organization", "N/A"),
                    "state": administrative_contact.get("state", "N/A"),
                    "country": administrative_contact.get("country", "N/A"),
                    "country_code": administrative_contact.get("countryCode", "N/A"),
                },
                "technical_contact": {
                    "organization": technical_contact.get("organization", "N/A"),
                    "state": technical_contact.get("state", "N/A"),
                    "country": technical_contact.get("country", "N/A"),
                    "country_code": technical_contact.get("countryCode", "N/A"),
                },
                "registry_data": {
                    "created_date": registry_data.get("createdDate", "N/A"),
                    "updated_date": registry_data.get("updatedDate", "N/A"),
                    "expires_date": registry_data.get("expiresDate", "N/A"),
                    "whois_server": registry_data.get("whoisServer", "N/A"),
                },
                "domain_availability": record.get("domainAvailability", "N/A"),
                "contact_email": record.get("contactEmail", "N/A"),
                "estimated_domain_age": record.get("estimatedDomainAge", "N/A"),
                "ips": ", ".join(record.get("ips", ["N/A"])),
            }
            return domain_details
        else:
            return {"error": "No WhoisRecord found"}
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}
    except json.JSONDecodeError:
        return {"error": "Failed to decode JSON response from API"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def find_max_buffer(website_name):
    """Find the maximum buffer size for the website."""
    low, high = 1000, 1500
    last_working_size = 0
    ttl_hops = get_ttl_hops(website_name)
    latency = get_latency(website_name)
    packet_loss = get_packet_loss(website_name)
    geo_location = get_geo_location(website_name)
    domain_details = get_domain_details(website_name)

    with tqdm(total=(high - low), desc=f"{Fore.GREEN}{website_name}{Style.RESET_ALL}", leave=False, bar_format="{l_bar}{bar}{r_bar}") as pbar:
        while low <= high:
            buffer_size = (low + high) // 2

            command = ["ping", website_name, "-c", "1", "-M", "do", "-s", str(buffer_size)] if platform.system().lower() != "windows" else ["ping", website_name, "-n", "1", "-f", "-l", str(buffer_size)]

            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout

            if "TTL=" in output:
                last_working_size = buffer_size
                low = buffer_size + 1
            elif "Packet needs to be fragmented" in output or "Message too long" in result.stderr:
                high = buffer_size - 1
            else:
                low = buffer_size + 1

            pbar.update(1)

    return [website_name, last_working_size, ttl_hops, latency, packet_loss, geo_location, domain_details]

def generate_html_report(results, website_name, filename=None):
    """Generate a more advanced, visually stunning, and interactive HTML report with advanced search, pagination, charts, and dynamic table sorting."""
    if not filename:
        filename = f"reports/{website_name}_buffer_results_{time.strftime('%Y%m%d_%H%M%S')}.html"

    html_content = f"""
    <html>
    <head>
        <title>Advanced Buffer Checker Report</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap');
            body {{
                font-family: 'Poppins', sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(to right, #2c3e50, #4ca1af);
                color: #fff;
                transition: background 0.5s, color 0.5s;
            }}
            .container {{
                max-width: 1100px;
                margin: auto;
                padding: 25px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                backdrop-filter: blur(10px);
            }}
            .header {{
                font-size: 35px;
                font-weight: bold;
                text-align: center;
                padding-bottom: 15px;
                border-bottom: 4px solid #fff;
                margin-bottom: 20px;
                animation: fadeIn 1.5s ease-in-out;
            }}
            .website-section {{
                margin-bottom: 25px;
                padding: 20px;
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.2);
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                animation: slideIn 1s ease-in-out;
                transition: transform 0.3s ease-in-out;
            }}
            .website-section:hover {{
                transform: scale(1.05);
                box-shadow: 0 6px 15px rgba(0,0,0,0.3);
            }}
            .website-title {{
                font-size: 24px;
                font-weight: bold;
                color: #f1c40f;
                margin-bottom: 10px;
                transition: color 0.3s ease-in-out;
            }}
            .website-title:hover {{
                color: #e67e22;
            }}
            .detail-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                animation: fadeIn 1.5s ease-in-out;
            }}
            .detail-table th, .detail-table td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
                color: #fff;
            }}
            .detail-table th {{
                background-color: #f1c40f;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                color: #ddd;
                font-size: 15px;
                animation: fadeIn 2s ease-in-out;
            }}
            /* Dark Mode */
            body.dark-mode {{
                background: #1c1c1c;
                color: #fff;
            }}
            .container.dark-mode {{
                background: rgba(255, 255, 255, 0.2);
            }}
            .header.dark-mode {{
                color: #f1c40f;
            }}
            .website-section.dark-mode {{
                background: rgba(255, 255, 255, 0.3);
                box-shadow: 0 4px 12px rgba(255, 255, 255, 0.3);
            }}
            /* Pagination */
            .pagination {{
                display: flex;
                justify-content: center;
                margin-top: 20px;
            }}
            .pagination button {{
                background-color: #f1c40f;
                border: none;
                color: white;
                padding: 10px 15px;
                text-align: center;
                font-size: 16px;
                cursor: pointer;
                border-radius: 5px;
                margin: 0 5px;
                transition: background 0.3s;
            }}
            .pagination button:hover {{
                background-color: #e67e22;
            }}
            /* Search Input */
            #search-input {{
                padding: 10px;
                margin-bottom: 20px;
                width: 100%;
                font-size: 16px;
                border-radius: 5px;
                border: 1px solid #ddd;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; }} to {{ opacity: 1; }}
            }}
            @keyframes slideIn {{
                from {{ transform: translateY(20px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }}
            }}
        </style>
        <!-- Add Chart.js for visualizing data -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="container">
            <div class="header">🚀 Advanced Buffer Checker Report</div>
            
            <!-- Search Bar -->
            <input type="text" id="search-input" placeholder="Search websites..." onkeyup="searchFunction()" />

            <!-- Chart Placeholder -->
            <canvas id="latencyChart" width="400" height="200"></canvas>
            
            <div id="website-sections">
    """
    
    # Add website sections and data for the chart
    latency_data = []
    labels = []
    for result in results:
        website_name, max_buffer_size, ttl_hops, latency, packet_loss, geo_location, domain_details = result
        
        labels.append(website_name)
        latency_data.append(latency)
        
        html_content += f"""
            <div class="website-section">
                <h2 class="website-title">{website_name}</h2>
                <table class="detail-table">
                    <tr><th>Parameter</th><th>Value</th></tr>
                    <tr><td>Max Buffer Size</td><td>{max_buffer_size} bytes</td></tr>
                    <tr><td>TTL Hops</td><td>{ttl_hops}</td></tr>
                    <tr><td>Latency</td><td>{latency} ms</td></tr>
                    <tr><td>Packet Loss</td><td>{packet_loss}</td></tr>
                    <tr><td>Geo Location</td><td>{geo_location}</td></tr>
                </table>
                <h3 class="website-title">Domain Details</h3>
        """
        
        if isinstance(domain_details, dict):
            html_content += "<table class='detail-table'>"
            for key, value in domain_details.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        html_content += f"<tr><td>{sub_key.replace('_', ' ').title()}</td><td>{sub_value or 'N/A'}</td></tr>"
                else:
                    html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value or 'N/A'}</td></tr>"
            html_content += "</table>"
        else:
            html_content += "<p style='color: red;'><strong>Error:</strong> Invalid domain details format</p>"
        
        html_content += "</div>"  # Close website-section
    
    html_content += f"""
            </div> <!-- End website-sections -->
            
            <!-- Pagination buttons -->
            <div class="pagination">
                <button onclick="prevPage()">Previous</button>
                <button onclick="nextPage()">Next</button>
            </div>
            
            <div class="footer">Report generated on {time.strftime('%Y-%m-%d %H:%M:%S')} by Advanced Buffer Checker</div>
        </div>

        <script>
            // Chart.js for latency data
            var ctx = document.getElementById('latencyChart').getContext('2d');
            var latencyChart = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: {labels},
                    datasets: [{{ 
                        label: 'Latency (ms)', 
                        data: {latency_data}, 
                        backgroundColor: 'rgba(241, 196, 15, 0.5)', 
                        borderColor: 'rgba(241, 196, 15, 1)', 
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});

            // Search function for filtering
            function searchFunction() {{
                var input = document.getElementById("search-input");
                var filter = input.value.toLowerCase();
                var sections = document.querySelectorAll(".website-section");
                sections.forEach(function(section) {{
                    var title = section.querySelector(".website-title").textContent;
                    if (title.toLowerCase().includes(filter)) {{
                        section.style.display = "block";
                    }} else {{
                        section.style.display = "none";
                    }}
                }});
            }}
            
            // Pagination logic (Simple example)
            var currentPage = 1;
            var itemsPerPage = 5;
            function showPage(page) {{
                var sections = document.querySelectorAll(".website-section");
                sections.forEach(function(section, index) {{
                    if (index >= (page - 1) * itemsPerPage && index < page * itemsPerPage) {{
                        section.style.display = "block";
                    }} else {{
                        section.style.display = "none";
                    }}
                }});
            }}
            function prevPage() {{
                if (currentPage > 1) {{
                    currentPage--;
                    showPage(currentPage);
                }}
            }}
            function nextPage() {{
                currentPage++;
                showPage(currentPage);
            }}
            showPage(currentPage);
        </script>
    </body>
    </html>
    """
    
    with open(filename, "w", encoding="utf-8") as htmlfile:
        htmlfile.write(html_content)

def main():
    """Main function to execute the script."""
    print_banner()
    
    # Allow user to input websites
    websites = input("Enter websites (comma-separated): ").split(",")
    websites = [website.strip() for website in websites if website.strip()]
    
    if not websites:
        print("No websites provided. Exiting.")
        return

    results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(find_max_buffer, website): website for website in websites}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    print("\n✅ All tests completed.\n")
    
    # Display table in terminal without domain details
    table_data = [[res[0], res[1], res[2], res[3], res[4], res[5]] for res in results]
    print(tabulate(table_data, headers=["Website", "Max Buffer Size (bytes)", "TTL Hops", "Latency (ms)", "Packet Loss", "Geo Location"], tablefmt="fancy_grid"))

    # Generate HTML report for each website
    for result in results:
        website_name = result[0]
        generate_html_report([result], website_name)
        print(f"📂 Report for {website_name} saved to reports/{website_name}_buffer_results_{time.strftime('%Y%m%d_%H%M%S')}.html")

if __name__ == "__main__":

    main()