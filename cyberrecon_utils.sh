#!/bin/bash

# CyberRecon Utility Scripts
# Collection of bash scripts for advanced security reconnaissance
# Author: Senior Security Developer

# Script 1: Advanced Port Scanner with Service Detection
advanced_port_scan() {
    local target=$1
    local output_file="/tmp/portscan_${target//\./_}_$(date +%s).txt"
    
    echo "[+] Starting advanced port scan for $target"
    echo "[+] Output will be saved to: $output_file"
    
    # Top 1000 ports scan with service version detection
    nmap -sS -sV -O -A --top-ports 1000 --script=default,vuln \
         --script-timeout=10s --host-timeout=30m \
         -oN "$output_file" "$target" 2>/dev/null
    
    # UDP scan for top 100 ports
    echo "[+] Scanning UDP ports..."
    nmap -sU --top-ports 100 --script=default \
         -oN "${output_file%.txt}_udp.txt" "$target" 2>/dev/null &
    
    # Wait for main scan to complete
    wait
    
    echo "[+] Port scan completed. Results saved to $output_file"
    return 0
}

# Script 2: Web Application Security Scanner
web_security_scan() {
    local target=$1
    local protocol=${2:-"http"}
    local full_url="${protocol}://${target}"
    
    echo "[+] Starting web application security scan for $full_url"
    
    # Directory and file enumeration
    echo "[+] Running directory enumeration..."
    if command -v dirb &> /dev/null; then
        dirb "$full_url" /usr/share/dirb/wordlists/common.txt \
             -o "/tmp/dirb_${target//\./_}_$(date +%s).txt" 2>/dev/null &
    fi
    
    if command -v gobuster &> /dev/null; then
        gobuster dir -u "$full_url" \
                 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
                 -x php,html,js,txt,xml \
                 -o "/tmp/gobuster_${target//\./_}_$(date +%s).txt" 2>/dev/null &
    fi
    
    # Nikto vulnerability scan
    echo "[+] Running Nikto web vulnerability scan..."
    nikto -h "$full_url" -Format txt \
          -output "/tmp/nikto_${target//\./_}_$(date +%s).txt" 2>/dev/null &
    
    # SSL/TLS security assessment
    if [[ $protocol == "https" ]]; then
        echo "[+] Running SSL/TLS security assessment..."
        if command -v testssl.sh &> /dev/null; then
            testssl.sh --fast "$full_url" \
                      > "/tmp/testssl_${target//\./_}_$(date +%s).txt" 2>/dev/null &
        fi
    fi
    
    wait
    echo "[+] Web security scan completed"
    return 0
}

# Script 3: DNS Enumeration and Subdomain Discovery
dns_enumeration() {
    local domain=$1
    local output_dir="/tmp/dns_enum_${domain//\./_}_$(date +%s)"
    mkdir -p "$output_dir"
    
    echo "[+] Starting comprehensive DNS enumeration for $domain"
    echo "[+] Results will be saved in: $output_dir"
    
    # Basic DNS record enumeration
    echo "[+] Gathering basic DNS records..."
    {
        echo "=== A Records ==="
        dig +short A "$domain"
        echo -e "\n=== AAAA Records ==="
        dig +short AAAA "$domain"
        echo -e "\n=== MX Records ==="
        dig +short MX "$domain"
        echo -e "\n=== NS Records ==="
        dig +short NS "$domain"
        echo -e "\n=== TXT Records ==="
        dig +short TXT "$domain"
        echo -e "\n=== SOA Record ==="
        dig +short SOA "$domain"
    } > "$output_dir/dns_records.txt"
    
    # Subdomain enumeration using multiple tools
    echo "[+] Discovering subdomains..."
    
    # Using subfinder
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -silent > "$output_dir/subfinder_subdomains.txt" 2>/dev/null &
    fi
    
    # Using assetfinder
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$domain" > "$output_dir/assetfinder_subdomains.txt" 2>/dev/null &
    fi
    
    # Using amass
    if command -v amass &> /dev/null; then
        amass enum -passive -d "$domain" > "$output_dir/amass_subdomains.txt" 2>/dev/null &
    fi
    
    # DNS brute force with common subdomains
    echo "[+] Brute forcing common subdomains..."
    common_subs=(www mail ftp admin test dev api blog shop app mobile secure vpn db backup stage prod)
    for sub in "${common_subs[@]}"; do
        if host "${sub}.${domain}" &>/dev/null; then
            echo "${sub}.${domain}" >> "$output_dir/bruteforce_subdomains.txt"
        fi
    done &
    
    wait
    
    # Combine and deduplicate results
    cat "$output_dir"/*_subdomains.txt 2>/dev/null | sort -u > "$output_dir/all_subdomains.txt"
    
    # Validate discovered subdomains
    echo "[+] Validating discovered subdomains..."
    while read -r subdomain; do
        if [[ -n "$subdomain" ]] && host "$subdomain" &>/dev/null; then
            echo "$subdomain" >> "$output_dir/valid_subdomains.txt"
        fi
    done < "$output_dir/all_subdomains.txt"
    
    echo "[+] DNS enumeration completed. Found $(wc -l < "$output_dir/valid_subdomains.txt" 2>/dev/null || echo 0) valid subdomains"
    return 0
}

# Script 4: Network Information Gathering
network_recon() {
    local target=$1
    local output_file="/tmp/network_recon_${target//\./_}_$(date +%s).txt"
    
    echo "[+] Starting network reconnaissance for $target"
    
    {
        echo "=== Network Reconnaissance Report ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo "=================================="
        
        # Ping sweep
        echo -e "\n[+] Connectivity Test:"
        if ping -c 4 "$target" &>/dev/null; then
            echo "✓ Target is reachable"
            ping -c 4 "$target" 2>/dev/null | tail -n 2
        else
            echo "✗ Target is not reachable via ICMP"
        fi
        
        # Traceroute
        echo -e "\n[+] Network Path (Traceroute):"
        traceroute -m 15 "$target" 2>/dev/null || echo "Traceroute failed or not available"
        
        # WHOIS information
        echo -e "\n[+] WHOIS Information:"
        whois "$target" 2>/dev/null | head -n 50 || echo "WHOIS lookup failed"
        
        # Reverse DNS lookup
        echo -e "\n[+] Reverse DNS Lookup:"
        if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            dig +short -x "$target" 2>/dev/null || echo "No reverse DNS record found"
        else
            echo "Target is not an IP address - skipping reverse DNS"
        fi
        
        # Geolocation (if geoiplookup is available)
        echo -e "\n[+] Geolocation Information:"
        if command -v geoiplookup &> /dev/null && [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            geoiplookup "$target" 2>/dev/null || echo "Geolocation lookup failed"
        else
            echo "Geolocation tool not available or target is not an IP"
        fi
        
    } > "$output_file"
    
    echo "[+] Network reconnaissance completed. Report saved to $output_file"
    return 0
}

# Script 5: Vulnerability Assessment Script
vulnerability_assessment() {
    local target=$1
    local scan_type=${2:-"basic"}
    local output_dir="/tmp/vuln_assessment_${target//\./_}_$(date +%s)"
    mkdir -p "$output_dir"
    
    echo "[+] Starting vulnerability assessment for $target"
    echo "[+] Scan type: $scan_type"
    echo "[+] Output directory: $output_dir"
    
    case $scan_type in
        "basic")
            # Basic vulnerability scan
            nmap --script vuln "$target" > "$output_dir/nmap_vuln_basic.txt" 2>/dev/null &
            ;;
        "comprehensive")
            # Comprehensive vulnerability scan
            nmap --script "vuln and not dos" "$target" > "$output_dir/nmap_vuln_comprehensive.txt" 2>/dev/null &
            
            # SMB vulnerability check
            nmap --script smb-vuln* "$target" > "$output_dir/smb_vulns.txt" 2>/dev/null &
            
            # Web application vulnerabilities
            if command -v nikto &> /dev/null; then
                nikto -h "http://$target" -Format txt -output "$output_dir/web_vulns.txt" 2>/dev/null &
            fi
            ;;
        "web")
            # Web-specific vulnerability assessment
            echo "[+] Running web-specific vulnerability tests..."
            
            # SQL injection tests
            if command -v sqlmap &> /dev/null; then
                sqlmap -u "http://$target" --batch --level=1 --risk=1 \
                       --dbs > "$output_dir/sqlmap_results.txt" 2>/dev/null &
            fi
            
            # Cross-site scripting tests
            if command -v xsser &> /dev/null; then
                xsser -u "http://$target" --auto > "$output_dir/xss_results.txt" 2>/dev/null &
            fi
            ;;
    esac
    
    wait
    
    # Generate summary report
    {
        echo "=== Vulnerability Assessment Summary ==="
        echo "Target: $target"
        echo "Scan Type: $scan_type"
        echo "Date: $(date)"
        echo "======================================="
        
        # Count potential vulnerabilities
        vuln_count=0
        for file in "$output_dir"/*.txt; do
            if [[ -f "$file" ]]; then
                local_count=$(grep -i "VULNERABLE\|CRITICAL\|HIGH\|MEDIUM" "$file" 2>/dev/null | wc -l)
                vuln_count=$((vuln_count + local_count))
            fi
        done
        
        echo "Potential vulnerabilities found: $vuln_count"
        echo ""
        
        # List all output files
        echo "Generated reports:"
        ls -la "$output_dir"/*.txt 2>/dev/null || echo "No report files generated"
        
    } > "$output_dir/summary.txt"
    
    echo "[+] Vulnerability assessment completed"
    echo "[+] Summary available at: $output_dir/summary.txt"
    return 0
}

# Script 6: Automated Reconnaissance Workflow
auto_recon() {
    local target=$1
    local recon_type=${2:-"standard"}
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local main_output_dir="/tmp/auto_recon_${target//\./_}_${timestamp}"
    mkdir -p "$main_output_dir"
    
    echo "[+] Starting automated reconnaissance workflow for $target"
    echo "[+] Reconnaissance type: $recon_type"
    echo "[+] Main output directory: $main_output_dir"
    
    # Create log file
    local log_file="$main_output_dir/recon.log"
    exec 1> >(tee -a "$log_file")
    exec 2> >(tee -a "$log_file" >&2)
    
    echo "$(date): Starting automated reconnaissance for $target" >> "$log_file"
    
    case $recon_type in
        "quick")
            echo "[+] Running quick reconnaissance..."
            network_recon "$target"
            advanced_port_scan "$target"
            ;;
        "standard")
            echo "[+] Running standard reconnaissance..."
            network_recon "$target"
            advanced_port_scan "$target"
            if [[ ! $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                dns_enumeration "$target"
            fi
            web_security_scan "$target"
            vulnerability_assessment "$target" "comprehensive"
            ;;
        "web-focused")
            echo "[+] Running web-focused reconnaissance..."
            network_recon "$target"
            web_security_scan "$target" "http"
            web_security_scan "$target" "https"
            vulnerability_assessment "$target" "web"
            ;;
    esac
    
    # Move all temporary files to main output directory
    find /tmp -name "*${target//\./_}*" -type f -newer "$main_output_dir" -exec mv {} "$main_output_dir/" \; 2>/dev/null
    
    # Generate final report
    generate_final_report "$target" "$main_output_dir"
    
    echo "$(date): Automated reconnaissance completed for $target" >> "$log_file"
    echo "[+] Automated reconnaissance completed!"
    echo "[+] All results saved in: $main_output_dir"
    echo "[+] Final report: $main_output_dir/final_report.html"
    
    return 0
}

# Script 7: Report Generator
generate_final_report() {
    local target=$1
    local output_dir=$2
    local report_file="$output_dir/final_report.html"
    
    echo "[+] Generating final HTML report..."
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberRecon Report - $target</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007acc; margin: 0; }
        .section { margin-bottom: 30px; padding: 20px; background: #f9f9f9; border-radius: 5px; border-left: 4px solid #007acc; }
        .section h2 { color: #333; margin-top: 0; }
        .file-content { background: #1e1e1e; color: #f8f8f2; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
        .summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2em; font-weight: bold; color: #007acc; }
        .stat-label { color: #666; margin-top: 5px; }
        .vulnerability { padding: 10px; margin: 5px 0; border-radius: 5px; }
        .vuln-critical { background: #ffebee; border-left: 4px solid #f44336; }
        .vuln-high { background: #fff3e0; border-left: 4px solid #ff9800; }
        .vuln-medium { background: #fff8e1; border-left: 4px solid #ffc107; }
        .vuln-low { background: #e8f5e8; border-left: 4px solid #4caf50; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 CyberRecon Security Assessment Report</h1>
            <p><strong>Target:</strong> $target</p>
            <p><strong>Generated:</strong> $(date)</p>
            <p><strong>Report ID:</strong> $(uuidgen 2>/dev/null || echo "RECON-$(date +%s)")</p>
        </div>

        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-number">$(ls "$output_dir"/*.txt 2>/dev/null | wc -l)</div>
                <div class="stat-label">Report Files Generated</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(grep -r "VULNERABLE\|CRITICAL" "$output_dir" 2>/dev/null | wc -l)</div>
                <div class="stat-label">Potential Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(grep -r "open.*port" "$output_dir" 2>/dev/null | wc -l)</div>
                <div class="stat-label">Open Ports Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$(find "$output_dir" -name "*subdomains*" -exec wc -l {} + 2>/dev/null | tail -1 | cut -d' ' -f1 || echo "0")</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
        </div>
EOF

    # Add sections for each report file
    for file in "$output_dir"/*.txt "$output_dir"/*.log; do
        if [[ -f "$file" ]] && [[ -s "$file" ]]; then
            filename=$(basename "$file")
            echo "        <div class=\"section\">" >> "$report_file"
            echo "            <h2>   ${filename}</h2>" >> "$report_file"
            echo "            <div class=\"file-content\">" >> "$report_file"
            
            # Sanitize content for HTML
            sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$file" >> "$report_file"
            
            echo "            </div>" >> "$report_file"
            echo "        </div>" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF
        <div class="section">
            <h2>⚠️ Security Recommendations</h2>
            <ul>
                <li><strong>Patch Management:</strong> Ensure all identified vulnerabilities are patched immediately</li>
                <li><strong>Port Security:</strong> Close unnecessary open ports and services</li>
                <li><strong>Access Control:</strong> Implement strong authentication and authorization mechanisms</li>
                <li><strong>Monitoring:</strong> Set up continuous security monitoring and logging</li>
                <li><strong>Regular Assessments:</strong> Conduct periodic security assessments</li>
                <li><strong>Incident Response:</strong> Develop and test incident response procedures</li>
            </ul>
        </div>

        <div class="section">
            <h2>📋 Methodology</h2>
            <p>This security assessment was conducted using industry-standard tools and techniques:</p>
            <ul>
                <li><strong>Network Scanning:</strong> Nmap for port discovery and service enumeration</li>
                <li><strong>Web Security:</strong> Nikto for web vulnerability assessment</li>
                <li><strong>DNS Enumeration:</strong> Multiple tools for subdomain discovery</li>
                <li><strong>Vulnerability Assessment:</strong> Automated and manual testing approaches</li>
                <li><strong>Information Gathering:</strong> OSINT and passive reconnaissance techniques</li>
            </ul>
        </div>

        <div class="section">
            <h2>⚖️ Disclaimer</h2>
            <p><strong>IMPORTANT:</strong> This security assessment was conducted for authorized testing purposes only. 
            The information in this report should be used responsibly and in accordance with applicable laws and regulations. 
            Unauthorized testing of systems you do not own is illegal and unethical.</p>
        </div>
    </div>
</body>
</html>
EOF

    echo "[+] Final report generated: $report_file"
}

# Script 8: Tool Installer and Environment Setup
setup_environment() {
    echo "[+] Setting up CyberRecon environment..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        echo "[+] Running as root - can install packages"
        INSTALL_CMD="apt-get install -y"
    else
        echo "[!] Not running as root - some installations may fail"
        echo "[!] Please run with sudo for full installation"
        INSTALL_CMD="echo '[SKIP]'"
    fi
    
    # Essential tools list
    TOOLS=(
        "nmap"
        "nikto"
        "sqlmap"
        "dnsutils"
        "whois"
        "traceroute"
        "curl"
        "wget"
        "git"
    )
    
    echo "[+] Installing essential security tools..."
    
    # Update package list
    if [[ $EUID -eq 0 ]]; then
        apt-get update
    fi
    
    # Install each tool
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo "✓ $tool is already installed"
        else
            echo "[+] Installing $tool..."
            $INSTALL_CMD "$tool"
        fi
    done
    
    # Install additional reconnaissance tools
    echo "[+] Setting up additional reconnaissance tools..."
    
    # Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo "[+] Installing subfinder..."
        if [[ $EUID -eq 0 ]]; then
            wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip -O /tmp/subfinder.zip
            unzip -q /tmp/subfinder.zip -d /tmp/
            mv /tmp/subfinder /usr/local/bin/
            chmod +x /usr/local/bin/subfinder
            rm /tmp/subfinder.zip
        fi
    else
        echo "✓ subfinder is already installed"
    fi
    
    # Assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo "[+] Installing assetfinder..."
        if [[ $EUID -eq 0 ]] && command -v go &> /dev/null; then
            go install github.com/tomnomnom/assetfinder@latest
            mv ~/go/bin/assetfinder /usr/local/bin/ 2>/dev/null
        fi
    else
        echo "✓ assetfinder is already installed"
    fi
    
    # Create wordlists directory
    echo "[+] Setting up wordlists..."
    mkdir -p /tmp/wordlists
    
    if [[ ! -f /tmp/wordlists/common.txt ]]; then
        echo "[+] Downloading common wordlists..."
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /tmp/wordlists/common.txt
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O /tmp/wordlists/subdomains.txt
    fi
    
    echo "[+] Environment setup completed!"
    echo "[+] Available tools:"
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo "  ✓ $tool"
        else
            echo "  ✗ $tool (not found)"
        fi
    done
}

# Script 9: Configuration Management
configure_apis() {
    local config_file="$HOME/.cyberrecon/config"
    mkdir -p "$HOME/.cyberrecon"
    
    echo "[+] CyberRecon API Configuration"
    echo "================================"
    
    # Shodan API Key
    read -p "Enter Shodan API Key (press Enter to skip): " shodan_key
    if [[ -n "$shodan_key" ]]; then
        echo "SHODAN_API_KEY=$shodan_key" > "$config_file"
        export SHODAN_API_KEY="$shodan_key"
        echo "✓ Shodan API key configured"
    fi
    
    # VirusTotal API Key
    read -p "Enter VirusTotal API Key (press Enter to skip): " vt_key
    if [[ -n "$vt_key" ]]; then
        echo "VIRUSTOTAL_API_KEY=$vt_key" >> "$config_file"
        export VIRUSTOTAL_API_KEY="$vt_key"
        echo "✓ VirusTotal API key configured"
    fi
    
    # SecurityTrails API Key
    read -p "Enter SecurityTrails API Key (press Enter to skip): " st_key
    if [[ -n "$st_key" ]]; then
        echo "SECURITYTRAILS_API_KEY=$st_key" >> "$config_file"
        export SECURITYTRAILS_API_KEY="$st_key"
        echo "✓ SecurityTrails API key configured"
    fi
    
    echo "[+] Configuration saved to: $config_file"
    echo "[+] To load configuration, run: source $config_file"
}

# Script 10: Main Menu Interface
show_menu() {
    clear
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                          CyberRecon Toolkit                     ║"
    echo "║              Advanced Cybersecurity Reconnaissance              ║"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    echo "║  1. Quick Port Scan              │  6. Vulnerability Assessment ║"
    echo "║  2. Web Security Scan            │  7. Automated Reconnaissance ║"
    echo "║  3. DNS/Subdomain Enumeration    │  8. Setup Environment        ║"
    echo "║  4. Network Reconnaissance       │  9. Configure APIs           ║"
    echo "║  5. Generate Report              │  0. Exit                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo
}

# Main execution function
main() {
    # Load configuration if available
    if [[ -f "$HOME/.cyberrecon/config" ]]; then
        source "$HOME/.cyberrecon/config"
    fi
    
    if [[ $# -eq 0 ]]; then
        # Interactive mode
        while true; do
            show_menu
            read -p "Select an option [0-9]: " choice
            echo
            
            case $choice in
                1)
                    read -p "Enter target (IP/Domain): " target
                    [[ -n "$target" ]] && advanced_port_scan "$target"
                    ;;
                2)
                    read -p "Enter target (IP/Domain): " target
                    [[ -n "$target" ]] && web_security_scan "$target"
                    ;;
                3)
                    read -p "Enter domain: " domain
                    [[ -n "$domain" ]] && dns_enumeration "$domain"
                    ;;
                4)
                    read -p "Enter target (IP/Domain): " target
                    [[ -n "$target" ]] && network_recon "$target"
                    ;;
                5)
                    read -p "Enter target: " target
                    read -p "Enter output directory: " output_dir
                    [[ -n "$target" ]] && [[ -n "$output_dir" ]] && generate_final_report "$target" "$output_dir"
                    ;;
                6)
                    read -p "Enter target: " target
                    echo "Scan types: basic, comprehensive, web"
                    read -p "Enter scan type [basic]: " scan_type
                    scan_type=${scan_type:-basic}
                    [[ -n "$target" ]] && vulnerability_assessment "$target" "$scan_type"
                    ;;
                7)
                    read -p "Enter target: " target
                    echo "Recon types: quick, standard, comprehensive, web-focused"
                    read -p "Enter recon type [standard]: " recon_type
                    recon_type=${recon_type:-standard}
                    [[ -n "$target" ]] && auto_recon "$target" "$recon_type"
                    ;;
                8)
                    setup_environment
                    ;;
                9)
                    configure_apis
                    ;;
                0)
                    echo "Goodbye!"
                    exit 0
                    ;;
                *)
                    echo "Invalid option. Please try again."
                    ;;
            esac
            
            echo
            read -p "Press Enter to continue..."
        done
    else
        # Command line mode
        case $1 in
            "port-scan"|"portscan")
                [[ -n "$2" ]] && advanced_port_scan "$2" || echo "Usage: $0 port-scan <target>"
                ;;
            "web-scan"|"webscan")
                [[ -n "$2" ]] && web_security_scan "$2" || echo "Usage: $0 web-scan <target>"
                ;;
            "dns-enum"|"dnsenum")
                [[ -n "$2" ]] && dns_enumeration "$2" || echo "Usage: $0 dns-enum <domain>"
                ;;
            "network-recon"|"netrecon")
                [[ -n "$2" ]] && network_recon "$2" || echo "Usage: $0 network-recon <target>"
                ;;
            "vuln-scan"|"vulnscan")
                [[ -n "$2" ]] && vulnerability_assessment "$2" "${3:-basic}" || echo "Usage: $0 vuln-scan <target> [scan_type]"
                ;;
            "auto-recon"|"autorecon")
                [[ -n "$2" ]] && auto_recon "$2" "${3:-standard}" || echo "Usage: $0 auto-recon <target> [recon_type]"
                ;;
            "setup")
                setup_environment
                ;;
            "config")
                configure_apis
                ;;
            *)
                echo "Usage: $0 [command] [target] [options]"
                echo "Commands: port-scan, web-scan, dns-enum, network-recon, vuln-scan, auto-recon, setup, config"
                echo "Or run without arguments for interactive mode"
                ;;
        esac
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                dns_enumeration "$target"
            fi
            vulnerability_assessment "$target" "basic"
            ;;
        "comprehensive")
            echo "[+] Running comprehensive reconnaissance..."
            network_recon "$target"
            advanced_port_scan "$target"
             if [[ ! $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                dns_enumeration "$target"
            fi
            web_security_scan "$target" "http"
            web_security_scan "$target" "https"
            vulnerability_assessment "$target" "comprehensive"