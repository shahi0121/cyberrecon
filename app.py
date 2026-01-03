#!/usr/bin/env python3
"""
CyberRecon - Advanced Cybersecurity Reconnaissance Tool
Author: Senior Security Developer
Version: 1.0.0
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import subprocess
import threading
import json
import re
import requests
import time
import os
import uuid
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'cyber_recon_2045_secure_key'
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global storage for scan results
scan_results = {}

class SecurityScanner:
    def __init__(self):
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', 'ca4d9ef09c6bc12b48c919ab3002f2f125ae3e696dadba5ea045f6c8e3ab0905')
        
    def validate_target(self, target):
        """Validate IP address or domain name"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if re.match(ip_pattern, target) or re.match(domain_pattern, target):
            return True
        return False
    
    def run_nmap_scan(self, target, scan_type='basic'):
        """Execute Nmap scan with different scan types"""
        try:
            scan_commands = {
                'basic': f'nmap -sV -sC {target}',
                'aggressive': f'nmap -A -T4 {target}',
                'stealth': f'nmap -sS -O {target}',
                'udp': f'nmap -sU --top-ports 100 {target}',
                'vuln': f'nmap --script vuln {target}'
            }
            
            command = scan_commands.get(scan_type, scan_commands['basic'])
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_nikto_scan(self, target):
        """Execute Nikto web vulnerability scan"""
        try:
            command = f'nikto -h {target} -Format txt'
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=600)
            
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Nikto scan timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_sqlmap_scan(self, target, url_path=''):
        """Execute SQLMap scan for SQL injection vulnerabilities"""
        try:
            full_url = f"http://{target}{url_path}" if url_path else f"http://{target}"
            command = f'sqlmap -u {full_url} --batch --level=1 --risk=1 --dbs'
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr if result.stderr else None
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'SQLMap scan timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def subdomain_enumeration(self, domain):
        """Enumerate subdomains using multiple techniques"""
        try:
            subdomains = set()
            
            # Using subfinder (if available)
            try:
                result = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True, timeout=120)
                if result.stdout:
                    subdomains.update(result.stdout.strip().split('\n'))
            except:
                pass
            
            # Using amass (if available)
            try:
                result = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True, timeout=180)
                if result.stdout:
                    subdomains.update(result.stdout.strip().split('\n'))
            except:
                pass
            
            # Basic DNS enumeration
            common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
            for sub in common_subs:
                try:
                    result = subprocess.run(['nslookup', f'{sub}.{domain}'], capture_output=True, text=True, timeout=5)
                    if 'NXDOMAIN' not in result.stdout:
                        subdomains.add(f'{sub}.{domain}')
                except:
                    continue
            
            return {
                'success': True,
                'subdomains': list(filter(None, subdomains))
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def shodan_lookup(self, target):
        """Query Shodan API for target information"""
        if not self.shodan_api_key:
            return {'success': False, 'error': 'Shodan API key not configured'}
        
        try:
            url = f"https://api.shodan.io/host/{target}?key={self.shodan_api_key}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': f'Shodan API error: {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def virustotal_lookup(self, target):
        """Query VirusTotal API for target information"""
        if not self.virustotal_api_key:
            return {'success': False, 'error': 'VirusTotal API key not configured'}
        
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            
            # For domains
            if not re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', target):
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': f'VirusTotal API error: {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

scanner = SecurityScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a comprehensive security scan"""
    data = request.json
    target = data.get('target', '').strip()
    scan_types = data.get('scan_types', [])
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not scanner.validate_target(target):
        return jsonify({'error': 'Invalid IP address or domain name'}), 400
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        'status': 'running',
        'target': target,
        'started_at': datetime.now().isoformat(),
        'results': {}
    }
    
    # Start scan in background
    thread = threading.Thread(target=execute_scan, args=(scan_id, target, scan_types))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get detailed scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id]['results'])

def execute_scan(scan_id, target, scan_types):
    """Execute the actual security scan"""
    try:
        results = {}
        
        # Nmap scans
        if 'nmap_basic' in scan_types:
            logger.info(f"Running Nmap basic scan on {target}")
            results['nmap_basic'] = scanner.run_nmap_scan(target, 'basic')
        
        if 'nmap_aggressive' in scan_types:
            logger.info(f"Running Nmap aggressive scan on {target}")
            results['nmap_aggressive'] = scanner.run_nmap_scan(target, 'aggressive')
        
        if 'nmap_vuln' in scan_types:
            logger.info(f"Running Nmap vulnerability scan on {target}")
            results['nmap_vuln'] = scanner.run_nmap_scan(target, 'vuln')
        
        # Nikto scan
        if 'nikto' in scan_types:
            logger.info(f"Running Nikto scan on {target}")
            results['nikto'] = scanner.run_nikto_scan(target)
        
        # SQLMap scan
        if 'sqlmap' in scan_types:
            logger.info(f"Running SQLMap scan on {target}")
            results['sqlmap'] = scanner.run_sqlmap_scan(target)
        
        # Subdomain enumeration
        if 'subdomains' in scan_types:
            logger.info(f"Enumerating subdomains for {target}")
            results['subdomains'] = scanner.subdomain_enumeration(target)
        
        # Shodan lookup
        if 'shodan' in scan_types:
            logger.info(f"Querying Shodan for {target}")
            results['shodan'] = scanner.shodan_lookup(target)
        
        # VirusTotal lookup
        if 'virustotal' in scan_types:
            logger.info(f"Querying VirusTotal for {target}")
            results['virustotal'] = scanner.virustotal_lookup(target)
        
        # Update scan results
        scan_results[scan_id]['results'] = results
        scan_results[scan_id]['status'] = 'completed'
        scan_results[scan_id]['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        scan_results[scan_id]['status'] = 'error'
        scan_results[scan_id]['error'] = str(e)

@app.route('/api/tools/ping', methods=['POST'])
def ping_target():
    """Simple ping test"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not scanner.validate_target(target):
        return jsonify({'error': 'Invalid target'}), 400
    
    try:
        result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True, timeout=10)
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr if result.stderr else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/tools/whois', methods=['POST'])
def whois_lookup():
    """WHOIS lookup"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not scanner.validate_target(target):
        return jsonify({'error': 'Invalid target'}), 400
    
    try:
        result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=15)
        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr if result.stderr else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Ensure required directories exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)