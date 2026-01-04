#!/usr/bin/env python3
"""
PortScanner Pro - AI-Powered Network Discovery Tool
A real-time network scanner with web UI and AI security analysis
"""

import socket
import subprocess
import threading
import time
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional

# Try to import OpenAI, but make it optional
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: OpenAI library not installed. Install with: pip install openai")

app = Flask(__name__)
CORS(app)

# OpenAI API Key - from environment variable
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')

# Configure OpenAI
if OPENAI_AVAILABLE and OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

# AI Security Analyzer - Generates detailed insights for risky devices
class AISecurityAnalyzer:
    """AI-powered security analysis for network devices using OpenAI"""

    # Known vulnerabilities by port/service
    VULNERABILITY_DATABASE = {
        23: {
            'cve': ['CVE-1999-0504', 'CVE-2000-0705'],
            'severity': 'CRITICAL',
            'exploits_available': True,
            'description': 'Telnet transmits passwords in plain text. Easily intercepted.',
            'remediation': 'Disable Telnet immediately. Use SSH (port 22) instead.'
        },
        21: {
            'cve': ['CVE-1999-0269', 'CVE-2010-0764'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'FTP can transmit credentials in plain text. Anonymous access may be enabled.',
            'remediation': 'Use SFTP (FTP over SSH) or disable if not needed.'
        },
        3389: {
            'cve': ['CVE-2019-1181', 'CVE-2019-1182', 'BlueKeep'],
            'severity': 'CRITICAL',
            'exploits_available': True,
            'description': 'RDP has had critical vulnerabilities. Exposed to internet = very dangerous.',
            'remediation': 'Use VPN instead of exposing RDP. Apply all Windows updates.'
        },
        5900: {
            'cve': ['CVE-2019-20807', 'CVE-2018-15129'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'VNC often has weak authentication or no authentication.',
            'remediation': 'Use SSH tunnel or VPN. Set strong VNC password.'
        },
        22: {
            'cve': ['CVE-2016-0777', 'CVE-2016-0778'],
            'severity': 'MEDIUM',
            'exploits_available': False,
            'description': 'SSH is generally secure but ensure key-based auth, not passwords.',
            'remediation': 'Disable password auth, use SSH keys only. Change default port.'
        },
        445: {
            'cve': ['WannaCry', 'EternalBlue', 'CVE-2017-0144'],
            'severity': 'CRITICAL',
            'exploits_available': True,
            'description': 'SMB has had wormable exploits. Ransomware attacks common.',
            'remediation': 'Block port 445 from internet. Apply all Windows patches.'
        },
        3306: {
            'cve': ['CVE-2012-2122', 'CVE-2016-6662'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'MySQL default configurations can be weak. Brute force attacks common.',
            'remediation': 'Strong password, restrict to localhost, use firewall.'
        },
        1433: {
            'cve': ['CVE-2019-1068', 'CVE-2019-0818'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'SQL Server default configurations may be vulnerable.',
            'remediation': 'Strong passwords, encrypt connections, restrict access.'
        },
        5432: {
            'cve': ['CVE-2019-9193', 'CVE-2018-1058'],
            'severity': 'MEDIUM',
            'exploits_available': False,
            'description': 'PostgreSQL is secure but requires proper configuration.',
            'remediation': 'Use strong passwords, enable SSL, restrict access by IP.'
        },
        139: {
            'cve': ['SMBGhost', 'CVE-2020-0796'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'NetBIOS/SMB1 has known vulnerabilities. Legacy protocol.',
            'remediation': 'Disable SMBv1. Use SMBv3 or newer.'
        },
        135: {
            'cve': ['CVE-2017-8759', 'CVE-2017-11882'],
            'severity': 'MEDIUM',
            'exploits_available': True,
            'description': 'Windows RPC can be exploited for remote code execution.',
            'remediation': 'Block from internet. Keep Windows fully updated.'
        },
        27017: {
            'cve': ['CVE-2017-12468', 'CVE-2015-2365'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'MongoDB often left unsecured with no authentication.',
            'remediation': 'Enable authentication! Never expose to internet without auth.'
        },
        6379: {
            'cve': ['CVE-2019-0740', 'CVE-2019-0739'],
            'severity': 'HIGH',
            'exploits_available': True,
            'description': 'Redis often left unsecured. Can be used for cryptojacking.',
            'remediation': 'Bind to localhost, require authentication, use firewall.'
        }
    }

    @classmethod
    def analyze_device(cls, device_info):
        """AI analysis of a risky device - returns detailed security insights"""
        if device_info['security_level'] not in ['high', 'medium']:
            return None

        analysis = {
            'device_ip': device_info['ip'],
            'device_type': device_info['device_type'],
            'risk_level': device_info['security_level'],
            'analysis': [],
            'recommendations': [],
            'overall_score': 0,
            'summary': ''
        }

        total_severity = 0
        critical_count = 0
        high_count = 0

        for port_info in device_info['open_ports']:
            port = port_info['port']
            vuln_data = cls.VULNERABILITY_DATABASE.get(port)

            if vuln_data:
                severity_score = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
                total_severity += severity_score.get(vuln_data['severity'], 1)

                if vuln_data['severity'] == 'CRITICAL':
                    critical_count += 1
                elif vuln_data['severity'] == 'HIGH':
                    high_count += 1

                finding = {
                    'port': port,
                    'service': port_info['name'],
                    'severity': vuln_data['severity'],
                    'exploits_available': vuln_data['exploits_available'],
                    'description': vuln_data['description'],
                    'remediation': vuln_data['remediation']
                }

                if vuln_data.get('cve'):
                    finding['cve'] = vuln_data['cve']

                analysis['analysis'].append(finding)
                analysis['recommendations'].append(vuln_data['remediation'])

        # Calculate overall security score (0-100, lower is worse)
        analysis['overall_score'] = max(0, 100 - total_severity * 2)

        # Generate AI summary
        analysis['summary'] = cls._generate_summary(
            device_info, critical_count, high_count, analysis['analysis']
        )

        # Remove duplicate recommendations
        analysis['recommendations'] = list(set(analysis['recommendations']))

        return analysis

    @classmethod
    def _generate_summary(cls, device_info, critical_count, high_count, findings):
        """Generate human-readable AI summary"""
        device_name = device_info.get('hostname') or device_info['device_type']
        ip = device_info['ip']

        if critical_count > 0:
            return (
                f"🚨 CRITICAL: {device_name} ({ip}) has {critical_count} critical vulnerability"
                f"{'ies' if critical_count > 1 else 'y'}. Immediate action required. "
                f"This device is actively exploitable and could provide attackers "
                f"with full access to your network."
            )
        elif high_count > 0:
            return (
                f"⚠️ HIGH RISK: {device_name} ({ip}) has {high_count} high-severity "
                f"vulnerabilit{'y' if high_count == 1 else 'ies'}. Attackers could "
                f"potentially exploit these to gain unauthorized access. Review "
                f"and patch as soon as possible."
            )
        else:
            return (
                f"⚡ ATTENTION: {device_name} ({ip}) has services that require "
                f"proper configuration. While not immediately exploitable, these "
                f"should be reviewed to ensure security best practices are followed."
            )

    @classmethod
    def analyze_with_openai(cls, device_info):
        """Use OpenAI GPT for intelligent security analysis"""
        if not OPENAI_AVAILABLE:
            return cls.analyze_device(device_info)

        if device_info['security_level'] not in ['high', 'medium']:
            return None

        # Prepare device info for the AI
        device_name = device_info.get('hostname') or device_info['device_type']
        ip = device_info['ip']
        ports = device_info['open_ports']

        # Build the prompt for OpenAI
        port_info = "\n".join([
            f"- Port {p['port']} ({p['name']}): {p.get('description', 'A service')}"
            for p in ports
        ])

        prompt = f"""You are a cybersecurity expert analyzing a network device. Provide a concise security assessment.

Device Information:
- IP: {ip}
- Device Type: {device_info['device_type']}
- Hostname: {device_name}
- Security Level: {device_info['security_level'].upper()}

Open Ports:
{port_info}

Provide a JSON response with this exact structure:
{{
    "summary": "One sentence summary of the security situation",
    "risk_assessment": "Brief explanation of the risks",
    "recommendations": ["action1", "action2", "action3"],
    "priority": "HIGH/MEDIUM/LOW",
    "attack_scenario": "Brief description of how an attacker could exploit this"
}}

Keep it concise and actionable. Focus on practical security advice."""

        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing network security analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )

            ai_response = response.choices[0].message.content.strip()

            # Try to parse JSON from the response
            try:
                ai_data = json.loads(ai_response)

                analysis = {
                    'device_ip': ip,
                    'device_type': device_info['device_type'],
                    'risk_level': device_info['security_level'],
                    'summary': ai_data.get('summary', ''),
                    'risk_assessment': ai_data.get('risk_assessment', ''),
                    'recommendations': ai_data.get('recommendations', []),
                    'priority': ai_data.get('priority', 'MEDIUM'),
                    'attack_scenario': ai_data.get('attack_scenario', ''),
                    'ai_powered': True,
                    'ports_analyzed': [p['port'] for p in ports]
                }

                return analysis

            except json.JSONDecodeError:
                # If JSON parsing fails, return rule-based analysis
                print(f"OpenAI response not valid JSON, using rule-based analysis")
                return cls.analyze_device(device_info)

        except Exception as e:
            print(f"OpenAI API error: {e}")
            # Fallback to rule-based analysis
            return cls.analyze_device(device_info)

    @classmethod
    def analyze_device(cls, device_info, use_openai=True):
        """Main analysis method - uses OpenAI if available, otherwise rule-based"""
        if use_openai and OPENAI_AVAILABLE:
            return cls.analyze_with_openai(device_info)
        else:
            # Use the original rule-based method
            return cls._analyze_rule_based(device_info)

    @classmethod
    def _analyze_rule_based(cls, device_info):
        """Original rule-based analysis (fallback)"""
        if device_info['security_level'] not in ['high', 'medium']:
            return None

        analysis = {
            'device_ip': device_info['ip'],
            'device_type': device_info['device_type'],
            'risk_level': device_info['security_level'],
            'analysis': [],
            'recommendations': [],
            'overall_score': 0,
            'summary': '',
            'ai_powered': False
        }

        total_severity = 0
        critical_count = 0
        high_count = 0

        for port_info in device_info['open_ports']:
            port = port_info['port']
            vuln_data = cls.VULNERABILITY_DATABASE.get(port)

            if vuln_data:
                severity_score = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
                total_severity += severity_score.get(vuln_data['severity'], 1)

                if vuln_data['severity'] == 'CRITICAL':
                    critical_count += 1
                elif vuln_data['severity'] == 'HIGH':
                    high_count += 1

                finding = {
                    'port': port,
                    'service': port_info['name'],
                    'severity': vuln_data['severity'],
                    'exploits_available': vuln_data['exploits_available'],
                    'description': vuln_data['description'],
                    'remediation': vuln_data['remediation']
                }

                if vuln_data.get('cve'):
                    finding['cve'] = vuln_data['cve']

                analysis['analysis'].append(finding)
                analysis['recommendations'].append(vuln_data['remediation'])

        # Calculate overall security score (0-100, lower is worse)
        analysis['overall_score'] = max(0, 100 - total_severity * 2)

        # Generate AI summary
        analysis['summary'] = cls._generate_summary(
            device_info, critical_count, high_count, analysis['analysis']
        )

        # Remove duplicate recommendations
        analysis['recommendations'] = list(set(analysis['recommendations']))

        return analysis

# Common port services with explanations for non-tech users
SERVICE_INFO = {
    21: {
        'name': 'FTP',
        'description': 'File Transfer Protocol - Used to transfer files between computers',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '📁',
        'what_it_does': 'Lets computers share files. Used by web servers to upload website files.'
    },
    22: {
        'name': 'SSH',
        'description': 'Secure Shell - Remote control of computers',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🔐',
        'what_it_does': 'Allows admins to control devices remotely. Secure way to access servers.'
    },
    23: {
        'name': 'Telnet',
        'description': 'Terminal Protocol - Old remote control (not secure)',
        'risk': 'high',
        'risk_label': 'High Risk',
        'icon': '⚠️',
        'what_it_does': 'Old way to control devices remotely. Not secure - passwords sent in plain text.'
    },
    25: {
        'name': 'SMTP',
        'description': 'Email Server - Sends emails',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '📧',
        'what_it_does': 'Email servers use this to send messages to other email servers.'
    },
    53: {
        'name': 'DNS',
        'description': 'Domain Name System - Internet phonebook',
        'risk': 'safe',
        'risk_label': 'Safe',
        'icon': '📖',
        'what_it_does': 'Translates website names (google.com) to IP addresses. Essential for internet.'
    },
    80: {
        'name': 'HTTP',
        'description': 'Web Server - Hosts websites',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '🌐',
        'what_it_does': 'This device is hosting a website or web application.'
    },
    110: {
        'name': 'POP3',
        'description': 'Email Receiver - Downloads email',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '📥',
        'what_it_does': 'Email clients use this to download messages from a server.'
    },
    135: {
        'name': 'Windows RPC',
        'description': 'Windows Service - Communication between Windows programs',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🪟',
        'what_it_does': 'Windows computers use this for programs to talk to each other.'
    },
    139: {
        'name': 'NetBIOS',
        'description': 'Windows File Sharing - Share files on local network',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '📂',
        'what_it_does': 'Windows file and printer sharing. Lets computers share resources.'
    },
    143: {
        'name': 'IMAP',
        'description': 'Email Access - Manages email on server',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '📬',
        'what_it_does': 'Modern email access. Keeps email on server, syncs across devices.'
    },
    443: {
        'name': 'HTTPS',
        'description': 'Secure Web Server - Secure websites',
        'risk': 'safe',
        'risk_label': 'Safe',
        'icon': '🔒',
        'what_it_does': 'Secure version of web server. Used for online banking, shopping, etc.'
    },
    445: {
        'name': 'SMB',
        'description': 'Windows Sharing - File and printer sharing',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🖨️',
        'what_it_does': 'Modern Windows file sharing. Used for network drives and printers.'
    },
    993: {
        'name': 'IMAPS',
        'description': 'Secure Email - Encrypted email access',
        'risk': 'safe',
        'risk_label': 'Safe',
        'icon': '🔐',
        'what_it_does': 'Secure version of IMAP. Passwords and emails are encrypted.'
    },
    995: {
        'name': 'POP3S',
        'description': 'Secure POP3 - Encrypted email download',
        'risk': 'safe',
        'risk_label': 'Safe',
        'icon': '🔐',
        'what_it_does': 'Secure version of POP3. Protects passwords during email download.'
    },
    1433: {
        'name': 'MSSQL',
        'description': 'Microsoft Database - SQL Server database',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🗄️',
        'what_it_does': 'Microsoft database server. Stores applications data.'
    },
    1521: {
        'name': 'Oracle DB',
        'description': 'Oracle Database - Enterprise database',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🏢',
        'what_it_does': 'Oracle database server. Used by large businesses.'
    },
    3306: {
        'name': 'MySQL',
        'description': 'MySQL Database - Popular database server',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🗄️',
        'what_it_does': 'Very popular database. Powers websites like WordPress, Facebook, etc.'
    },
    3389: {
        'name': 'RDP',
        'description': 'Remote Desktop - Control Windows computer',
        'risk': 'high',
        'risk_label': 'High Risk',
        'icon': '🖥️',
        'what_it_does': 'Remote Desktop Protocol. Lets you control a Windows computer from anywhere.'
    },
    5432: {
        'name': 'PostgreSQL',
        'description': 'PostgreSQL Database - Advanced database',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🐘',
        'what_it_does': 'Advanced database system. Used by many applications and websites.'
    },
    5900: {
        'name': 'VNC',
        'description': 'Remote Screen - Share/control screen',
        'risk': 'high',
        'risk_label': 'High Risk',
        'icon': '👁️',
        'what_it_does': 'Virtual Network Computing. Lets you see and control a computer screen.'
    },
    6379: {
        'name': 'Redis',
        'description': 'Redis Cache - Fast data storage',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '⚡',
        'what_it_does': 'In-memory database. Used for caching and quick data access.'
    },
    7001: {
        'name': 'WebLogic',
        'description': 'Oracle WebLogic - Enterprise web server',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🏢',
        'what_it_does': 'Oracle enterprise application server. Runs business applications.'
    },
    8000: {
        'name': 'HTTP Alt',
        'description': 'Web Server - Alternative web port',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '🌐',
        'what_it_does': 'Another port for web servers. Used for development and testing.'
    },
    8001: {
        'name': 'HTTP Alt',
        'description': 'Web Server - Alternative web port',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '🌐',
        'what_it_does': 'Another port for web servers. Used for development and testing.'
    },
    8080: {
        'name': 'HTTP Proxy',
        'description': 'Web Proxy/Server - Common web port',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '🌐',
        'what_it_does': 'Very common web server port. Used by many web applications.'
    },
    8443: {
        'name': 'HTTPS Alt',
        'description': 'Secure Web - Alternative secure port',
        'risk': 'safe',
        'risk_label': 'Safe',
        'icon': '🔒',
        'what_it_does': 'Alternative port for secure web servers.'
    },
    9000: {
        'name': 'SonarQube',
        'description': 'Code Analysis - Code quality tool',
        'risk': 'low',
        'risk_label': 'Safe',
        'icon': '🔍',
        'what_it_does': 'Code quality and security analysis tool for developers.'
    },
    27017: {
        'name': 'MongoDB',
        'description': 'Mongo Database - NoSQL database',
        'risk': 'medium',
        'risk_label': 'Medium',
        'icon': '🍃',
        'what_it_does': 'Popular NoSQL database. Stores modern application data.'
    },
}

# Device type detection patterns
DEVICE_PATTERNS = {
    'router': {
        'patterns': [r'router', r'gateway', r'asus', r'netgear', r'linksys', r'tp-link', r'd-link', r'fritz'],
        'ports': [53, 80, 443, 8080],
        'icon': '📡',
        'description': 'Routes internet traffic to all your devices'
    },
    'printer': {
        'patterns': [r'printer', r'hp', r'canon', r'epson', r'brother', r'print'],
        'ports': [9100, 515, 631],
        'icon': '🖨️',
        'description': 'Network printer for printing documents'
    },
    'server': {
        'patterns': [r'server', r'nas', r'storage'],
        'ports': [22, 3306, 5432, 1433, 80, 443],
        'icon': '🖥️',
        'description': 'A server computer hosting services or storing data'
    },
    'camera': {
        'patterns': [r'cam', r'camera', r'ipc', r'dahua', r'hikvision'],
        'ports': [80, 554, 8000],
        'icon': '📹',
        'description': 'Security or monitoring camera'
    },
    'tv': {
        'patterns': [r'tv', r'samsung', r'lg', r'sony', r'roku', r'chromecast'],
        'ports': [8080, 8000],
        'icon': '📺',
        'description': 'Smart TV or streaming device'
    },
    'phone': {
        'patterns': [r'iphone', r'android', r'pixel'],
        'icon': '📱',
        'description': 'Mobile device connected to WiFi'
    },
    'laptop': {
        'patterns': [r'laptop', r'macbook', r'notebook'],
        'icon': '💻',
        'description': 'Laptop computer'
    },
    'desktop': {
        'patterns': [r'desktop', r'pc-', r'win-', r'ubuntu'],
        'icon': '🖥️',
        'description': 'Desktop computer'
    },
    'iot': {
        'patterns': [r'iot', r'sensor', r'switch', r'plug', r'bulb'],
        'icon': '💡',
        'description': 'Smart home device (switch, sensor, bulb, etc)'
    },
    'gaming': {
        'patterns': [r'playstation', r'xbox', r'switch', r'ps4', r'ps5'],
        'icon': '🎮',
        'description': 'Gaming console'
    },
}

# Global scan state
scan_results = []
scan_status = {"scanning": False, "progress": 0, "found": 0}


def get_local_ip():
    """Get the local IP address and network segment"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"


def get_network_segment(ip):
    """Get the /24 network segment from an IP"""
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"


def detect_device_type(hostname, open_ports, ip):
    """Detect what type of device this is"""
    hostname_lower = (hostname or "").lower()
    port_numbers = [p['port'] for p in open_ports]

    # Check hostname patterns
    for device_type, info in DEVICE_PATTERNS.items():
        for pattern in info.get('patterns', []):
            if re.search(pattern, hostname_lower):
                return {
                    'type': device_type,
                    'icon': info['icon'],
                    'description': info['description']
                }

    # Check by ports
    for device_type, info in DEVICE_PATTERNS.items():
        if 'ports' in info:
            if any(p in port_numbers for p in info['ports']):
                return {
                    'type': device_type,
                    'icon': info['icon'],
                    'description': info['description']
                }

    # Check if it's likely the gateway (usually .1)
    if ip.endswith('.1') or ip.endswith('.254'):
        return {
            'type': 'router',
            'icon': '📡',
            'description': 'Your router/gateway - connects you to the internet'
        }

    return {
        'type': 'unknown',
        'icon': '📦',
        'description': 'A device on your network'
    }


def get_security_risk(open_ports):
    """Calculate overall security risk level"""
    if not open_ports:
        return {'level': 'safe', 'label': 'Safe', 'color': '#00ff88'}

    high_risk_ports = [23, 3389, 5900, 21]
    medium_risk_ports = [22, 135, 139, 445, 1433, 3306, 5432, 6379, 27017]

    port_numbers = [p['port'] for p in open_ports]

    if any(p in high_risk_ports for p in port_numbers):
        return {'level': 'high', 'label': 'High Risk', 'color': '#ff4757'}
    elif any(p in medium_risk_ports for p in port_numbers):
        return {'level': 'medium', 'label': 'Medium Risk', 'color': '#ffa502'}
    else:
        return {'level': 'low', 'label': 'Low Risk', 'color': '#00d9ff'}


def ping_host(ip):
    """Check if a host is up using ping"""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True,
            text=True,
            timeout=3
        )
        return ip if result.returncode == 0 else None
    except:
        return None


def scan_port(ip, port, timeout=1):
    """Scan a single port on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service_info = SERVICE_INFO.get(port, {
                'name': 'Unknown',
                'description': 'A service running on this port',
                'risk': 'unknown',
                'risk_label': 'Unknown',
                'icon': '❓',
                'what_it_does': 'A service is running on this port'
            })
            return {
                "port": port,
                "name": service_info['name'],
                "description": service_info['description'],
                "risk": service_info['risk'],
                "risk_label": service_info['risk_label'],
                "icon": service_info['icon'],
                "what_it_does": service_info['what_it_does']
            }
    except:
        pass
    return None


def scan_host_ports(ip, ports=None):
    """Scan common ports on a host"""
    if ports is None:
        ports = list(SERVICE_INFO.keys()) + [135, 139, 1433, 1521, 7001, 8000, 8001, 9000, 9100, 515, 554, 631]

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports


def scan_network(network_segment, start_ip=1, end_ip=254):
    """Scan the network for active hosts"""
    global scan_results, scan_status

    scan_results = []
    scan_status = {"scanning": True, "progress": 0, "found": 0}

    hosts_to_scan = [f"{network_segment}.{i}" for i in range(start_ip, end_ip + 1)]
    total = len(hosts_to_scan)

    # Phase 1: Ping sweep to find live hosts
    live_hosts = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts_to_scan}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result:
                live_hosts.append(result)
                scan_status["found"] = len(live_hosts)
            scan_status["progress"] = int((i + 1) / total * 50)

    # Phase 2: Port scan live hosts
    for i, host in enumerate(live_hosts):
        open_ports = scan_host_ports(host)

        try:
            hostname = socket.gethostbyaddr(host)[0]
        except:
            hostname = None

        # Get MAC address
        mac = "Unknown"
        try:
            result = subprocess.run(['arp', '-n', host], capture_output=True, text=True)
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if host in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[2]
                            break
        except:
            pass

        # Detect device type
        device_info = detect_device_type(hostname, open_ports, host)

        # Get security risk
        security = get_security_risk(open_ports)

        host_info = {
            "ip": host,
            "hostname": hostname,
            "mac": mac,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "device_type": device_info['type'],
            "device_icon": device_info['icon'],
            "device_description": device_info['description'],
            "security_level": security['level'],
            "security_label": security['label'],
            "security_color": security['color'],
            "ai_analysis": None  # Will be filled for risky devices
        }
        scan_results.append(host_info)
        scan_status["progress"] = 50 + int((i + 1) / len(live_hosts) * 40)

    # Phase 3: AI Analysis of risky devices only
    risky_devices = [d for d in scan_results if d['security_level'] in ['high', 'medium']]

    if risky_devices:
        scan_status["progress"] = 90
        for i, device in enumerate(risky_devices):
            # Run AI analysis on this risky device
            ai_result = AISecurityAnalyzer.analyze_device(device)
            if ai_result:
                device['ai_analysis'] = ai_result
            scan_status["progress"] = 90 + int((i + 1) / len(risky_devices) * 10)

    scan_status["scanning"] = False
    return scan_results


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/info')
def get_info():
    """Get local network info"""
    local_ip = get_local_ip()
    network = get_network_segment(local_ip)
    return jsonify({
        "local_ip": local_ip,
        "network_segment": network
    })


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a network scan"""
    data = request.json or {}
    network = data.get('network', get_network_segment(get_local_ip()))

    def run_scan():
        scan_network(network)

    thread = threading.Thread(target=run_scan)
    thread.start()

    return jsonify({"status": "started"})


@app.route('/api/status')
def get_status():
    """Get current scan status"""
    return jsonify(scan_status)


@app.route('/api/results')
def get_results():
    """Get scan results"""
    return jsonify(scan_results)


@app.route('/api/stop', methods=['POST'])
def stop_scan():
    """Stop the current scan"""
    scan_status["scanning"] = False
    return jsonify({"status": "stopped"})


@app.route('/api/scan/<ip>', methods=['POST'])
def scan_single_host(ip):
    """Scan a single host for ports"""
    ports = scan_host_ports(ip)
    return jsonify({"ip": ip, "open_ports": ports})


if __name__ == '__main__':
    print("\n" + "="*50)
    print("  PortScanner Pro - Starting Server")
    print("="*50)
    print(f"\nLocal IP: {get_local_ip()}")
    print(f"Network: {get_network_segment(get_local_ip())}.0/24")
    print("\nOpen browser to: http://localhost:5000")
    print("="*50 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
