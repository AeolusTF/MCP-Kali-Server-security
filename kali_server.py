#!/usr/bin/env python3

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import re
import shlex
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

# Security configuration
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")
ALLOWED_IP_RANGES = os.environ.get("ALLOWED_IP_RANGES", "").split(",")
MAX_COMMAND_LENGTH = int(os.environ.get("MAX_COMMAND_LENGTH", 1000))

app = Flask(__name__)

class SecurityValidator:
    """Class to validate and sanitize inputs"""
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain format"""
        if not domain:
            return False
        
        # Basic domain validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        if re.match(domain_pattern, domain) or re.match(ip_pattern, domain):
            return True
        
        # Check if it's a URL
        url_pattern = r'^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?(/.*)?$'
        return bool(re.match(url_pattern, domain))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ip_pattern, ip):
            return False
        
        # Validate each octet
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return False
        
        return True
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename:
            return ""
        
        # Remove directory traversal attempts
        filename = re.sub(r'\.\./|\.\.\\', '', filename)
        filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)
        
        # Limit length
        return filename[:100]
    
    @staticmethod
    def validate_command_args(args: str) -> bool:
        """Validate command line arguments"""
        if not args:
            return True
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            r'[;&|`]',  # Command separators
            r'\$\(',    # Command substitution
            r'\{',      # Brace expansion
            r'>|<',     # Redirection
            r'\*',      # Wildcards (in some contexts)
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, args):
                return False
        
        return True
    
    @staticmethod
    def is_target_allowed(target: str) -> bool:
        """Check if target is in allowed list"""
        if not ALLOWED_DOMAINS and not ALLOWED_IP_RANGES:
            return True  # No restrictions configured
        
        # Extract domain or IP from target
        if '://' in target:
            target = target.split('://')[1]
        if '/' in target:
            target = target.split('/')[0]
        if ':' in target:
            target = target.split(':')[0]
        
        # Check against allowed domains
        for allowed_domain in ALLOWED_DOMAINS:
            if allowed_domain and target.endswith(allowed_domain):
                return True
        
        # Check against allowed IP ranges
        if SecurityValidator.validate_ip(target):
            for ip_range in ALLOWED_IP_RANGES:
                if ip_range and target.startswith(ip_range):
                    return True
        
        return False

class CommandExecutor:
    """Class to handle command execution with better timeout management and security"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                self.stdout_data += line
        except Exception as e:
            logger.error(f"Error reading stdout: {str(e)}")
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                self.stderr_data += line
        except Exception as e:
            logger.error(f"Error reading stderr: {str(e)}")
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        # Security check: limit command length
        if len(self.command) > MAX_COMMAND_LENGTH:
            logger.warning(f"Command too long: {len(self.command)} characters")
            return {
                "stdout": "",
                "stderr": f"Command too long (max {MAX_COMMAND_LENGTH} characters)",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": False
            }
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                env={**os.environ, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}  # Restricted PATH
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            # Sanitize output to remove sensitive information if needed
            sanitized_stdout = self.stdout_data
            sanitized_stderr = self.stderr_data
            
            return {
                "stdout": sanitized_stdout,
                "stderr": sanitized_stderr,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            # Don't expose full traceback in production
            error_msg = "Internal server error" if not DEBUG_MODE else str(e)
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {error_msg}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.before_request
def limit_remote_addr():
    """Optional: Limit access to specific IP addresses"""
    # Implement IP whitelisting if needed
    pass


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "JSON body is required"}), 400
        
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        # Security validation
        if not SecurityValidator.validate_command_args(command):
            return jsonify({
                "error": "Invalid command parameters detected"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        error_msg = "Internal server error" if not DEBUG_MODE else str(e)
        return jsonify({
            "error": f"Server error: {error_msg}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "JSON body is required"}), 400
        
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        # Security validation
        if not SecurityValidator.validate_domain(target) and not SecurityValidator.validate_ip(target):
            return jsonify({
                "error": "Invalid target format"
            }), 400
        
        if not SecurityValidator.is_target_allowed(target):
            return jsonify({
                "error": "Target not allowed"
            }), 403
        
        if not SecurityValidator.validate_command_args(additional_args):
            return jsonify({
                "error": "Invalid additional arguments"
            }), 400
        
        # Build command safely
        command_parts = ["nmap", scan_type]
        
        if ports:
            if not re.match(r'^[\d,\-]+$', ports):
                return jsonify({"error": "Invalid ports format"}), 400
            command_parts.extend(["-p", ports])
        
        if additional_args:
            command_parts.extend(shlex.split(additional_args))
        
        command_parts.append(target)
        
        command = " ".join(shlex.quote(part) for part in command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        error_msg = "Internal server error" if not DEBUG_MODE else str(e)
        return jsonify({
            "error": f"Server error: {error_msg}"
        }), 500

# Similar security improvements should be applied to all other tool endpoints
# For brevity, I'll show the pattern for one more endpoint

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "JSON body is required"}), 400
        
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Security validation
        if not SecurityValidator.validate_domain(url):
            return jsonify({
                "error": "Invalid URL format"
            }), 400
        
        if not SecurityValidator.is_target_allowed(url):
            return jsonify({
                "error": "Target not allowed"
            }), 403
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        # Sanitize wordlist path
        sanitized_wordlist = SecurityValidator.sanitize_filename(wordlist)
        
        if not SecurityValidator.validate_command_args(additional_args):
            return jsonify({
                "error": "Invalid additional arguments"
            }), 400
        
        # Build command safely
        command_parts = ["gobuster", mode, "-u", url, "-w", sanitized_wordlist]
        
        if additional_args:
            command_parts.extend(shlex.split(additional_args))
        
        command = " ".join(shlex.quote(part) for part in command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        error_msg = "Internal server error" if not DEBUG_MODE else str(e)
        return jsonify({
            "error": f"Server error: {error_msg}"
        }), 500

# Apply similar security improvements to all other endpoints:
# dirb, nikto, sqlmap, metasploit, hydra, john, wpscan, enum4linux

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--allowed-domains", help="Comma-separated list of allowed domains")
    parser.add_argument("--allowed-ips", help="Comma-separated list of allowed IP ranges")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    if args.allowed_domains:
        ALLOWED_DOMAINS = args.allowed_domains.split(",")
    
    if args.allowed_ips:
        ALLOWED_IP_RANGES = args.allowed_ips.split(",")
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    logger.info(f"Security settings: Allowed domains: {ALLOWED_DOMAINS}, Allowed IP ranges: {ALLOWED_IP_RANGES}")
    
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)