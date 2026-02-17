"""
Infrastructure Fingerprinter Module
شناسایی ویژگی‌های زیرساختی سرورها
"""

import asyncio
import logging
import re
import ssl
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

import aiohttp

from .prober import ProbeResponse, HTTPProber

logger = logging.getLogger(__name__)


class CDNProvider(Enum):
    """Known CDN providers"""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    CLOUDFRONT = "cloudfront"
    AZURE_CDN = "azure_cdn"
    GOOGLE_CLOUD = "google_cloud"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    STACKPATH = "stackpath"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class SecurityHeaders:
    """Security headers analysis"""
    has_hsts: bool = False
    hsts_max_age: Optional[int] = None
    has_csp: bool = False
    has_x_frame_options: bool = False
    has_x_content_type_options: bool = False
    has_x_xss_protection: bool = False
    has_referrer_policy: bool = False
    has_permissions_policy: bool = False
    security_score: float = 0.0
    
    def calculate_score(self):
        """Calculate security score based on headers"""
        score = 0.0
        total = 7
        
        if self.has_hsts:
            score += 1.5  # HSTS is important
        if self.has_csp:
            score += 1.5  # CSP is important
        if self.has_x_frame_options:
            score += 1.0
        if self.has_x_content_type_options:
            score += 1.0
        if self.has_x_xss_protection:
            score += 0.5
        if self.has_referrer_policy:
            score += 0.75
        if self.has_permissions_policy:
            score += 0.75
        
        self.security_score = score / total
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'has_hsts': self.has_hsts,
            'hsts_max_age': self.hsts_max_age,
            'has_csp': self.has_csp,
            'has_x_frame_options': self.has_x_frame_options,
            'has_x_content_type_options': self.has_x_content_type_options,
            'has_x_xss_protection': self.has_x_xss_protection,
            'has_referrer_policy': self.has_referrer_policy,
            'has_permissions_policy': self.has_permissions_policy,
            'security_score': self.security_score
        }


@dataclass
class SSLInfo:
    """SSL/TLS certificate information"""
    has_ssl: bool = False
    ssl_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: bool = False
    is_self_signed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'has_ssl': self.has_ssl,
            'ssl_version': self.ssl_version,
            'cipher_suite': self.cipher_suite,
            'issuer': self.issuer,
            'subject': self.subject,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'is_expired': self.is_expired,
            'is_self_signed': self.is_self_signed
        }


@dataclass
class InfrastructureFingerprint:
    """Complete infrastructure fingerprint for a server"""
    address: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Basic info
    is_web_server: bool = False
    http_port_open: bool = False
    https_port_open: bool = False
    
    # Server identification
    server_software: Optional[str] = None
    powered_by: Optional[str] = None
    detected_tech: List[str] = field(default_factory=list)
    
    # CDN detection
    cdn_provider: CDNProvider = CDNProvider.NONE
    is_behind_cdn: bool = False
    cdn_confidence: float = 0.0
    
    # Security
    security_headers: SecurityHeaders = field(default_factory=SecurityHeaders)
    ssl_info: SSLInfo = field(default_factory=SSLInfo)
    
    # HTTP info
    http_status: Optional[int] = None
    redirects_to_https: bool = False
    
    # Additional metadata
    response_time_ms: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'timestamp': self.timestamp.isoformat(),
            'is_web_server': self.is_web_server,
            'http_port_open': self.http_port_open,
            'https_port_open': self.https_port_open,
            'server_software': self.server_software,
            'powered_by': self.powered_by,
            'detected_tech': self.detected_tech,
            'cdn_provider': self.cdn_provider.value,
            'is_behind_cdn': self.is_behind_cdn,
            'cdn_confidence': self.cdn_confidence,
            'security_headers': self.security_headers.to_dict(),
            'ssl_info': self.ssl_info.to_dict(),
            'http_status': self.http_status,
            'redirects_to_https': self.redirects_to_https,
            'response_time_ms': self.response_time_ms,
        }


class CDNDetector:
    """Detect CDN providers from headers and other signals"""
    
    # CDN detection signatures
    CDN_SIGNATURES = {
        CDNProvider.CLOUDFLARE: {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'server_patterns': [r'cloudflare'],
        },
        CDNProvider.AKAMAI: {
            'headers': ['x-akamai-transformed', 'akamai-origin-hop'],
            'server_patterns': [r'akamai', r'akamaicdn'],
        },
        CDNProvider.FASTLY: {
            'headers': ['x-served-by', 'x-cache', 'fastly-debug-digest'],
            'server_patterns': [r'fastly'],
        },
        CDNProvider.CLOUDFRONT: {
            'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'server_patterns': [r'cloudfront', r'amazon'],
        },
        CDNProvider.AZURE_CDN: {
            'headers': ['x-azure-ref', 'x-ec-custom-error'],
            'server_patterns': [r'azure', r'microsoft'],
        },
        CDNProvider.GOOGLE_CLOUD: {
            'headers': ['x-goog-meta-', 'x-guploader-uploadid'],
            'server_patterns': [r'google', r'gws'],
        },
        CDNProvider.IMPERVA: {
            'headers': ['x-iinfo', 'x-cdn'],
            'server_patterns': [r'imperva', r'incapsula'],
        },
        CDNProvider.SUCURI: {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server_patterns': [r'sucuri'],
        },
    }
    
    def detect(self, headers: Dict[str, str], server_header: Optional[str] = None) -> tuple[CDNProvider, float]:
        """
        Detect CDN provider from headers.
        Returns (provider, confidence)
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        server_lower = server_header.lower() if server_header else ""
        
        best_match = CDNProvider.NONE
        best_confidence = 0.0
        
        for provider, signatures in self.CDN_SIGNATURES.items():
            confidence = 0.0
            
            # Check headers
            for header in signatures['headers']:
                if header.lower() in headers_lower:
                    confidence += 0.4
            
            # Check server patterns
            for pattern in signatures['server_patterns']:
                if re.search(pattern, server_lower, re.IGNORECASE):
                    confidence += 0.5
            
            # Cap at 1.0
            confidence = min(confidence, 1.0)
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = provider
        
        return best_match, best_confidence


class SecurityHeadersAnalyzer:
    """Analyze security headers"""
    
    def analyze(self, headers: Dict[str, str]) -> SecurityHeaders:
        """Analyze security headers from response"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        security = SecurityHeaders()
        
        # HSTS
        if 'strict-transport-security' in headers_lower:
            security.has_hsts = True
            hsts_value = headers_lower['strict-transport-security']
            match = re.search(r'max-age=(\d+)', hsts_value)
            if match:
                security.hsts_max_age = int(match.group(1))
        
        # CSP
        security.has_csp = 'content-security-policy' in headers_lower
        
        # X-Frame-Options
        security.has_x_frame_options = 'x-frame-options' in headers_lower
        
        # X-Content-Type-Options
        security.has_x_content_type_options = 'x-content-type-options' in headers_lower
        
        # X-XSS-Protection
        security.has_x_xss_protection = 'x-xss-protection' in headers_lower
        
        # Referrer-Policy
        security.has_referrer_policy = 'referrer-policy' in headers_lower
        
        # Permissions-Policy / Feature-Policy
        security.has_permissions_policy = (
            'permissions-policy' in headers_lower or
            'feature-policy' in headers_lower
        )
        
        security.calculate_score()
        return security


class TechnologyDetector:
    """Detect server technologies from headers and responses"""
    
    TECH_PATTERNS = {
        'nginx': [r'nginx', r'openresty'],
        'apache': [r'apache', r'httpd'],
        'iis': [r'microsoft-iis', r'iis/'],
        'litespeed': [r'litespeed'],
        'caddy': [r'caddy'],
        'php': [r'php/', r'x-powered-by.*php'],
        'asp.net': [r'asp\.net', r'x-aspnet-version'],
        'nodejs': [r'node', r'express'],
        'python': [r'python', r'gunicorn', r'uwsgi', r'werkzeug'],
        'java': [r'tomcat', r'jetty', r'jboss', r'wildfly'],
        'wordpress': [r'wordpress', r'wp-'],
        'drupal': [r'drupal'],
        'varnish': [r'varnish'],
        'envoy': [r'envoy'],
    }
    
    def detect(self, headers: Dict[str, str]) -> List[str]:
        """Detect technologies from headers"""
        detected = []
        
        # Combine relevant headers
        text_to_check = " ".join([
            headers.get('server', ''),
            headers.get('x-powered-by', ''),
            headers.get('via', ''),
        ]).lower()
        
        # Also check all header names and values
        all_headers = " ".join(f"{k}={v}" for k, v in headers.items()).lower()
        text_to_check += " " + all_headers
        
        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    if tech not in detected:
                        detected.append(tech)
                    break
        
        return detected


class InfrastructureFingerprinter:
    """
    Main fingerprinting class that combines all detection capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10.0)
        
        self.cdn_detector = CDNDetector()
        self.security_analyzer = SecurityHeadersAnalyzer()
        self.tech_detector = TechnologyDetector()
        self.http_prober = HTTPProber(timeout=self.timeout)
    
    async def fingerprint(self, address: str) -> InfrastructureFingerprint:
        """Generate full infrastructure fingerprint for an address"""
        fingerprint = InfrastructureFingerprint(address=address)
        
        # Probe HTTP
        try:
            http_response = await self.http_prober.probe_http(address, port=80)
            fingerprint.http_port_open = http_response.is_active
            
            if http_response.is_active:
                fingerprint.is_web_server = True
                fingerprint.http_status = http_response.http_status
                fingerprint.server_software = http_response.server_header
                fingerprint.response_time_ms = http_response.response_time_ms
                
                # Check for HTTPS redirect
                if http_response.http_status in [301, 302, 307, 308]:
                    fingerprint.redirects_to_https = True
        except Exception as e:
            logger.debug(f"HTTP probe failed for {address}: {e}")
        
        # Probe HTTPS
        try:
            https_response = await self.http_prober.probe_https(address, port=443)
            fingerprint.https_port_open = https_response.is_active
            
            if https_response.is_active:
                fingerprint.is_web_server = True
                fingerprint.ssl_info.has_ssl = True
                
                if https_response.ssl_info:
                    fingerprint.ssl_info.ssl_version = https_response.ssl_info.get('version')
                    cipher = https_response.ssl_info.get('cipher')
                    if cipher:
                        fingerprint.ssl_info.cipher_suite = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                
                # Use HTTPS info if HTTP didn't work
                if not fingerprint.server_software:
                    fingerprint.server_software = https_response.server_header
                if fingerprint.response_time_ms == 0:
                    fingerprint.response_time_ms = https_response.response_time_ms
        except Exception as e:
            logger.debug(f"HTTPS probe failed for {address}: {e}")
        
        # Get full headers for analysis
        if fingerprint.is_web_server:
            headers = await self._fetch_headers(address)
            fingerprint.headers = headers
            
            # CDN detection
            cdn, confidence = self.cdn_detector.detect(headers, fingerprint.server_software)
            fingerprint.cdn_provider = cdn
            fingerprint.is_behind_cdn = cdn != CDNProvider.NONE
            fingerprint.cdn_confidence = confidence
            
            # Security headers
            fingerprint.security_headers = self.security_analyzer.analyze(headers)
            
            # Technology detection
            fingerprint.detected_tech = self.tech_detector.detect(headers)
            
            # X-Powered-By
            fingerprint.powered_by = headers.get('x-powered-by')
        
        return fingerprint
    
    async def _fetch_headers(self, address: str) -> Dict[str, str]:
        """Fetch all headers from an address"""
        headers = {}
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try HTTPS first
                url = f"https://[{address}]/"
                try:
                    async with session.get(url, ssl=ssl_context, allow_redirects=False) as response:
                        headers = dict(response.headers)
                except:
                    # Fall back to HTTP
                    url = f"http://[{address}]/"
                    async with session.get(url, allow_redirects=False) as response:
                        headers = dict(response.headers)
        except Exception as e:
            logger.debug(f"Error fetching headers for {address}: {e}")
        
        return headers
    
    async def fingerprint_batch(
        self,
        addresses: List[str],
        max_concurrent: int = 20
    ) -> Dict[str, InfrastructureFingerprint]:
        """Fingerprint multiple addresses concurrently"""
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fingerprint_with_semaphore(addr: str):
            async with semaphore:
                return addr, await self.fingerprint(addr)
        
        tasks = [fingerprint_with_semaphore(addr) for addr in addresses]
        
        for coro in asyncio.as_completed(tasks):
            addr, fp = await coro
            results[addr] = fp
        
        return results
    
    def summarize_fingerprints(
        self,
        fingerprints: Dict[str, InfrastructureFingerprint]
    ) -> Dict[str, Any]:
        """Generate summary statistics from fingerprints"""
        total = len(fingerprints)
        
        if total == 0:
            return {}
        
        web_servers = sum(1 for fp in fingerprints.values() if fp.is_web_server)
        https_enabled = sum(1 for fp in fingerprints.values() if fp.https_port_open)
        behind_cdn = sum(1 for fp in fingerprints.values() if fp.is_behind_cdn)
        
        # CDN distribution
        cdn_dist = {}
        for fp in fingerprints.values():
            cdn = fp.cdn_provider.value
            cdn_dist[cdn] = cdn_dist.get(cdn, 0) + 1
        
        # Technology distribution
        tech_dist = {}
        for fp in fingerprints.values():
            for tech in fp.detected_tech:
                tech_dist[tech] = tech_dist.get(tech, 0) + 1
        
        # Security score
        security_scores = [
            fp.security_headers.security_score
            for fp in fingerprints.values()
            if fp.is_web_server
        ]
        avg_security = sum(security_scores) / len(security_scores) if security_scores else 0
        
        return {
            'total_addresses': total,
            'web_servers': web_servers,
            'web_server_ratio': web_servers / total,
            'https_enabled': https_enabled,
            'https_ratio': https_enabled / total,
            'behind_cdn': behind_cdn,
            'cdn_ratio': behind_cdn / total,
            'cdn_distribution': cdn_dist,
            'technology_distribution': tech_dist,
            'average_security_score': avg_security,
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def main():
        fingerprinter = InfrastructureFingerprinter()
        
        # Test with some addresses
        test_addresses = [
            "2001:4860:4860::8888",  # Google
            "2606:4700:4700::1111",  # Cloudflare
        ]
        
        print("Fingerprinting test addresses...")
        
        for addr in test_addresses:
            print(f"\nFingerprinting {addr}...")
            fp = await fingerprinter.fingerprint(addr)
            
            print(f"  Web Server: {fp.is_web_server}")
            print(f"  HTTPS: {fp.https_port_open}")
            print(f"  Server: {fp.server_software}")
            print(f"  CDN: {fp.cdn_provider.value} (confidence: {fp.cdn_confidence:.2f})")
            print(f"  Technologies: {fp.detected_tech}")
            print(f"  Security Score: {fp.security_headers.security_score:.2f}")
    
    asyncio.run(main())
