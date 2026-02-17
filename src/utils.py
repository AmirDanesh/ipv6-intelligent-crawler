"""
Utility Functions
توابع کمکی پروژه
"""

import ipaddress
import logging
from typing import List, Optional, Tuple
from pathlib import Path
import json
import csv
from datetime import datetime

logger = logging.getLogger(__name__)


def is_valid_ipv6(address: str) -> bool:
    """Check if a string is a valid IPv6 address"""
    try:
        ipaddress.IPv6Address(address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_global_unicast(address: str) -> bool:
    """Check if IPv6 address is globally routable"""
    try:
        ip = ipaddress.IPv6Address(address)
        return ip.is_global
    except:
        return False


def is_private_or_reserved(address: str) -> bool:
    """Check if IPv6 address is private or reserved"""
    try:
        ip = ipaddress.IPv6Address(address)
        return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local
    except:
        return True


def normalize_ipv6(address: str) -> Optional[str]:
    """Normalize an IPv6 address to standard format"""
    try:
        ip = ipaddress.IPv6Address(address)
        return str(ip)
    except:
        return None


def expand_ipv6(address: str) -> Optional[str]:
    """Expand an IPv6 address to full format"""
    try:
        ip = ipaddress.IPv6Address(address)
        return ip.exploded
    except:
        return None


def compress_ipv6(address: str) -> Optional[str]:
    """Compress an IPv6 address to shortest format"""
    try:
        ip = ipaddress.IPv6Address(address)
        return ip.compressed
    except:
        return None


def get_prefix(address: str, prefix_len: int = 64) -> Optional[str]:
    """Get the prefix of an IPv6 address"""
    try:
        network = ipaddress.IPv6Network(f"{address}/{prefix_len}", strict=False)
        return str(network.network_address)
    except:
        return None


def addresses_in_same_prefix(addr1: str, addr2: str, prefix_len: int = 64) -> bool:
    """Check if two addresses are in the same prefix"""
    prefix1 = get_prefix(addr1, prefix_len)
    prefix2 = get_prefix(addr2, prefix_len)
    return prefix1 is not None and prefix1 == prefix2


def filter_valid_addresses(addresses: List[str]) -> List[str]:
    """Filter list to only valid global IPv6 addresses"""
    valid = []
    for addr in addresses:
        if is_valid_ipv6(addr) and is_global_unicast(addr):
            normalized = normalize_ipv6(addr)
            if normalized:
                valid.append(normalized)
    return list(set(valid))  # Remove duplicates


def load_addresses_from_file(filepath: Path) -> List[str]:
    """Load IPv6 addresses from a text file (one per line)"""
    if not filepath.exists():
        logger.warning(f"File not found: {filepath}")
        return []
    
    addresses = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if is_valid_ipv6(line):
                    addresses.append(normalize_ipv6(line))
    
    return addresses


def save_addresses_to_file(addresses: List[str], filepath: Path):
    """Save IPv6 addresses to a text file"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        for addr in addresses:
            f.write(f"{addr}\n")
    logger.info(f"Saved {len(addresses)} addresses to {filepath}")


def export_to_csv(
    data: List[dict],
    filepath: Path,
    fieldnames: Optional[List[str]] = None
):
    """Export data to CSV file"""
    if not data:
        logger.warning("No data to export")
        return
    
    if fieldnames is None:
        fieldnames = list(data[0].keys())
    
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    
    logger.info(f"Exported {len(data)} rows to {filepath}")


def load_from_csv(filepath: Path) -> List[dict]:
    """Load data from CSV file"""
    if not filepath.exists():
        logger.warning(f"File not found: {filepath}")
        return []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def calculate_hit_rate(active: int, total: int) -> Tuple[float, str]:
    """Calculate and format hit rate"""
    if total == 0:
        return 0.0, "0.00%"
    rate = active / total
    return rate, f"{rate * 100:.2f}%"


def estimate_time_remaining(
    completed: int,
    total: int,
    elapsed_seconds: float
) -> Optional[str]:
    """Estimate time remaining for a task"""
    if completed == 0 or total == 0:
        return None
    
    rate = completed / elapsed_seconds  # items per second
    remaining = total - completed
    eta_seconds = remaining / rate
    
    return format_duration(eta_seconds)


class ProgressTracker:
    """Track progress of long-running operations"""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.description = description
        self.completed = 0
        self.start_time = datetime.now()
        self.successes = 0
        self.failures = 0
    
    def update(self, count: int = 1, success: bool = True):
        """Update progress"""
        self.completed += count
        if success:
            self.successes += count
        else:
            self.failures += count
    
    def get_elapsed(self) -> float:
        """Get elapsed time in seconds"""
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_rate(self) -> float:
        """Get items per second"""
        elapsed = self.get_elapsed()
        if elapsed == 0:
            return 0.0
        return self.completed / elapsed
    
    def get_eta(self) -> Optional[str]:
        """Get estimated time to completion"""
        return estimate_time_remaining(
            self.completed,
            self.total,
            self.get_elapsed()
        )
    
    def get_progress_string(self) -> str:
        """Get formatted progress string"""
        pct = (self.completed / self.total * 100) if self.total > 0 else 0
        eta = self.get_eta() or "?"
        rate = self.get_rate()
        
        return (
            f"{self.description}: {self.completed}/{self.total} ({pct:.1f}%) "
            f"- {rate:.1f}/s - ETA: {eta}"
        )
    
    def get_summary(self) -> dict:
        """Get summary statistics"""
        return {
            'total': self.total,
            'completed': self.completed,
            'successes': self.successes,
            'failures': self.failures,
            'elapsed_seconds': self.get_elapsed(),
            'rate_per_second': self.get_rate(),
            'success_rate': self.successes / self.completed if self.completed > 0 else 0
        }


# IPv6-specific utilities

def get_allocation_info(address: str) -> dict:
    """Get allocation information for an IPv6 address"""
    try:
        ip = ipaddress.IPv6Address(address)
        
        # Check first nibble/byte for allocation
        first_byte = (int(ip) >> 120) & 0xFF
        
        info = {
            'address': str(ip),
            'is_global': ip.is_global,
            'is_private': ip.is_private,
            'is_reserved': ip.is_reserved,
            'is_loopback': ip.is_loopback,
            'is_link_local': ip.is_link_local,
            'is_multicast': ip.is_multicast,
        }
        
        # Determine allocation type
        if first_byte == 0x20:
            info['allocation'] = 'Global Unicast (2000::/3)'
        elif first_byte >= 0x20 and first_byte <= 0x3F:
            info['allocation'] = 'Global Unicast'
        elif first_byte == 0xFC or first_byte == 0xFD:
            info['allocation'] = 'Unique Local (fc00::/7)'
        elif first_byte == 0xFE:
            second_nibble = (int(ip) >> 116) & 0xF
            if second_nibble >= 0x8 and second_nibble <= 0xB:
                info['allocation'] = 'Link-Local (fe80::/10)'
            else:
                info['allocation'] = 'Reserved'
        elif first_byte == 0xFF:
            info['allocation'] = 'Multicast (ff00::/8)'
        else:
            info['allocation'] = 'Reserved/Unknown'
        
        return info
    except:
        return {'address': address, 'error': 'Invalid address'}


def estimate_address_space_coverage(
    addresses: List[str],
    prefix_len: int = 48
) -> dict:
    """Estimate coverage of address space"""
    if not addresses:
        return {'coverage': 0, 'prefixes': 0}
    
    prefixes = set()
    for addr in addresses:
        prefix = get_prefix(addr, prefix_len)
        if prefix:
            prefixes.add(prefix)
    
    # Total possible /48 prefixes in 2000::/3 (global unicast)
    # 2^(48-3) = 2^45 prefixes
    total_prefixes = 2 ** (prefix_len - 3)
    
    return {
        'observed_prefixes': len(prefixes),
        'estimated_total_prefixes': total_prefixes,
        'coverage_ratio': len(prefixes) / total_prefixes,
        'prefix_length': prefix_len
    }


# Example usage
if __name__ == "__main__":
    # Test utilities
    test_addr = "2001:4860:4860::8888"
    
    print(f"Address: {test_addr}")
    print(f"Valid: {is_valid_ipv6(test_addr)}")
    print(f"Global: {is_global_unicast(test_addr)}")
    print(f"Expanded: {expand_ipv6(test_addr)}")
    print(f"Prefix /48: {get_prefix(test_addr, 48)}")
    print(f"Allocation: {get_allocation_info(test_addr)}")
