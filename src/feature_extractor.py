"""
Feature Extractor Module
استخراج ویژگی‌ها از آدرس‌های IPv6 برای مدل ML
"""

import ipaddress
import math
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from collections import Counter
import logging

logger = logging.getLogger(__name__)


@dataclass
class IPv6Features:
    """Features extracted from an IPv6 address"""
    address: str
    nibbles: List[int]  # 32 nibbles (4-bit values)
    feature_vector: np.ndarray
    feature_names: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'nibbles': self.nibbles,
            'features': dict(zip(self.feature_names, self.feature_vector.tolist()))
        }


class IPv6FeatureExtractor:
    """
    Extract features from IPv6 addresses for machine learning.
    
    Features include:
    - Nibble values (32 nibbles)
    - Entropy measures
    - Pattern features (zeros, ones, sequences)
    - Allocation type features
    - Statistical features
    """
    
    # Known prefix patterns
    KNOWN_PREFIXES = {
        '2001:db8': 'documentation',      # Documentation prefix
        '2001:4860': 'google',             # Google
        '2606:4700': 'cloudflare',         # Cloudflare
        '2400:cb00': 'cloudflare',         # Cloudflare
        '2a00:1450': 'google',             # Google
        '2607:f8b0': 'google',             # Google
        '2a03:2880': 'facebook',           # Facebook
        '2620:1ec': 'amazon',              # Amazon
    }
    
    def __init__(self):
        self.feature_names = self._get_feature_names()
        
    def _get_feature_names(self) -> List[str]:
        """Get names of all features"""
        names = []
        
        # Nibble features (32 nibbles)
        for i in range(32):
            names.append(f'nibble_{i}')
        
        # Entropy features
        names.extend([
            'entropy_full',           # Entropy of all nibbles
            'entropy_network',        # Entropy of network part (first 64 bits)
            'entropy_interface',      # Entropy of interface part (last 64 bits)
        ])
        
        # Zero features
        names.extend([
            'zero_nibble_count',      # Count of zero nibbles
            'zero_nibble_ratio',      # Ratio of zero nibbles
            'max_zero_run',           # Maximum consecutive zeros
            'zero_run_count',         # Number of zero runs
        ])
        
        # Pattern features
        names.extend([
            'unique_nibbles',         # Number of unique nibble values
            'max_nibble_freq',        # Most frequent nibble frequency
            'is_eui64',               # Whether it looks like EUI-64
            'has_embedded_ipv4',      # Whether it has embedded IPv4
            'low_byte_pattern',       # Pattern in low bytes
        ])
        
        # Prefix features
        names.extend([
            'prefix_type',            # Known prefix type (encoded)
            'first_nibble',           # First nibble value
            'second_nibble',          # Second nibble value
        ])
        
        # Statistical features
        names.extend([
            'nibble_mean',            # Mean of nibble values
            'nibble_std',             # Standard deviation
            'nibble_median',          # Median
            'nibble_skewness',        # Skewness
        ])
        
        # Segment features
        names.extend([
            'segment_diversity',      # How different are the 8 segments
            'segment_pattern',        # Pattern type (all same, sequential, etc.)
        ])
        
        return names
    
    def address_to_nibbles(self, address: str) -> List[int]:
        """Convert IPv6 address to 32 nibbles (4-bit values)"""
        try:
            ip = ipaddress.IPv6Address(address)
            # Get the packed bytes (16 bytes = 128 bits)
            packed = ip.packed
            nibbles = []
            for byte in packed:
                nibbles.append((byte >> 4) & 0xF)  # High nibble
                nibbles.append(byte & 0xF)          # Low nibble
            return nibbles
        except Exception as e:
            logger.error(f"Error converting address {address}: {e}")
            return [0] * 32
    
    def calculate_entropy(self, nibbles: List[int]) -> float:
        """Calculate Shannon entropy of nibbles"""
        if not nibbles:
            return 0.0
        
        counts = Counter(nibbles)
        total = len(nibbles)
        entropy = 0.0
        
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def find_zero_runs(self, nibbles: List[int]) -> Tuple[int, int]:
        """Find maximum zero run and count of zero runs"""
        max_run = 0
        current_run = 0
        run_count = 0
        
        for nibble in nibbles:
            if nibble == 0:
                current_run += 1
            else:
                if current_run > 0:
                    run_count += 1
                    max_run = max(max_run, current_run)
                current_run = 0
        
        if current_run > 0:
            run_count += 1
            max_run = max(max_run, current_run)
        
        return max_run, run_count
    
    def is_eui64(self, nibbles: List[int]) -> bool:
        """Check if address appears to be EUI-64 format"""
        # EUI-64 has ff:fe in the middle of interface ID
        # Interface ID is the last 64 bits (last 16 nibbles)
        interface_nibbles = nibbles[16:]
        
        # Check for ff:fe pattern (nibbles 6-9 of interface ID)
        if len(interface_nibbles) >= 10:
            # ff:fe would be nibbles at positions 6,7,8,9 being f,f,f,e
            if (interface_nibbles[6] == 0xf and 
                interface_nibbles[7] == 0xf and
                interface_nibbles[8] == 0xf and 
                interface_nibbles[9] == 0xe):
                return True
        return False
    
    def has_embedded_ipv4(self, nibbles: List[int]) -> bool:
        """Check if address has embedded IPv4 (last 32 bits)"""
        # Common pattern: ::ffff:IPv4 or ::IPv4
        # Check if first 24 nibbles are mostly zeros
        first_24 = nibbles[:24]
        zero_count = sum(1 for n in first_24 if n == 0)
        return zero_count >= 20
    
    def get_prefix_type(self, address: str) -> int:
        """Get encoded prefix type"""
        address_lower = address.lower()
        for prefix, ptype in self.KNOWN_PREFIXES.items():
            if address_lower.startswith(prefix.lower()):
                return hash(ptype) % 100  # Simple encoding
        return 0
    
    def calculate_skewness(self, values: List[int]) -> float:
        """Calculate skewness of values"""
        if len(values) < 3:
            return 0.0
        
        n = len(values)
        mean = sum(values) / n
        
        # Calculate moments
        m2 = sum((x - mean) ** 2 for x in values) / n
        m3 = sum((x - mean) ** 3 for x in values) / n
        
        if m2 == 0:
            return 0.0
        
        return m3 / (m2 ** 1.5)
    
    def get_segment_diversity(self, address: str) -> float:
        """Calculate diversity of 8 segments (16-bit groups)"""
        try:
            ip = ipaddress.IPv6Address(address)
            # Explode to full form and split
            exploded = ip.exploded
            segments = exploded.split(':')
            unique_segments = len(set(segments))
            return unique_segments / 8.0
        except:
            return 0.0
    
    def get_low_byte_pattern(self, nibbles: List[int]) -> int:
        """Analyze pattern in low bytes"""
        # Check last 4 nibbles (2 bytes)
        last_4 = nibbles[-4:]
        
        # Pattern types:
        # 0 = all zeros
        # 1 = sequential (like 0,1,2,3)
        # 2 = low values (all < 4)
        # 3 = high values (all >= 12)
        # 4 = mixed
        
        if all(n == 0 for n in last_4):
            return 0
        if last_4 == list(range(last_4[0], last_4[0] + 4)):
            return 1
        if all(n < 4 for n in last_4):
            return 2
        if all(n >= 12 for n in last_4):
            return 3
        return 4
    
    def extract_features(self, address: str) -> IPv6Features:
        """Extract all features from an IPv6 address"""
        nibbles = self.address_to_nibbles(address)
        features = []
        
        # 1. Nibble features (32 values)
        features.extend(nibbles)
        
        # 2. Entropy features
        features.append(self.calculate_entropy(nibbles))
        features.append(self.calculate_entropy(nibbles[:16]))  # Network part
        features.append(self.calculate_entropy(nibbles[16:]))  # Interface part
        
        # 3. Zero features
        zero_count = sum(1 for n in nibbles if n == 0)
        features.append(zero_count)
        features.append(zero_count / 32.0)
        max_zero_run, zero_run_count = self.find_zero_runs(nibbles)
        features.append(max_zero_run)
        features.append(zero_run_count)
        
        # 4. Pattern features
        features.append(len(set(nibbles)))
        counts = Counter(nibbles)
        features.append(max(counts.values()) / 32.0)
        features.append(1 if self.is_eui64(nibbles) else 0)
        features.append(1 if self.has_embedded_ipv4(nibbles) else 0)
        features.append(self.get_low_byte_pattern(nibbles))
        
        # 5. Prefix features
        features.append(self.get_prefix_type(address))
        features.append(nibbles[0] if nibbles else 0)
        features.append(nibbles[1] if len(nibbles) > 1 else 0)
        
        # 6. Statistical features
        features.append(np.mean(nibbles))
        features.append(np.std(nibbles))
        features.append(np.median(nibbles))
        features.append(self.calculate_skewness(nibbles))
        
        # 7. Segment features
        features.append(self.get_segment_diversity(address))
        features.append(0)  # Placeholder for segment pattern
        
        feature_vector = np.array(features, dtype=np.float32)
        
        return IPv6Features(
            address=address,
            nibbles=nibbles,
            feature_vector=feature_vector,
            feature_names=self.feature_names
        )
    
    def extract_features_batch(self, addresses: List[str]) -> Tuple[np.ndarray, List[str]]:
        """Extract features for multiple addresses"""
        features_list = []
        valid_addresses = []
        
        for addr in addresses:
            try:
                features = self.extract_features(addr)
                features_list.append(features.feature_vector)
                valid_addresses.append(addr)
            except Exception as e:
                logger.warning(f"Error extracting features for {addr}: {e}")
        
        if features_list:
            return np.vstack(features_list), valid_addresses
        else:
            return np.array([]), []
    
    def get_feature_count(self) -> int:
        """Get the number of features"""
        return len(self.feature_names)
    
    def get_feature_importance_names(self) -> List[str]:
        """Get feature names for importance analysis"""
        return self.feature_names.copy()


class AddressPatternAnalyzer:
    """Analyze patterns in IPv6 address collections"""
    
    def __init__(self, extractor: Optional[IPv6FeatureExtractor] = None):
        self.extractor = extractor or IPv6FeatureExtractor()
        
    def analyze_prefix_distribution(self, addresses: List[str]) -> Dict[str, int]:
        """Analyze distribution of prefixes"""
        prefix_counts = {}
        
        for addr in addresses:
            try:
                ip = ipaddress.IPv6Address(addr)
                # Get /48 prefix
                network = ipaddress.IPv6Network(f"{addr}/48", strict=False)
                prefix = str(network.network_address)[:19]  # First 4 groups
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
            except:
                continue
        
        return prefix_counts
    
    def find_clusters(self, addresses: List[str], prefix_length: int = 64) -> Dict[str, List[str]]:
        """Group addresses by common prefix"""
        clusters = {}
        
        for addr in addresses:
            try:
                network = ipaddress.IPv6Network(f"{addr}/{prefix_length}", strict=False)
                prefix = str(network.network_address)
                if prefix not in clusters:
                    clusters[prefix] = []
                clusters[prefix].append(addr)
            except:
                continue
        
        return clusters
    
    def get_allocation_pattern(self, addresses: List[str]) -> Dict[str, Any]:
        """Analyze allocation patterns in a set of addresses"""
        if not addresses:
            return {}
        
        features_matrix, valid_addrs = self.extractor.extract_features_batch(addresses)
        
        if len(features_matrix) == 0:
            return {}
        
        return {
            'total_addresses': len(valid_addrs),
            'unique_prefixes_48': len(self.analyze_prefix_distribution(valid_addrs)),
            'mean_entropy': float(np.mean(features_matrix[:, 32])),  # Full entropy
            'mean_zero_ratio': float(np.mean(features_matrix[:, 36])),  # Zero ratio
            'eui64_ratio': float(np.mean(features_matrix[:, 41])),  # EUI-64
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    extractor = IPv6FeatureExtractor()
    
    # Test addresses
    test_addresses = [
        "2001:4860:4860::8888",      # Google DNS
        "2606:4700:4700::1111",      # Cloudflare DNS
        "2607:f8b0:4004:800::200e",  # Google
        "::1",                        # Loopback
        "fe80::1",                    # Link-local
    ]
    
    print("IPv6 Feature Extraction Examples:")
    print("=" * 60)
    
    for addr in test_addresses:
        features = extractor.extract_features(addr)
        print(f"\nAddress: {addr}")
        print(f"  Nibbles: {features.nibbles[:8]}... (first 8)")
        print(f"  Feature vector shape: {features.feature_vector.shape}")
        print(f"  Entropy: {features.feature_vector[32]:.3f}")
        print(f"  Zero ratio: {features.feature_vector[36]:.3f}")
