"""
Address Generator Module
تولید آدرس‌های IPv6 جدید بر اساس پیش‌بینی مدل
"""

import ipaddress
import random
import logging
from typing import List, Dict, Any, Optional, Set, Tuple, Generator
from dataclasses import dataclass
from collections import defaultdict
import numpy as np

from .feature_extractor import IPv6FeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class GeneratedAddress:
    """A generated IPv6 address with metadata"""
    address: str
    generation_method: str
    confidence: float
    source_prefix: Optional[str] = None
    source_address: Optional[str] = None
    
    def __hash__(self):
        return hash(self.address)
    
    def __eq__(self, other):
        return self.address == other.address


class IPv6AddressGenerator:
    """
    Generate IPv6 addresses using various strategies:
    1. Prefix-based: Generate addresses in known active prefixes
    2. Pattern-based: Generate based on observed patterns
    3. Mutation-based: Mutate known active addresses
    4. Random-guided: Random generation guided by ML predictions
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.feature_extractor = IPv6FeatureExtractor()
        self.generated: Set[str] = set()
        
        # Known active prefixes and their statistics
        self.active_prefixes: Dict[str, Dict[str, Any]] = {}
        
        # Common interface ID patterns
        self.common_interface_patterns = [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],  # ::1
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],  # ::2
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],  # ::100
            [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],  # ::1:0:0:0:1
        ]
    
    def learn_from_active_addresses(self, addresses: List[str]):
        """Learn patterns from known active addresses"""
        logger.info(f"Learning from {len(addresses)} active addresses...")
        
        for addr in addresses:
            try:
                ip = ipaddress.IPv6Address(addr)
                
                # Extract /48 prefix
                network = ipaddress.IPv6Network(f"{addr}/48", strict=False)
                prefix_48 = str(network.network_address)
                
                if prefix_48 not in self.active_prefixes:
                    self.active_prefixes[prefix_48] = {
                        'count': 0,
                        'addresses': [],
                        'interface_ids': []
                    }
                
                self.active_prefixes[prefix_48]['count'] += 1
                self.active_prefixes[prefix_48]['addresses'].append(addr)
                
                # Extract interface ID (last 64 bits)
                interface_id = int(ip) & ((1 << 64) - 1)
                self.active_prefixes[prefix_48]['interface_ids'].append(interface_id)
                
            except Exception as e:
                logger.debug(f"Error learning from {addr}: {e}")
        
        logger.info(f"Learned {len(self.active_prefixes)} unique /48 prefixes")
    
    def generate_in_prefix(
        self,
        prefix: str,
        count: int = 100,
        strategy: str = 'mixed'
    ) -> List[GeneratedAddress]:
        """Generate addresses within a specific prefix"""
        generated = []
        
        try:
            network = ipaddress.IPv6Network(prefix, strict=False)
            prefix_len = network.prefixlen
            
            # Number of bits available for host part
            host_bits = 128 - prefix_len
            max_hosts = min(2 ** host_bits, 2 ** 32)  # Cap at 4 billion
            
            strategies = ['sequential', 'random', 'common_patterns']
            if strategy == 'mixed':
                # Mix strategies
                per_strategy = count // len(strategies)
            else:
                strategies = [strategy]
                per_strategy = count
            
            for strat in strategies:
                for _ in range(per_strategy):
                    if strat == 'sequential':
                        # Generate low sequential addresses
                        offset = len(generated) + 1
                        addr = network.network_address + offset
                    elif strat == 'common_patterns':
                        # Use common interface patterns
                        pattern_idx = random.randint(0, len(self.common_interface_patterns) - 1)
                        pattern = self.common_interface_patterns[pattern_idx]
                        interface_id = sum(n << (4 * (15 - i)) for i, n in enumerate(pattern))
                        addr = ipaddress.IPv6Address(int(network.network_address) | interface_id)
                    else:  # random
                        offset = random.randint(1, min(max_hosts, 10000))
                        addr = network.network_address + offset
                    
                    addr_str = str(addr)
                    if addr_str not in self.generated:
                        self.generated.add(addr_str)
                        generated.append(GeneratedAddress(
                            address=addr_str,
                            generation_method=f'prefix_{strat}',
                            confidence=0.5,
                            source_prefix=prefix
                        ))
                        
                        if len(generated) >= count:
                            break
                
                if len(generated) >= count:
                    break
                    
        except Exception as e:
            logger.error(f"Error generating in prefix {prefix}: {e}")
        
        return generated
    
    def generate_mutations(
        self,
        source_address: str,
        count: int = 10
    ) -> List[GeneratedAddress]:
        """Generate addresses by mutating a known active address"""
        generated = []
        
        try:
            ip = ipaddress.IPv6Address(source_address)
            nibbles = self.feature_extractor.address_to_nibbles(source_address)
            
            for _ in range(count * 2):  # Generate extra, some might be duplicates
                new_nibbles = nibbles.copy()
                
                # Mutation strategies
                mutation_type = random.choice(['increment', 'decrement', 'nearby', 'last_nibble'])
                
                if mutation_type == 'increment':
                    # Increment the last byte
                    if new_nibbles[-1] < 15:
                        new_nibbles[-1] += 1
                    else:
                        new_nibbles[-1] = 0
                        if new_nibbles[-2] < 15:
                            new_nibbles[-2] += 1
                            
                elif mutation_type == 'decrement':
                    # Decrement the last byte
                    if new_nibbles[-1] > 0:
                        new_nibbles[-1] -= 1
                    else:
                        new_nibbles[-1] = 15
                        if new_nibbles[-2] > 0:
                            new_nibbles[-2] -= 1
                            
                elif mutation_type == 'nearby':
                    # Small random change to interface ID
                    pos = random.randint(24, 31)  # Last 8 nibbles
                    change = random.randint(-2, 2)
                    new_nibbles[pos] = max(0, min(15, new_nibbles[pos] + change))
                    
                else:  # last_nibble
                    # Change just the last nibble
                    new_nibbles[-1] = random.randint(0, 15)
                
                # Convert nibbles back to address
                new_addr = self._nibbles_to_address(new_nibbles)
                
                if new_addr and new_addr not in self.generated:
                    self.generated.add(new_addr)
                    generated.append(GeneratedAddress(
                        address=new_addr,
                        generation_method=f'mutation_{mutation_type}',
                        confidence=0.6,
                        source_address=source_address
                    ))
                    
                    if len(generated) >= count:
                        break
                        
        except Exception as e:
            logger.debug(f"Error mutating {source_address}: {e}")
        
        return generated
    
    def _nibbles_to_address(self, nibbles: List[int]) -> Optional[str]:
        """Convert 32 nibbles back to IPv6 address string"""
        try:
            # Combine nibbles into bytes
            bytes_list = []
            for i in range(0, 32, 2):
                byte_val = (nibbles[i] << 4) | nibbles[i + 1]
                bytes_list.append(byte_val)
            
            # Create IPv6 address from bytes
            addr = ipaddress.IPv6Address(bytes(bytes_list))
            return str(addr)
        except Exception as e:
            logger.debug(f"Error converting nibbles to address: {e}")
            return None
    
    def generate_from_learned_patterns(
        self,
        count: int = 1000
    ) -> List[GeneratedAddress]:
        """Generate addresses based on learned patterns"""
        if not self.active_prefixes:
            logger.warning("No patterns learned yet")
            return []
        
        generated = []
        
        # Sort prefixes by activity count
        sorted_prefixes = sorted(
            self.active_prefixes.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        
        # Generate more addresses in more active prefixes
        total_count = sum(p[1]['count'] for p in sorted_prefixes)
        
        for prefix, stats in sorted_prefixes:
            # Proportional allocation
            prefix_count = max(1, int(count * stats['count'] / total_count))
            
            # Generate in this prefix
            prefix_generated = self.generate_in_prefix(prefix, prefix_count)
            generated.extend(prefix_generated)
            
            # Also mutate known addresses in this prefix
            if stats['addresses']:
                source = random.choice(stats['addresses'])
                mutations = self.generate_mutations(source, prefix_count // 2)
                generated.extend(mutations)
            
            if len(generated) >= count:
                break
        
        return generated[:count]
    
    def generate_random_in_ranges(
        self,
        count: int = 1000
    ) -> List[GeneratedAddress]:
        """Generate random addresses in common allocation ranges"""
        generated = []
        
        # Common IPv6 ranges
        common_ranges = [
            "2001::/16",    # Global Unicast
            "2400::/12",    # APNIC
            "2600::/12",    # ARIN
            "2800::/12",    # LACNIC
            "2a00::/12",    # RIPE NCC
            "2c00::/12",    # AfriNIC
        ]
        
        per_range = count // len(common_ranges)
        
        for range_str in common_ranges:
            try:
                network = ipaddress.IPv6Network(range_str, strict=False)
                
                for _ in range(per_range):
                    # Random address in range
                    # For large ranges, we need to be smart about generation
                    prefix_len = network.prefixlen
                    random_bits = 128 - prefix_len
                    
                    # Generate random offset (limit to reasonable size)
                    max_offset = min(2 ** random_bits, 2 ** 48)
                    offset = random.randint(0, max_offset - 1)
                    
                    addr = ipaddress.IPv6Address(int(network.network_address) + offset)
                    addr_str = str(addr)
                    
                    if addr_str not in self.generated:
                        self.generated.add(addr_str)
                        generated.append(GeneratedAddress(
                            address=addr_str,
                            generation_method='random_range',
                            confidence=0.3,
                            source_prefix=range_str
                        ))
                        
            except Exception as e:
                logger.debug(f"Error generating in range {range_str}: {e}")
        
        return generated[:count]
    
    def generate_batch(
        self,
        count: int = 1000,
        strategy: str = 'balanced'
    ) -> List[GeneratedAddress]:
        """
        Generate a batch of addresses using specified strategy.
        
        Strategies:
        - 'balanced': Mix of all methods
        - 'learned': Focus on learned patterns
        - 'random': Random generation
        - 'aggressive': More mutations and nearby addresses
        """
        generated = []
        
        if strategy == 'balanced':
            # 50% learned patterns, 30% mutations, 20% random
            if self.active_prefixes:
                learned = self.generate_from_learned_patterns(int(count * 0.5))
                generated.extend(learned)
            
            # Add random
            random_gen = self.generate_random_in_ranges(int(count * 0.2))
            generated.extend(random_gen)
            
        elif strategy == 'learned':
            if self.active_prefixes:
                generated = self.generate_from_learned_patterns(count)
            else:
                logger.warning("No patterns learned, falling back to random")
                generated = self.generate_random_in_ranges(count)
                
        elif strategy == 'random':
            generated = self.generate_random_in_ranges(count)
            
        elif strategy == 'aggressive':
            # Mostly mutations of known addresses
            if self.active_prefixes:
                all_addresses = []
                for stats in self.active_prefixes.values():
                    all_addresses.extend(stats['addresses'])
                
                per_address = max(1, count // len(all_addresses))
                for addr in all_addresses:
                    mutations = self.generate_mutations(addr, per_address)
                    generated.extend(mutations)
                    if len(generated) >= count:
                        break
            else:
                generated = self.generate_random_in_ranges(count)
        
        # Remove duplicates and return
        seen = set()
        unique = []
        for g in generated:
            if g.address not in seen:
                seen.add(g.address)
                unique.append(g)
        
        return unique[:count]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics"""
        return {
            'total_generated': len(self.generated),
            'learned_prefixes': len(self.active_prefixes),
            'generation_methods': self._count_methods()
        }
    
    def _count_methods(self) -> Dict[str, int]:
        """Count addresses by generation method (placeholder)"""
        return {}
    
    def reset(self):
        """Reset the generator state"""
        self.generated.clear()
        self.active_prefixes.clear()


class SmartAddressGenerator:
    """
    Smart generator that uses ML model predictions to guide generation.
    Implements closed-loop optimization.
    
    Now supports metaheuristic algorithms:
    - Genetic Algorithm (GA)
    - Ant Colony Optimization (ACO)
    - Cuckoo Search (CS)
    """
    
    def __init__(self, predictor=None, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.predictor = predictor
        self.base_generator = IPv6AddressGenerator(config)
        
        self.min_confidence = config.get('min_confidence', 0.7) if config else 0.7
        self.batch_size = config.get('batch_size', 1000) if config else 1000
        
        # Track success rates by generation method
        self.method_success: Dict[str, Tuple[int, int]] = defaultdict(lambda: (0, 0))
        
        # Metaheuristic generator (lazy loading)
        self._metaheuristic_generator = None
        self.use_metaheuristic = config.get('use_metaheuristic', True) if config else True
    
    @property
    def metaheuristic_generator(self):
        """Lazy load metaheuristic generator"""
        if self._metaheuristic_generator is None:
            try:
                from .metaheuristic_generator import HybridMetaheuristicGenerator
                self._metaheuristic_generator = HybridMetaheuristicGenerator(
                    self.config.get('metaheuristic', {})
                )
                # Set fitness function if predictor exists
                if self.predictor:
                    self._metaheuristic_generator.set_fitness_function(
                        self._get_fitness_scores
                    )
                logger.info("Metaheuristic generator initialized (GA + ACO + Cuckoo Search)")
            except ImportError as e:
                logger.warning(f"Metaheuristic generator not available: {e}")
                self.use_metaheuristic = False
        return self._metaheuristic_generator
    
    def _get_fitness_scores(self, addresses: List[str]) -> List[float]:
        """Get fitness scores from ML predictor"""
        if self.predictor is None:
            return [0.5] * len(addresses)
        
        try:
            predictions = self.predictor.predict_combined(addresses)
            return [prob for _, prob in predictions]
        except Exception as e:
            logger.warning(f"Error getting fitness scores: {e}")
            return [0.5] * len(addresses)
    
    def set_predictor(self, predictor):
        """Set the ML predictor"""
        self.predictor = predictor
        # Update fitness function in metaheuristic generator
        if self._metaheuristic_generator:
            self._metaheuristic_generator.set_fitness_function(
                self._get_fitness_scores
            )
    
    def learn_from_seeds(self, addresses: List[str]):
        """Learn patterns from seed addresses"""
        self.base_generator.learn_from_active_addresses(addresses)
    
    def generate_candidates(
        self,
        count: int = 1000,
        filter_by_prediction: bool = True,
        strategy: str = 'hybrid'
    ) -> List[GeneratedAddress]:
        """
        Generate candidate addresses using various strategies.
        
        Strategies:
        - 'classic': Original prefix/mutation/random methods
        - 'metaheuristic': GA + ACO + Cuckoo Search
        - 'hybrid': Combination of both (default)
        """
        all_candidates = []
        
        # استراتژی کلاسیک
        if strategy in ('classic', 'hybrid'):
            classic_count = count if strategy == 'classic' else count // 2
            oversample_factor = 3 if filter_by_prediction else 1
            
            classic_candidates = self.base_generator.generate_batch(
                classic_count * oversample_factor,
                strategy='balanced'
            )
            all_candidates.extend(classic_candidates)
        
        # استراتژی فراابتکاری
        if strategy in ('metaheuristic', 'hybrid') and self.use_metaheuristic:
            meta_count = count if strategy == 'metaheuristic' else count // 2
            
            try:
                if self.metaheuristic_generator:
                    # جمع‌آوری آدرس‌های seed از الگوهای یادگرفته شده
                    seed_addresses = []
                    for prefix_stats in self.base_generator.active_prefixes.values():
                        seed_addresses.extend(prefix_stats.get('addresses', []))
                    
                    if seed_addresses:
                        meta_results = self.metaheuristic_generator.generate(
                            seed_addresses,
                            total_count=meta_count
                        )
                        
                        # تبدیل به GeneratedAddress
                        for algo_name, addresses in meta_results.items():
                            for addr in addresses:
                                all_candidates.append(GeneratedAddress(
                                    address=addr,
                                    generation_method=f'metaheuristic_{algo_name}',
                                    confidence=0.5
                                ))
                        
                        logger.info(f"Metaheuristic generated {sum(len(v) for v in meta_results.values())} candidates")
            except Exception as e:
                logger.warning(f"Metaheuristic generation failed: {e}")
        
        if not filter_by_prediction or self.predictor is None:
            return all_candidates[:count]
        
        # Get predictions
        addresses = [c.address for c in all_candidates]
        
        try:
            predictions = self.predictor.predict_combined(addresses)
            
            # Create lookup for predictions
            pred_lookup = {addr: prob for addr, prob in predictions}
            
            # Update confidence and filter
            filtered = []
            for candidate in all_candidates:
                prob = pred_lookup.get(candidate.address, 0.5)
                candidate.confidence = prob
                
                if prob >= self.min_confidence:
                    filtered.append(candidate)
            
            # Sort by confidence
            filtered.sort(key=lambda x: x.confidence, reverse=True)
            
            return filtered[:count]
            
        except Exception as e:
            logger.warning(f"Error in prediction filtering: {e}")
            return all_candidates[:count]
    
    def update_from_results(
        self,
        results: List[Tuple[GeneratedAddress, bool]]
    ):
        """Update generator based on probe results"""
        # Track metaheuristic algorithm success separately
        meta_stats = {'ga': {'hits': 0, 'total': 0}, 
                      'aco': {'hits': 0, 'total': 0}, 
                      'cs': {'hits': 0, 'total': 0}}
        
        for gen_addr, is_active in results:
            method = gen_addr.generation_method
            current = self.method_success[method]
            self.method_success[method] = (
                current[0] + int(is_active),
                current[1] + 1
            )
            
            # Track metaheuristic algorithms
            if method.startswith('metaheuristic_'):
                algo = method.replace('metaheuristic_', '')
                if algo in meta_stats:
                    meta_stats[algo]['total'] += 1
                    if is_active:
                        meta_stats[algo]['hits'] += 1
            
            # If active, learn from it
            if is_active:
                self.base_generator.learn_from_active_addresses([gen_addr.address])
        
        # Update metaheuristic generator weights
        if self._metaheuristic_generator:
            for algo, stats in meta_stats.items():
                if stats['total'] > 0:
                    self._metaheuristic_generator.update_success(
                        algo, stats['hits'], stats['total']
                    )
    
    def get_method_statistics(self) -> Dict[str, float]:
        """Get success rate by generation method"""
        stats = {}
        for method, (success, total) in self.method_success.items():
            if total > 0:
                stats[method] = success / total
            else:
                stats[method] = 0.0
        
        # Add metaheuristic statistics
        if self._metaheuristic_generator:
            meta_stats = self._metaheuristic_generator.get_statistics()
            stats['_metaheuristic_weights'] = meta_stats.get('weights', {})
        
        return stats


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    generator = IPv6AddressGenerator()
    
    # Learn from some sample addresses
    sample_active = [
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2606:4700:4700::1111",
    ]
    
    generator.learn_from_active_addresses(sample_active)
    
    # Generate addresses
    generated = generator.generate_batch(20, strategy='balanced')
    
    print("Generated Addresses:")
    for g in generated:
        print(f"  {g.address} ({g.generation_method}, conf: {g.confidence:.2f})")
    
    # Test SmartAddressGenerator with metaheuristics
    print("\n" + "=" * 60)
    print("Testing SmartAddressGenerator with Metaheuristics")
    print("=" * 60)
    
    smart_gen = SmartAddressGenerator(config={'use_metaheuristic': True})
    smart_gen.learn_from_seeds(sample_active)
    
    candidates = smart_gen.generate_candidates(
        count=30, 
        filter_by_prediction=False, 
        strategy='hybrid'
    )
    
    print(f"\nGenerated {len(candidates)} candidates:")
    for c in candidates[:10]:
        print(f"  {c.address} ({c.generation_method})")

