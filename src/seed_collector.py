"""
Seed Collector Module
جمع‌آوری آدرس‌های IPv6 اولیه از منابع مختلف
"""

import asyncio
import logging
import ipaddress
from typing import List, Set, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json
import socket

import dns.resolver
import dns.reversename
import aiohttp
from tqdm import tqdm

logger = logging.getLogger(__name__)


@dataclass
class SeedAddress:
    """Represents a seed IPv6 address with metadata"""
    address: str
    source: str
    domain: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    is_active: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'source': self.source,
            'domain': self.domain,
            'discovered_at': self.discovered_at.isoformat(),
            'is_active': self.is_active,
            'metadata': self.metadata
        }


class DNSSeedCollector:
    """Collect IPv6 addresses from DNS AAAA records"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    def resolve_domain(self, domain: str) -> List[SeedAddress]:
        """Resolve a domain to its IPv6 addresses"""
        seeds = []
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                addr = str(rdata)
                seed = SeedAddress(
                    address=addr,
                    source='dns_aaaa',
                    domain=domain,
                    metadata={'record_type': 'AAAA'}
                )
                seeds.append(seed)
                logger.debug(f"Found IPv6 {addr} for domain {domain}")
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No AAAA record for {domain}")
        except dns.resolver.Timeout:
            logger.debug(f"Timeout resolving {domain}")
        except Exception as e:
            logger.debug(f"Error resolving {domain}: {e}")
        return seeds
    
    def collect_from_domains_file(self, filepath: Path) -> List[SeedAddress]:
        """Collect seeds from a file containing domain names"""
        seeds = []
        if not filepath.exists():
            logger.warning(f"Domains file not found: {filepath}")
            return seeds
            
        with open(filepath, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        logger.info(f"Resolving {len(domains)} domains...")
        for domain in tqdm(domains, desc="DNS Resolution"):
            seeds.extend(self.resolve_domain(domain))
            
        logger.info(f"Collected {len(seeds)} IPv6 addresses from DNS")
        return seeds


class PublicListCollector:
    """Collect IPv6 addresses from public lists and datasets"""
    
    PUBLIC_SOURCES = [
        # IPv6 hitlists and public datasets
        "https://ipv6hitlist.github.io/",  # Example - actual URLs need verification
    ]
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self.session = session
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def fetch_hitlist(self, url: str) -> List[SeedAddress]:
        """Fetch IPv6 addresses from a public hitlist"""
        seeds = []
        try:
            session = await self._get_session()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    content = await response.text()
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                # Validate IPv6 address
                                ipaddress.IPv6Address(line)
                                seed = SeedAddress(
                                    address=line,
                                    source='public_hitlist',
                                    metadata={'source_url': url}
                                )
                                seeds.append(seed)
                            except ipaddress.AddressValueError:
                                continue
        except Exception as e:
            logger.error(f"Error fetching hitlist from {url}: {e}")
        return seeds
    
    def load_from_file(self, filepath: Path) -> List[SeedAddress]:
        """Load IPv6 addresses from a local file"""
        seeds = []
        if not filepath.exists():
            logger.warning(f"File not found: {filepath}")
            return seeds
            
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ipaddress.IPv6Address(line)
                        seed = SeedAddress(
                            address=line,
                            source='local_file',
                            metadata={'filepath': str(filepath)}
                        )
                        seeds.append(seed)
                    except ipaddress.AddressValueError:
                        continue
        
        logger.info(f"Loaded {len(seeds)} addresses from {filepath}")
        return seeds


class BGPSeedCollector:
    """Collect IPv6 prefixes from BGP routing data"""
    
    def __init__(self):
        self.prefixes: Set[str] = set()
        
    async def fetch_ris_data(self, session: aiohttp.ClientSession) -> List[str]:
        """Fetch BGP prefix data from RIPE RIS"""
        prefixes = []
        # This is a simplified example - real implementation would parse RIS dumps
        # or use the RIPE Stat API
        try:
            url = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status == 200:
                    data = await response.json()
                    for prefix_data in data.get('data', {}).get('prefixes', []):
                        prefix = prefix_data.get('prefix', '')
                        if ':' in prefix:  # IPv6 prefix
                            prefixes.append(prefix)
        except Exception as e:
            logger.error(f"Error fetching BGP data: {e}")
        return prefixes
    
    def generate_addresses_from_prefix(self, prefix: str, count: int = 10) -> List[SeedAddress]:
        """Generate sample addresses from a prefix for probing"""
        seeds = []
        try:
            network = ipaddress.IPv6Network(prefix, strict=False)
            # Generate addresses at different positions in the prefix
            # Common patterns: ::1, ::2, low numbers, EUI-64 patterns
            sample_suffixes = [1, 2, 3, 100, 1000, 0xFFFF]
            
            for suffix in sample_suffixes[:count]:
                try:
                    addr = network.network_address + suffix
                    if addr in network:
                        seed = SeedAddress(
                            address=str(addr),
                            source='bgp_prefix',
                            metadata={'prefix': prefix}
                        )
                        seeds.append(seed)
                except:
                    continue
        except Exception as e:
            logger.debug(f"Error processing prefix {prefix}: {e}")
        return seeds


class WellKnownAddressCollector:
    """Collect well-known IPv6 addresses (DNS roots, major services)"""
    
    WELL_KNOWN_DOMAINS = [
        # Root DNS servers
        'a.root-servers.net',
        'b.root-servers.net',
        'c.root-servers.net',
        'd.root-servers.net',
        'e.root-servers.net',
        'f.root-servers.net',
        # Major services
        'google.com',
        'www.google.com',
        'facebook.com',
        'cloudflare.com',
        'amazon.com',
        'microsoft.com',
        'apple.com',
        'netflix.com',
        'twitter.com',
        'github.com',
        'stackoverflow.com',
        # CDNs
        'cdn.cloudflare.com',
        'akamai.com',
        'fastly.com',
    ]
    
    def __init__(self):
        self.dns_collector = DNSSeedCollector()
        
    def collect(self) -> List[SeedAddress]:
        """Collect IPv6 addresses from well-known domains"""
        seeds = []
        logger.info("Collecting IPv6 addresses from well-known domains...")
        
        for domain in tqdm(self.WELL_KNOWN_DOMAINS, desc="Well-known domains"):
            domain_seeds = self.dns_collector.resolve_domain(domain)
            for seed in domain_seeds:
                seed.source = 'well_known'
            seeds.extend(domain_seeds)
            
        logger.info(f"Collected {len(seeds)} addresses from well-known domains")
        return seeds


class SeedCollector:
    """Main seed collector that aggregates all sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.seeds: List[SeedAddress] = []
        self.unique_addresses: Set[str] = set()
        
        # Initialize sub-collectors
        self.dns_collector = DNSSeedCollector()
        self.public_collector = PublicListCollector()
        self.bgp_collector = BGPSeedCollector()
        self.wellknown_collector = WellKnownAddressCollector()
        
    def add_seed(self, seed: SeedAddress) -> bool:
        """Add a seed if it's not a duplicate"""
        if seed.address not in self.unique_addresses:
            self.unique_addresses.add(seed.address)
            self.seeds.append(seed)
            return True
        return False
    
    def add_seeds(self, seeds: List[SeedAddress]) -> int:
        """Add multiple seeds, return count of new seeds"""
        count = 0
        for seed in seeds:
            if self.add_seed(seed):
                count += 1
        return count
    
    async def collect_all(self, data_dir: Path) -> List[SeedAddress]:
        """Collect seeds from all configured sources"""
        logger.info("Starting seed collection from all sources...")
        
        # 1. Well-known domains
        wellknown_seeds = self.wellknown_collector.collect()
        added = self.add_seeds(wellknown_seeds)
        logger.info(f"Added {added} seeds from well-known domains")
        
        # 2. DNS from domains file
        domains_file = data_dir / "seeds" / "domains.txt"
        if domains_file.exists():
            dns_seeds = self.dns_collector.collect_from_domains_file(domains_file)
            added = self.add_seeds(dns_seeds)
            logger.info(f"Added {added} seeds from domains file")
        
        # 3. Load from existing seed files
        seeds_dir = data_dir / "seeds"
        if seeds_dir.exists():
            for seed_file in seeds_dir.glob("*.txt"):
                if seed_file.name != "domains.txt":
                    file_seeds = self.public_collector.load_from_file(seed_file)
                    added = self.add_seeds(file_seeds)
                    logger.info(f"Added {added} seeds from {seed_file.name}")
        
        # 4. BGP prefixes (generate sample addresses)
        async with aiohttp.ClientSession() as session:
            prefixes = await self.bgp_collector.fetch_ris_data(session)
            for prefix in prefixes[:100]:  # Limit to first 100 prefixes
                prefix_seeds = self.bgp_collector.generate_addresses_from_prefix(prefix)
                self.add_seeds(prefix_seeds)
        
        logger.info(f"Total unique seeds collected: {len(self.seeds)}")
        return self.seeds
    
    def save_seeds(self, filepath: Path):
        """Save collected seeds to a JSON file"""
        data = {
            'collected_at': datetime.now().isoformat(),
            'total_count': len(self.seeds),
            'seeds': [seed.to_dict() for seed in self.seeds]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(self.seeds)} seeds to {filepath}")
    
    def load_seeds(self, filepath: Path) -> List[SeedAddress]:
        """Load seeds from a JSON file"""
        if not filepath.exists():
            logger.warning(f"Seeds file not found: {filepath}")
            return []
            
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.seeds = []
        self.unique_addresses = set()
        
        for seed_data in data.get('seeds', []):
            seed = SeedAddress(
                address=seed_data['address'],
                source=seed_data['source'],
                domain=seed_data.get('domain'),
                discovered_at=datetime.fromisoformat(seed_data['discovered_at']),
                is_active=seed_data.get('is_active'),
                metadata=seed_data.get('metadata', {})
            )
            self.add_seed(seed)
        
        logger.info(f"Loaded {len(self.seeds)} seeds from {filepath}")
        return self.seeds
    
    def get_addresses(self) -> List[str]:
        """Get list of unique IPv6 addresses"""
        return [seed.address for seed in self.seeds]
    
    def filter_by_source(self, source: str) -> List[SeedAddress]:
        """Filter seeds by their source"""
        return [seed for seed in self.seeds if seed.source == source]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about collected seeds"""
        sources = {}
        for seed in self.seeds:
            sources[seed.source] = sources.get(seed.source, 0) + 1
        
        return {
            'total_seeds': len(self.seeds),
            'by_source': sources,
            'unique_domains': len(set(s.domain for s in self.seeds if s.domain)),
        }


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    logging.basicConfig(level=logging.INFO)
    
    config = {}
    collector = SeedCollector(config)
    
    # Quick test with well-known domains
    seeds = collector.wellknown_collector.collect()
    print(f"\nCollected {len(seeds)} seeds from well-known domains")
    for seed in seeds[:10]:
        print(f"  {seed.address} ({seed.domain})")
