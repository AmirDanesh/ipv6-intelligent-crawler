"""
Prober Module
اسکنر برای بررسی فعال بودن آدرس‌های IPv6
"""

import asyncio
import logging
import socket
import ssl
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

import aiohttp
from asyncio_throttle import Throttler

logger = logging.getLogger(__name__)


class ProbeResult(Enum):
    """Result types for probing"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TIMEOUT = "timeout"
    ERROR = "error"
    FILTERED = "filtered"


@dataclass
class ProbeResponse:
    """Response from a single probe"""
    address: str
    port: int
    result: ProbeResult
    response_time_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    http_status: Optional[int] = None
    server_header: Optional[str] = None
    error_message: Optional[str] = None
    ssl_info: Optional[Dict[str, Any]] = None
    
    @property
    def is_active(self) -> bool:
        return self.result == ProbeResult.ACTIVE
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'port': self.port,
            'result': self.result.value,
            'response_time_ms': self.response_time_ms,
            'timestamp': self.timestamp.isoformat(),
            'http_status': self.http_status,
            'server_header': self.server_header,
            'error_message': self.error_message,
            'ssl_info': self.ssl_info
        }


class TCPProber:
    """Low-level TCP connection prober"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    async def probe(self, address: str, port: int) -> ProbeResponse:
        """Probe a single address:port with TCP connection"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port),
                timeout=self.timeout
            )
            
            # Connection successful
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            writer.close()
            await writer.wait_closed()
            
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.ACTIVE,
                response_time_ms=response_time
            )
            
        except asyncio.TimeoutError:
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.TIMEOUT,
                response_time_ms=self.timeout * 1000,
                error_message="Connection timeout"
            )
            
        except ConnectionRefusedError:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.FILTERED,
                response_time_ms=response_time,
                error_message="Connection refused"
            )
            
        except OSError as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            # Check for specific errors
            if "Network is unreachable" in str(e):
                result = ProbeResult.INACTIVE
            elif "No route to host" in str(e):
                result = ProbeResult.INACTIVE
            else:
                result = ProbeResult.ERROR
                
            return ProbeResponse(
                address=address,
                port=port,
                result=result,
                response_time_ms=response_time,
                error_message=str(e)
            )
            
        except Exception as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.ERROR,
                response_time_ms=response_time,
                error_message=str(e)
            )


class HTTPProber:
    """HTTP/HTTPS prober for web servers"""
    
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "IPv6-Research-Crawler/1.0 (Educational)"
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        
    def _create_connector(self) -> aiohttp.TCPConnector:
        """Create a connector that works with IPv6"""
        return aiohttp.TCPConnector(
            force_close=True,
            enable_cleanup_closed=True,
            ssl=False  # Will be handled per-request
        )
    
    async def probe_http(
        self,
        address: str,
        port: int = 80,
        path: str = "/"
    ) -> ProbeResponse:
        """Probe an HTTP server"""
        url = f"http://[{address}]:{port}{path}"
        return await self._probe_url(address, port, url, use_ssl=False)
    
    async def probe_https(
        self,
        address: str,
        port: int = 443,
        path: str = "/"
    ) -> ProbeResponse:
        """Probe an HTTPS server"""
        url = f"https://[{address}]:{port}{path}"
        return await self._probe_url(address, port, url, use_ssl=True)
    
    async def _probe_url(
        self,
        address: str,
        port: int,
        url: str,
        use_ssl: bool
    ) -> ProbeResponse:
        """Probe a URL"""
        start_time = asyncio.get_event_loop().time()
        
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        # SSL context that doesn't verify (for research purposes)
        if use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context = None
        
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=self._create_connector()
            ) as session:
                async with session.get(
                    url,
                    headers=headers,
                    ssl=ssl_context,
                    allow_redirects=False
                ) as response:
                    response_time = (asyncio.get_event_loop().time() - start_time) * 1000
                    
                    # Extract server header
                    server_header = response.headers.get('Server', None)
                    
                    # Get SSL info if HTTPS
                    ssl_info = None
                    if use_ssl and hasattr(response, 'connection'):
                        try:
                            transport = response.connection.transport
                            if transport and hasattr(transport, 'get_extra_info'):
                                ssl_object = transport.get_extra_info('ssl_object')
                                if ssl_object:
                                    ssl_info = {
                                        'version': ssl_object.version(),
                                        'cipher': ssl_object.cipher(),
                                    }
                        except:
                            pass
                    
                    return ProbeResponse(
                        address=address,
                        port=port,
                        result=ProbeResult.ACTIVE,
                        response_time_ms=response_time,
                        http_status=response.status,
                        server_header=server_header,
                        ssl_info=ssl_info
                    )
                    
        except asyncio.TimeoutError:
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.TIMEOUT,
                response_time_ms=self.timeout * 1000,
                error_message="HTTP request timeout"
            )
            
        except aiohttp.ClientConnectorError as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.INACTIVE,
                response_time_ms=response_time,
                error_message=str(e)
            )
            
        except Exception as e:
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return ProbeResponse(
                address=address,
                port=port,
                result=ProbeResult.ERROR,
                response_time_ms=response_time,
                error_message=str(e)
            )


class IPv6Prober:
    """
    Main prober class that orchestrates probing operations.
    Supports rate limiting, concurrent probing, and multiple protocols.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        self.timeout = self.config.get('timeout', 5.0)
        self.max_concurrent = self.config.get('max_concurrent', 100)
        self.rate_limit = self.config.get('rate_limit', 50)  # per second
        self.ports = self.config.get('ports', [80, 443])
        self.retries = self.config.get('retries', 2)
        
        self.tcp_prober = TCPProber(timeout=self.timeout)
        self.http_prober = HTTPProber(timeout=self.timeout)
        
        # Rate limiter
        self.throttler = Throttler(rate_limit=self.rate_limit)
        
        # Statistics
        self.stats = {
            'total_probed': 0,
            'active': 0,
            'inactive': 0,
            'timeout': 0,
            'error': 0
        }
        
        # Already probed addresses (for deduplication)
        self.probed: Set[str] = set()
    
    async def probe_address(
        self,
        address: str,
        probe_type: str = 'http'
    ) -> List[ProbeResponse]:
        """Probe a single address on configured ports"""
        results = []
        
        if address in self.probed:
            return results
        
        self.probed.add(address)
        
        for port in self.ports:
            async with self.throttler:
                if probe_type == 'tcp':
                    response = await self.tcp_prober.probe(address, port)
                elif probe_type == 'http':
                    if port == 443:
                        response = await self.http_prober.probe_https(address, port)
                    else:
                        response = await self.http_prober.probe_http(address, port)
                else:
                    response = await self.tcp_prober.probe(address, port)
                
                results.append(response)
                self._update_stats(response)
        
        return results
    
    async def probe_batch(
        self,
        addresses: List[str],
        probe_type: str = 'http',
        progress_callback=None
    ) -> Dict[str, List[ProbeResponse]]:
        """Probe multiple addresses concurrently"""
        results = {}
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def probe_with_semaphore(addr: str) -> Tuple[str, List[ProbeResponse]]:
            async with semaphore:
                responses = await self.probe_address(addr, probe_type)
                if progress_callback:
                    progress_callback(addr, responses)
                return addr, responses
        
        # Create tasks
        tasks = [probe_with_semaphore(addr) for addr in addresses]
        
        # Execute with progress
        for coro in asyncio.as_completed(tasks):
            addr, responses = await coro
            results[addr] = responses
        
        return results
    
    def _update_stats(self, response: ProbeResponse):
        """Update statistics from a response"""
        self.stats['total_probed'] += 1
        
        if response.result == ProbeResult.ACTIVE:
            self.stats['active'] += 1
        elif response.result == ProbeResult.INACTIVE:
            self.stats['inactive'] += 1
        elif response.result == ProbeResult.TIMEOUT:
            self.stats['timeout'] += 1
        else:
            self.stats['error'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get probing statistics"""
        total = self.stats['total_probed']
        if total == 0:
            hit_rate = 0
        else:
            hit_rate = self.stats['active'] / total
        
        return {
            **self.stats,
            'hit_rate': hit_rate,
            'unique_addresses': len(self.probed)
        }
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'total_probed': 0,
            'active': 0,
            'inactive': 0,
            'timeout': 0,
            'error': 0
        }
        self.probed.clear()
    
    def filter_active(
        self,
        results: Dict[str, List[ProbeResponse]]
    ) -> List[str]:
        """Filter to get only active addresses"""
        active = []
        for addr, responses in results.items():
            if any(r.is_active for r in responses):
                active.append(addr)
        return active


class ProbeResultStore:
    """Store and manage probe results"""
    
    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath
        self.results: Dict[str, List[ProbeResponse]] = {}
    
    def add_results(self, results: Dict[str, List[ProbeResponse]]):
        """Add probe results"""
        for addr, responses in results.items():
            if addr not in self.results:
                self.results[addr] = []
            self.results[addr].extend(responses)
    
    def get_active_addresses(self) -> List[str]:
        """Get all addresses that were found active"""
        return [
            addr for addr, responses in self.results.items()
            if any(r.is_active for r in responses)
        ]
    
    def get_inactive_addresses(self) -> List[str]:
        """Get all addresses that were found inactive"""
        return [
            addr for addr, responses in self.results.items()
            if not any(r.is_active for r in responses)
        ]
    
    def save(self, filepath: Optional[str] = None):
        """Save results to file"""
        filepath = filepath or self.filepath
        if not filepath:
            raise ValueError("No filepath specified")
        
        data = {
            addr: [r.to_dict() for r in responses]
            for addr, responses in self.results.items()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath: Optional[str] = None):
        """Load results from file"""
        filepath = filepath or self.filepath
        if not filepath:
            raise ValueError("No filepath specified")
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.results = {}
        for addr, responses_data in data.items():
            self.results[addr] = []
            for r_data in responses_data:
                response = ProbeResponse(
                    address=r_data['address'],
                    port=r_data['port'],
                    result=ProbeResult(r_data['result']),
                    response_time_ms=r_data['response_time_ms'],
                    timestamp=datetime.fromisoformat(r_data['timestamp']),
                    http_status=r_data.get('http_status'),
                    server_header=r_data.get('server_header'),
                    error_message=r_data.get('error_message'),
                    ssl_info=r_data.get('ssl_info')
                )
                self.results[addr].append(response)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        total = len(self.results)
        active = len(self.get_active_addresses())
        
        return {
            'total_addresses': total,
            'active_addresses': active,
            'inactive_addresses': total - active,
            'hit_rate': active / total if total > 0 else 0
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def main():
        prober = IPv6Prober({
            'timeout': 5.0,
            'max_concurrent': 10,
            'rate_limit': 5,
            'ports': [80, 443]
        })
        
        # Test with some known IPv6 addresses
        test_addresses = [
            "2001:4860:4860::8888",  # Google DNS
            "2606:4700:4700::1111",  # Cloudflare DNS
        ]
        
        print("Probing test addresses...")
        results = await prober.probe_batch(test_addresses, probe_type='http')
        
        for addr, responses in results.items():
            print(f"\n{addr}:")
            for r in responses:
                print(f"  Port {r.port}: {r.result.value} ({r.response_time_ms:.1f}ms)")
        
        print(f"\nStatistics: {prober.get_statistics()}")
    
    asyncio.run(main())
