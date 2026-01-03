
import aiohttp
import asyncio
import json
import socket as sock_module

class DoHResolver:
    """DNS-over-HTTPS resolver for privacy"""
    
    PROVIDERS = {
        'cloudflare': 'https://cloudflare-dns.com/dns-query',
        'google': 'https://dns.google/resolve',
        'quad9': 'https://dns.quad9.net:5053/dns-query'
    }
    
    def __init__(self, provider='cloudflare'):
        self.provider = provider
        self.url = self.PROVIDERS.get(provider, self.PROVIDERS['cloudflare'])
        self.session = None
    
    async def _ensure_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def resolve(self, hostname):
        """Resolve hostname using DoH, returns list of IP addresses"""
        await self._ensure_session()
        
        try:
            params = {
                'name': hostname,
                'type': 'A'  # IPv4
            }
            
            headers = {
                'accept': 'application/dns-json'
            }
            
            async with self.session.get(self.url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # Extract IP addresses from response
                    ips = []
                    if 'Answer' in data:
                        for answer in data['Answer']:
                            if answer.get('type') == 1:  # A record
                                ips.append(answer['data'])
                    
                    if ips:
                        return ips
        except Exception as e:
            # Fallback to system DNS on error
            pass
        
        # Fallback to system DNS
        try:
            info = await asyncio.get_event_loop().getaddrinfo(hostname, None, family=sock_module.AF_INET)
            return [addr[4][0] for addr in info]
        except Exception:
            raise Exception(f"Failed to resolve {hostname}")
    
    async def close(self):
        if self.session:
            await self.session.close()
