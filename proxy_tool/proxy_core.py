
import asyncio
import ssl
import socket
import logging
import random
from urllib.parse import urlparse
from .cert_manager import CertManager
from .doh_resolver import DoHResolver
from .mock_engine import MockEngine

# Setup Logging
logger = logging.getLogger("ProxyCore")

# User-Agent pool for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

class ProxyServer:
    def __init__(self, host='127.0.0.1', port=8080, cert_manager=None, 
                 fragment_size=0, ttl=0, custom_headers=None,
                 min_delay=0, max_delay=0, rotate_ua=False, 
                 front_domain=None, padding_size=0,
                 use_doh=False, doh_provider='cloudflare', privacy_mode=False):
        self.host = host
        self.port = port
        self.cert_manager = cert_manager or CertManager()
        self.fragment_size = fragment_size
        self.ttl = ttl
        self.custom_headers = custom_headers or {}
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rotate_ua = rotate_ua
        self.front_domain = front_domain
        self.padding_size = padding_size
        self.use_doh = use_doh
        self.doh_resolver = DoHResolver(doh_provider) if use_doh else None
        self.privacy_mode = privacy_mode
        self.mock_engine = MockEngine()
        self.server = None
        self.running = False
        self.log_queue = None # Can be set by TUI

    def log(self, message):
        logger.info(message)
        if self.log_queue:
            asyncio.create_task(self.log_queue.put(message))

    async def start(self):
        self.running = True
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        self.log(f"Proxy listening on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()

    async def handle_client(self, reader, writer):
        try:
            # Read first line to detect method
            initial_data = await reader.read(4096)
            if not initial_data:
                writer.close()
                return

            decoded = initial_data.decode('utf-8', errors='ignore')
            lines = decoded.split('\r\n')
            request_line = lines[0]
            parts = request_line.split()
            
            if not parts:
                writer.close()
                return

            method = parts[0]
            url = parts[1]
            
            if method == 'CONNECT':
                await self.handle_https(reader, writer, url, initial_data)
            else:
                await self.handle_http(reader, writer, url, initial_data)

        except Exception as e:
            self.log(f"Error handling client: {e}")
            writer.close()

    async def handle_https(self, client_reader, client_writer, url, initial_data):
        target_host, target_port = url.split(':')
        target_port = int(target_port)

        self.log(f"HTTPS CONNECT to {target_host}:{target_port}")

        # 1. Respond 200 Connection Established
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # 2. Server Side SSL Handshake (MITM)
        cert_path, key_path = self.cert_manager.get_certificate(target_host)
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        try:
            await client_writer.start_tls(ssl_ctx, server_side=True)
        except Exception as e:
            self.log(f"SSL handshake failed: {e}")
            client_writer.close()
            return
        
        # 3. Connect Upstream (Client Side SSL)
        try:
            upstream_reader, upstream_writer = await self.connect_upstream(target_host, target_port, ssl=True)
        except Exception as e:
            self.log(f"Failed to connect upstream {target_host}: {e}")
            client_writer.close()
            return

        # 4. Relay Loop (Decrypted)
        await self.relay(client_reader, client_writer, upstream_reader, upstream_writer, is_https=True)

    async def handle_http(self, client_reader, client_writer, url, initial_data):
        parsed = urlparse(url)
        target_host = parsed.hostname
        target_port = parsed.port or 80
        
        # If hostname is missing (e.g. transparent proxy or weird request), try parsing header (skipped for simplicity)
        if not target_host:
             # Fallback for when url is just path (e.g. reverse proxy mode, not typical forward proxy but usually url is full)
             # But in standard HTTP proxy, URL is absolute.
             # If manual request: GET / HTTP/1.1\r\nHost: example.com
             # We need to extract Host header logic if url is relative.
             for line in initial_data.decode(errors='ignore').split('\r\n'):
                 if line.lower().startswith("host:"):
                     target_host = line.split(":", 1)[1].strip()
                     if ":" in target_host:
                         target_host, port_s = target_host.split(":")
                         target_port = int(port_s)
                     break
        
        if not target_host:
             self.log("Could not determine target host")
             client_writer.close()
             return

        if self.privacy_mode:
            self.log(f"HTTP Request to {target_host}")
        else:
            self.log(f"HTTP Request to {target_host}:{target_port} - {url}")
        
        # Check for mock response
        mock_response = self.mock_engine.match(url)
        if mock_response:
            self.log(f"[MOCK] Returning mocked response for {url}")
            mock_data = self.mock_engine.create_response(mock_response)
            client_writer.write(mock_data)
            await client_writer.drain()
            client_writer.close()
            return

        try:
            upstream_reader, upstream_writer = await self.connect_upstream(target_host, target_port, ssl=False)
        except Exception as e:
            self.log(f"Failed to connect upstream: {e}")
            client_writer.close()
            return

        # Forward the initial packet we already read
        # Need to inject custom headers here if needed into the initial packet
        initial_data = self.modify_headers(initial_data)
        
        await self.send_packet(upstream_writer, initial_data)
        
        await self.relay(client_reader, client_writer, upstream_reader, upstream_writer, is_https=False)


    async def connect_upstream(self, host, port, ssl):
        # DNS-over-HTTPS resolution
        resolved_host = host
        if self.use_doh and self.doh_resolver:
            try:
                ips = await self.doh_resolver.resolve(host)
                if ips:
                    resolved_host = ips[0]
                    if not self.privacy_mode:
                        self.log(f"DoH resolved {host} -> {resolved_host}")
            except Exception as e:
                self.log(f"DoH resolution failed for {host}, using system DNS: {e}")
        
        reader, writer = await asyncio.open_connection(resolved_host, port, ssl=ssl, server_hostname=host if ssl else None)
        sock = writer.transport.get_extra_info('socket')
        
        if sock:
             # Disable Nagle's algorithm to ensure fragments are sent immediately
             sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if self.ttl > 0 and sock:
             try:
                 if sock.family == socket.AF_INET:
                     sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
                     self.log(f"Set IPv4 TTL to {self.ttl}")
                 elif sock.family == socket.AF_INET6:
                     # Attempt to set IPv6 Hop Limit
                     # Windows sometimes uses distinct constants or behaves differently
                     IPPROTO_IPV6 = 41
                     IPV6_UNICAST_HOPS = 4
                     sock.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, self.ttl)
                     self.log(f"Set IPv6 TTL (Hop Limit) to {self.ttl}")
             except Exception as e:
                 # Log but do not fail the connection
                 self.log(f"Warning: Failed to set TTL (family={sock.family}): {e}")
        
        return reader, writer

    def modify_headers(self, data: bytes) -> bytes:
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            # Find end of headers
            try:
                header_end_idx = lines.index('')
            except ValueError:
                header_end_idx = len(lines)

            # Inject/modify headers
            new_lines = []
            new_lines.append(lines[0]) # Request line
            
            # Track if we've seen certain headers
            has_ua = False
            has_host = False
            
            for line in lines[1:header_end_idx]:
                lower_line = line.lower()
                
                # User-Agent rotation
                if lower_line.startswith('user-agent:') and self.rotate_ua:
                    new_lines.append(f"User-Agent: {random.choice(USER_AGENTS)}")
                    has_ua = True
                # Domain fronting - override Host header
                elif lower_line.startswith('host:') and self.front_domain:
                    new_lines.append(f"Host: {self.front_domain}")
                    has_host = True
                else:
                    new_lines.append(line)
            
            # Add UA if not present and rotation enabled
            if self.rotate_ua and not has_ua:
                new_lines.append(f"User-Agent: {random.choice(USER_AGENTS)}")
            
            # Add custom headers
            for k, v in self.custom_headers.items():
                new_lines.append(f"{k}: {v}")
                
            new_lines.append('') # Empty line separator
            new_lines.extend(lines[header_end_idx+1:])
            
            modified = '\r\n'.join(new_lines).encode('utf-8')
            
            # Protocol obfuscation - add random padding
            if self.padding_size > 0:
                padding = bytes(random.randint(0, 255) for _ in range(self.padding_size))
                modified += padding
            
            return modified
        except Exception as e:
            self.log(f"Header modification error: {e}")
            return data

    async def send_packet(self, writer, data):
        # TCP Fragmentation / Segmentation
        if self.fragment_size > 0 and len(data) > self.fragment_size:
            # self.log(f"Fragmenting {len(data)} bytes into {self.fragment_size} byte chunks")
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + self.fragment_size]
                writer.write(chunk)
                await writer.drain() # Force send logic
                
                # Random delay injection
                if self.max_delay > 0:
                    delay = random.uniform(self.min_delay / 1000, self.max_delay / 1000)
                    await asyncio.sleep(delay)
                
                offset += self.fragment_size
        else:
            writer.write(data)
            await writer.drain()

    async def relay(self, client_r, client_w, upstream_r, upstream_w, is_https):
        async def pipe_c2u():
            try:
                while True:
                    data = await client_r.read(4096)
                    if not data: break
                    # If HTTPS, we are strictly tunneling decrypted payload now
                    # If HTTP, we might want to check for new requests but keeping it simple for now
                    if not is_https:
                        data = self.modify_headers(data)
                        
                    await self.send_packet(upstream_w, data)
            except Exception as e:
                pass # Connection closed
            finally:
                upstream_w.close()

        async def pipe_u2c():
            try:
                while True:
                    data = await upstream_r.read(4096)
                    if not data: break
                    # We typically don't frag back to client, or modify response headers yet
                    client_w.write(data)
                    await client_w.drain()
            except Exception as e:
                pass
            finally:
                client_w.close()

        await asyncio.gather(pipe_c2u(), pipe_u2c())
