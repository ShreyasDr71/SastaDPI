# SastaDPI - Advanced TUI Proxy

A powerful Terminal User Interface (TUI) proxy with advanced evasion, security, and development features for network analysis and testing.

## Features

### ✅ Currently Implemented

#### Core Capabilities
- **TCP Fragmentation**: Split packets into configurable chunk sizes (e.g., 5, 38 bytes)
- **TTL Modification**: Set custom IP Time-To-Live values for both IPv4 and IPv6
- **HTTP/HTTPS Interception**: Full MITM with dynamic certificate generation
- **Header Modification**: Inject custom headers into HTTP requests

#### Advanced Evasion Techniques
- **Random Delay Injection**: Add configurable delays (min/max ms) between packet fragments
- **User-Agent Rotation**: Automatically rotate through 5 common browser user agents
- **Domain Fronting**: Override Host headers for censorship circumvention
- **Protocol Obfuscation**: Add random padding bytes to evade DPI (Deep Packet Inspection)

#### Security & Privacy
- **DNS-over-HTTPS (DoH)**: Encrypted DNS resolution via Cloudflare, Google, or Quad9
- **Privacy Mode**: Hide full URLs in logs, showing only domain names

#### Developer Tools
- **Mock Response Engine**: Define URL patterns in `mocks.json` and return predefined responses
- **Request Replay System**: Save and replay HTTP requests for testing (`request_store.py`)
- **Packet Inspector**: Included tool to verify fragmentation (`tools/packet_inspector.py`)

### 🚧 Future Improvements

#### Performance & Reliability
- **Connection Pooling**: Reuse upstream connections for better performance
- **Response Caching**: Cache responses with Cache-Control header parsing
- **Compression Support**: Gzip/Brotli encoding and decoding

#### Advanced Security
- **Upstream Proxy Chaining**: Route through SOCKS5 or HTTP proxies (e.g., Tor)
- **IP Spoofing**: Requires raw sockets and admin privileges
- **Request Logging Toggle**: Selective logging filters by domain/pattern

#### Protocol Support
- **WebSocket Support**: Transparent proxying of WebSocket connections
- **HTTP/2 Support**: Handle HTTP/2 protocol and stream multiplexing

#### UI Enhancements
- **Traffic Statistics Dashboard**: Request/response size, bandwidth, connection count
- **Request History View**: Scrollable list of past requests with filtering
- **Configuration Profiles**: Save/load different proxy setups
- **Dark/Light Theme Toggle**: Customizable color schemes

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m proxy_tool
```

### HTTPS Setup
For HTTPS interception, trust the generated CA certificate:
1. Start the proxy once to generate `certs/ca.crt`
2. Install to "Trusted Root Certification Authorities" (Windows) or equivalent
3. Restart your browser

### Configuration Examples

**Basic HTTP Proxy:**
- Listen Port: `8080`
- All other settings: default

**Maximum Evasion:**
- Fragment Size: `10`
- TTL: `64`
- Delay Range: `5-20` ms
- User-Agent Rotation: `ON`
- Domain Fronting: `cdn.cloudflare.com`
- Padding: `8` bytes
- DoH: `ON`

### Testing

**HTTP with Custom Header:**
```bash
curl.exe -v -x http://localhost:8080 http://httpbin.org/headers
```

**HTTPS:**
```bash
curl.exe -v -x http://localhost:8080 https://example.com
```

**Fragmentation Verification:**
```bash
# Terminal 1
python tools/packet_inspector.py

# Terminal 2 (set Fragment Size to 5 in TUI)
curl.exe -v -x http://localhost:8080 http://localhost:9000/
```

**Mock Response Test:**
```bash
curl.exe -v -x http://localhost:8080 http://api.example.com/users
```

## Mock Responses

Edit `mocks.json` to define URL patterns and responses:
```json
[
  {
    "pattern": "api\\.example\\.com/users",
    "response": {
      "status": 200,
      "body": {"users": [{"id": 1, "name": "Alice"}]}
    }
  }
]
```

## Project Structure

```
ByeBye/
├── proxy_tool/          # Main application
│   ├── __init__.py
│   ├── __main__.py      # Entry point
│   ├── tui.py           # Terminal UI
│   ├── proxy_core.py    # Core proxy logic
│   ├── cert_manager.py  # SSL certificate generation
│   ├── doh_resolver.py  # DNS-over-HTTPS
│   ├── mock_engine.py   # Mock response system
│   └── request_store.py # Request replay
├── tools/
│   └── packet_inspector.py  # Fragmentation verification
├── tests/
│   └── verify_core.py   # Automated tests
├── mocks.json           # Mock response configuration
├── requirements.txt
└── .gitignore
```

## Contributing

Contributions are welcome! Areas for improvement:
- Implement features from the "Future Improvements" section
- Add more evasion techniques
- Improve TUI responsiveness
- Add automated tests

## License

MIT
