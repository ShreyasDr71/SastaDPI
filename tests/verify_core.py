
import asyncio

from proxy_tool.proxy_core import ProxyServer
import threading
import time
import requests

async def start_server():
    server = ProxyServer(port=9999, custom_headers={'X-Test': 'Worked'})
    await server.start()

def run_server_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())

def test_proxy():
    # Start proxy in thread
    t = threading.Thread(target=run_server_thread, daemon=True)
    t.start()
    
    # Wait for startup
    time.sleep(2)
    
    proxies = {
        'http': 'http://127.0.0.1:9999',
        'https': 'http://127.0.0.1:9999',
    }
    
    print("Testing HTTP via proxy...")
    try:
        # httpbin.org/headers returns headers sent to it
        resp = requests.get("http://httpbin.org/headers", proxies=proxies, timeout=10)
        data = resp.json()
        print(f"Status: {resp.status_code}")
        print("Headers received by server:", data['headers'])
        if 'X-Test' in data['headers']:
            print("SUCCESS: Custom header injected.")
        else:
            print("FAIL: Custom header not found.")
            
    except Exception as e:
        print(f"HTTP Test Failed: {e}")

    # Note: HTTPS test would require trusting CA, so we skip programmatic check or use verify=False and expect failure on cert check but success on connection
    print("\nTesting HTTPS (Connection) via proxy...")
    try:
        resp = requests.get("https://example.com", proxies=proxies, verify=False, timeout=10)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
             print("SUCCESS: HTTPS Connect worked.")
    except Exception as e:
        print(f"HTTPS Test Failed: {e}")

if __name__ == "__main__":
    test_proxy()
