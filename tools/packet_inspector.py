
import socket
import sys

def run_inspector(port=9000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    
    print(f"Packet Inspector listening on port {port}...")
    print("Use this as the target URL: http://localhost:9000/")
    
    while True:
        client, addr = server.accept()
        print(f"\n[+] Connection from {addr}")
        
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                print(f" -> Received chunk of {len(data)} bytes")
                # print(f"    Data: {data[:50]}...") 
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()
            print("[-] Connection closed")

if __name__ == "__main__":
    port = 9000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_inspector(port)
