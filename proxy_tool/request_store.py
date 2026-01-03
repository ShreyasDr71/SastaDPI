
import json
import os
from datetime import datetime

class RequestStore:
    """Save and replay HTTP requests"""
    
    def __init__(self, storage_dir="saved_requests"):
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
    
    def save_request(self, method, url, headers, body=None):
        """Save a request to a JSON file"""
        timestamp = datetime.now().isoformat()
        filename = f"request_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.storage_dir, filename)
        
        request_data = {
            'timestamp': timestamp,
            'method': method,
            'url': url,
            'headers': dict(headers) if headers else {},
            'body': body.decode('utf-8', errors='ignore') if body else None
        }
        
        with open(filepath, 'w') as f:
            json.dump(request_data, f, indent=2)
        
        return filepath
    
    def load_request(self, filepath):
        """Load a request from a JSON file"""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def list_requests(self):
        """List all saved requests"""
        files = [f for f in os.listdir(self.storage_dir) if f.endswith('.json')]
        return sorted(files, reverse=True)
