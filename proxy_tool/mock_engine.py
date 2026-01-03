
import json
import re
import os

class MockEngine:
    """Match requests and return mock responses"""
    
    def __init__(self, rules_file="mocks.json"):
        self.rules_file = rules_file
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load mock rules from JSON file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    self.rules = json.load(f)
            except Exception as e:
                print(f"Failed to load mock rules: {e}")
                self.rules = []
    
    def match(self, url):
        """Check if URL matches any mock rule"""
        for rule in self.rules:
            pattern = rule.get('pattern', '')
            if re.search(pattern, url):
                return rule.get('response')
        return None
    
    def create_response(self, mock_data):
        """Create HTTP response from mock data"""
        status = mock_data.get('status', 200)
        headers = mock_data.get('headers', {})
        body = mock_data.get('body', '')
        
        # Build HTTP response
        response_line = f"HTTP/1.1 {status} OK\r\n"
        header_lines = '\r\n'.join([f"{k}: {v}" for k, v in headers.items()])
        
        if isinstance(body, dict):
            body = json.dumps(body)
            if 'Content-Type' not in headers:
                header_lines += "\r\nContent-Type: application/json"
        
        response = f"{response_line}{header_lines}\r\n\r\n{body}"
        return response.encode('utf-8')
