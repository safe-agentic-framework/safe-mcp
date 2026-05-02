import json
import re
import unittest

__author__ = "Vikranth Kumar Shivaa"

class CovertChannelDetector:
    def __init__(self):
        self.suspicious_patterns = ['base64', '==', 'data:image', 'data:application']
        # Regex to simulate the entropy check from the Sigma rule
        self.high_entropy_regex = re.compile(r'[a-zA-Z0-9+/]{20,}={0,2}')

    def detect(self, log_entry):
        parameters = json.dumps(log_entry.get('parameters', {}))
        
        # Check for suspicious keywords
        for pattern in self.suspicious_patterns:
            if pattern in parameters:
                return True
                
        # Check for high entropy / long encoded strings
        if self.high_entropy_regex.search(parameters):
            return True
            
        return False

class TestCovertChannelDetection(unittest.TestCase):
    def setUp(self):
        with open('techniques/SAFE-T1910/test-logs.json', 'r') as f:
            self.logs = json.load(f)
        self.detector = CovertChannelDetector()

    def test_benign_weather(self):
        log = self.logs[0]
        self.assertFalse(self.detector.detect(log), "Benign weather lookup should not be detected")

    def test_benign_fetch(self):
        log = self.logs[1]
        self.assertFalse(self.detector.detect(log), "Benign URL fetch should not be detected")

    def test_malicious_weather_smuggling(self):
        log = self.logs[2]
        self.assertTrue(self.detector.detect(log), "Weather lookup with base64 suffix should be detected")

    def test_malicious_url_exfil(self):
        log = self.logs[3]
        self.assertTrue(self.detector.detect(log), "URL with base64 payload should be detected")

if __name__ == '__main__':
    unittest.main()

