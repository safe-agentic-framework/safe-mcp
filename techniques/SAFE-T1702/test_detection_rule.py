import unittest
import json
import os
import yaml

class TestSharedMemoryPoisoningDetection(unittest.TestCase):
    __author__ = "Vikranth Kumar Shivaa"

    def setUp(self):
        self.logs_path = os.path.join(os.path.dirname(__file__), 'test-logs.json')
        self.rule_path = os.path.join(os.path.dirname(__file__), 'detection-rule.yml')
        
        with open(self.logs_path, 'r') as f:
            self.logs = json.load(f)
            
        with open(self.rule_path, 'r') as f:
            self.rule = yaml.safe_load(f)

    def detect(self, log):
        # Simplified detection logic based on the Sigma rule
        detection = self.rule['detection']
        tool_names = detection['selection_tool']['tool_name|contains']
        keywords = detection['selection_keywords']['parameters|contains']
        encodings = detection['selection_suspicious_encoding']['parameters|contains']
        
        log_tool = log.get('tool_name', '')
        log_params = log.get('parameters', {})
        # Flatten parameters to string for searching
        param_str = str(log_params)
        
        tool_match = any(tn in log_tool for tn in tool_names)
        keyword_match = any(kw in param_str for kw in keywords)
        encoding_match = any(enc in param_str for enc in encodings)
        
        return tool_match and (keyword_match or encoding_match)

    def test_benign_memory_save(self):
        # Log 0 is benign
        self.assertFalse(self.detect(self.logs[0]), "Benign memory save should not be detected")

    def test_malicious_memory_injection(self):
        # Log 1 contains "[SYSTEM] IMPERATIVE:"
        self.assertTrue(self.detect(self.logs[1]), "Malicious memory injection should be detected")

    def test_malicious_embedding_injection(self):
        # Log 2 contains "Ignore previous instructions"
        self.assertTrue(self.detect(self.logs[2]), "Malicious embedding injection should be detected")

    def test_benign_search(self):
        # Log 3 is a search, not a save
        self.assertFalse(self.detect(self.logs[3]), "Search operation should not be detected")
        
    def test_obfuscated_payload(self):
        # Log 4 contains "data:application...base64"
        self.assertTrue(self.detect(self.logs[4]), "Obfuscated/Encoded payload should be detected")

if __name__ == '__main__':
    unittest.main()
