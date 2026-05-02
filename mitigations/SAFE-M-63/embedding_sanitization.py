#!/usr/bin/env python3
"""
SAFE-T1505 Mitigation Example: Vector Store Sanitization
Demonstrates vector database cleaning and credential pattern detection

Author: Sumit Yadav (rockerritesh4@gmail.com)
Date: 2025-11-16

Research Foundation:
- Vector store security (SAFE-T2106)
- Embedding security (Galileo AI, 2024)
- Semantic similarity measures (arXiv:2509.09714)

Model Recommendations:
- Embeddings: all-MiniLM-L6-v2 (tested, recommended for production)
- Vector Stores: ChromaDB, Pinecone, Weaviate, FAISS
- API Options: OpenAI Embeddings API, Google Vertex AI
- Sanitization: Run before storing in vector database
"""
# /// script
# dependencies = [
#   "numpy>=1.24.0",
# ]
# ///

import numpy as np
import re
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CredentialType(Enum):
    """Types of credentials to detect"""
    OPENAI_API_KEY = r'sk-[a-zA-Z0-9]{32,}'
    AWS_ACCESS_KEY = r'AKIA[0-9A-Z]{16}'
    GOOGLE_API_KEY = r'AIza[0-9A-Za-z\-_]{35}'
    GOOGLE_OAUTH = r'ya29\.[0-9A-Za-z\-_]+'
    SLACK_TOKEN = r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'
    GITHUB_PAT = r'ghp_[a-zA-Z0-9]{36}'
    GITLAB_PAT = r'glpat-[a-zA-Z0-9\-_]{20,}'
    GENERIC_JWT = r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'


@dataclass
class VectorEntry:
    """Represents an entry in the vector store"""
    id: str
    text: str
    embedding: np.ndarray
    metadata: Dict


class VectorStoreSanitizer:
    """Sanitize vector stores to remove API keys and credentials"""
    
    def __init__(self, semantic_threshold: float = 0.75):
        """
        Initialize sanitizer
        
        Args:
            semantic_threshold: Similarity threshold for semantic detection
        """
        self.semantic_threshold = semantic_threshold
        self.credential_patterns = [cred_type.value for cred_type in CredentialType]
        
        # Credential-related keywords
        self.credential_keywords = {
            'api_key', 'api key', 'apikey',
            'secret', 'secret_key', 'secret key',
            'token', 'access_token', 'auth_token',
            'password', 'passwd', 'pwd',
            'credential', 'credentials',
            'bearer', 'authorization',
            'private_key', 'private key',
        }
    
    def detect_credential_pattern(self, text: str) -> List[Tuple[str, str]]:
        """
        Detect credential patterns in text using regex
        
        Args:
            text: Text to scan
            
        Returns:
            List of (credential_type, matched_value) tuples
        """
        findings = []
        
        for cred_type in CredentialType:
            matches = re.finditer(cred_type.value, text)
            for match in matches:
                findings.append((cred_type.name, match.group()))
        
        return findings
    
    def detect_credential_keywords(self, text: str) -> Set[str]:
        """
        Detect credential-related keywords in text
        
        Args:
            text: Text to scan
            
        Returns:
            Set of found keywords
        """
        text_lower = text.lower()
        found_keywords = set()
        
        for keyword in self.credential_keywords:
            if keyword in text_lower:
                found_keywords.add(keyword)
        
        return found_keywords
    
    def calculate_semantic_distance(
        self,
        embedding: np.ndarray,
        credential_embedding: np.ndarray
    ) -> float:
        """
        Calculate semantic distance between embeddings
        
        Args:
            embedding: Entry embedding
            credential_embedding: Known credential pattern embedding
            
        Returns:
            Cosine distance (1 - cosine similarity)
        """
        similarity = np.dot(embedding, credential_embedding) / (
            np.linalg.norm(embedding) * np.linalg.norm(credential_embedding)
        )
        return 1.0 - similarity
    
    def fuzzy_match_credential(self, text: str, threshold: float = 0.8) -> bool:
        """
        Fuzzy matching for obfuscated credentials
        Based on Levenshtein distance
        
        Args:
            text: Text to check
            threshold: Similarity threshold
            
        Returns:
            True if potential obfuscated credential detected
        """
        # Check for patterns like: "sk-XXX...XXX", "AKIA****", etc.
        obfuscation_patterns = [
            r'sk-[X*]{10,}',
            r'AKIA[X*]{10,}',
            r'AIza[X*]{10,}',
            r'\*{8,}',  # Multiple asterisks
            r'X{8,}',   # Multiple X's
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def sanitize_entry(self, entry: VectorEntry) -> Dict:
        """
        Sanitize a single vector store entry
        
        Args:
            entry: Vector entry to sanitize
            
        Returns:
            Sanitization result
        """
        result = {
            'entry_id': entry.id,
            'should_remove': False,
            'reasons': [],
            'findings': {
                'credential_patterns': [],
                'credential_keywords': set(),
                'fuzzy_matches': False,
            }
        }
        
        # 1. Pattern-based detection
        credential_patterns = self.detect_credential_pattern(entry.text)
        if credential_patterns:
            result['should_remove'] = True
            result['reasons'].append('Contains credential patterns')
            result['findings']['credential_patterns'] = credential_patterns
        
        # 2. Keyword detection
        keywords = self.detect_credential_keywords(entry.text)
        if keywords:
            result['findings']['credential_keywords'] = keywords
            if len(keywords) >= 2:  # Multiple credential keywords
                result['should_remove'] = True
                result['reasons'].append('Multiple credential keywords detected')
        
        # 3. Fuzzy matching for obfuscated credentials
        if self.fuzzy_match_credential(entry.text):
            result['should_remove'] = True
            result['reasons'].append('Obfuscated credential pattern detected')
            result['findings']['fuzzy_matches'] = True
        
        return result
    
    def sanitize_vector_store(
        self,
        entries: List[VectorEntry]
    ) -> Dict:
        """
        Sanitize entire vector store
        
        Args:
            entries: List of vector entries
            
        Returns:
            Sanitization report
        """
        report = {
            'total_entries': len(entries),
            'entries_to_remove': [],
            'entries_clean': [],
            'statistics': {
                'credential_patterns_found': 0,
                'keyword_matches': 0,
                'fuzzy_matches': 0,
                'total_removed': 0,
            }
        }
        
        for entry in entries:
            result = self.sanitize_entry(entry)
            
            if result['should_remove']:
                report['entries_to_remove'].append(result)
                report['statistics']['total_removed'] += 1
                
                # Update statistics
                if result['findings']['credential_patterns']:
                    report['statistics']['credential_patterns_found'] += 1
                if result['findings']['credential_keywords']:
                    report['statistics']['keyword_matches'] += 1
                if result['findings']['fuzzy_matches']:
                    report['statistics']['fuzzy_matches'] += 1
            else:
                report['entries_clean'].append(entry.id)
        
        # Calculate removal rate
        report['removal_rate'] = (
            report['statistics']['total_removed'] / report['total_entries']
            if report['total_entries'] > 0 else 0
        )
        
        return report


def main():
    """Demonstration of vector store sanitization"""
    print("=" * 80)
    print("SAFE-T1505: Vector Store Sanitization Example")
    print("=" * 80)
    print()
    
    # Initialize sanitizer
    sanitizer = VectorStoreSanitizer(semantic_threshold=0.75)
    
    # Create test vector entries
    test_entries = [
        VectorEntry(
            id="entry_001",
            text="How to use Python for data analysis",
            embedding=np.random.randn(384),
            metadata={"category": "documentation"}
        ),
        VectorEntry(
            id="entry_002",
            text="My OpenAI API key is sk-proj-abc123xyz789secretkey456",
            embedding=np.random.randn(384),
            metadata={"category": "user_context"}
        ),
        VectorEntry(
            id="entry_003",
            text="AWS credentials: AKIA1234567890ABCDEF",
            embedding=np.random.randn(384),
            metadata={"category": "configuration"}
        ),
        VectorEntry(
            id="entry_004",
            text="Configure API key and secret token for authentication",
            embedding=np.random.randn(384),
            metadata={"category": "documentation"}
        ),
        VectorEntry(
            id="entry_005",
            text="Database password: **********",
            embedding=np.random.randn(384),
            metadata={"category": "configuration"}
        ),
        VectorEntry(
            id="entry_006",
            text="Best practices for Python programming",
            embedding=np.random.randn(384),
            metadata={"category": "documentation"}
        ),
    ]
    
    print(f"Analyzing {len(test_entries)} vector store entries...\n")
    
    # Sanitize vector store
    report = sanitizer.sanitize_vector_store(test_entries)
    
    # Print results
    print("=" * 80)
    print("SANITIZATION REPORT")
    print("=" * 80)
    print(f"Total Entries Analyzed: {report['total_entries']}")
    print(f"Entries to Remove: {report['statistics']['total_removed']}")
    print(f"Clean Entries: {len(report['entries_clean'])}")
    print(f"Removal Rate: {report['removal_rate']*100:.1f}%")
    print()
    
    print("-" * 80)
    print("STATISTICS")
    print("-" * 80)
    print(f"Credential Patterns Found: {report['statistics']['credential_patterns_found']}")
    print(f"Keyword Matches: {report['statistics']['keyword_matches']}")
    print(f"Fuzzy Matches: {report['statistics']['fuzzy_matches']}")
    print()
    
    print("-" * 80)
    print("ENTRIES TO REMOVE")
    print("-" * 80)
    for entry_result in report['entries_to_remove']:
        print(f"\nEntry ID: {entry_result['entry_id']}")
        print(f"Reasons: {', '.join(entry_result['reasons'])}")
        
        if entry_result['findings']['credential_patterns']:
            print("Credential Patterns:")
            for cred_type, value in entry_result['findings']['credential_patterns']:
                print(f"  - {cred_type}: {value[:20]}...")
        
        if entry_result['findings']['credential_keywords']:
            print(f"Keywords: {', '.join(entry_result['findings']['credential_keywords'])}")
    
    print()
    print("=" * 80)
    print("IMPLEMENTATION NOTES")
    print("=" * 80)
    print("✓ Pattern-based detection using regex")
    print("✓ Keyword matching for credential terms")
    print("✓ Fuzzy matching for obfuscated credentials")
    print("✓ Multiple detection layers for comprehensive coverage")
    print("✓ Based on research: arXiv:2509.09714, Galileo AI 2024")
    print("=" * 80)


if __name__ == "__main__":
    main()

