#!/usr/bin/env python3
"""
SAFE-T1505 Detection Example: Clustering-Based Anomaly Detection
Demonstrates k-means and k-NN for detecting credential extraction attempts

Author: Sumit Yadav (rockerritesh4@gmail.com)
Date: 2025-11-16

Research Foundation:
- Supervised learning algorithms (arXiv:2204.12868)
- Metric learning (arXiv:1306.6709)
- Embedding redundancy detection (arXiv:2506.01435)

Model Recommendations:
- Embeddings: Use small models like all-MiniLM-L6-v2 for production
- API Options: OpenAI Embeddings, Google Vertex AI, Cohere Embed
- Clustering: sklearn implementations work well for <100K embeddings
- For larger scale: Use FAISS or Annoy for approximate nearest neighbors
"""
# /// script
# dependencies = [
#   "numpy>=1.24.0",
#   "scikit-learn>=1.3.0",
# ]
# ///

import numpy as np
from typing import List, Dict, Tuple
from sklearn.cluster import KMeans, DBSCAN
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import silhouette_score


class ClusteringAnomalyDetector:
    """Detect API key extraction using clustering and k-NN algorithms"""
    
    def __init__(self, n_clusters: int = 5, k_neighbors: int = 5):
        """
        Initialize detector
        
        Args:
            n_clusters: Number of clusters for k-means
            k_neighbors: Number of neighbors for k-NN
        """
        self.n_clusters = n_clusters
        self.k_neighbors = k_neighbors
        self.kmeans = None
        self.knn = None
        self.credential_cluster_id = None
        
    def train_kmeans(self, embeddings: np.ndarray, labels: List[str]):
        """
        Train k-means clustering model
        
        Args:
            embeddings: Training embeddings
            labels: Labels indicating if each embedding is credential-related
        """
        # Train k-means
        self.kmeans = KMeans(n_clusters=self.n_clusters, random_state=42)
        cluster_assignments = self.kmeans.fit_predict(embeddings)
        
        # Identify credential cluster(s)
        # Find clusters with highest proportion of credential-related queries
        cluster_credential_ratios = {}
        
        for cluster_id in range(self.n_clusters):
            cluster_mask = cluster_assignments == cluster_id
            cluster_labels = [labels[i] for i, mask in enumerate(cluster_mask) if mask]
            
            if len(cluster_labels) > 0:
                credential_ratio = sum(
                    1 for label in cluster_labels if label == 'credential'
                ) / len(cluster_labels)
                cluster_credential_ratios[cluster_id] = credential_ratio
        
        # Select cluster with highest credential ratio as credential cluster
        if cluster_credential_ratios:
            self.credential_cluster_id = max(
                cluster_credential_ratios,
                key=cluster_credential_ratios.get
            )
        
        print(f"Trained k-means with {self.n_clusters} clusters")
        print(f"Credential cluster ID: {self.credential_cluster_id}")
        print(f"Credential ratio: {cluster_credential_ratios.get(self.credential_cluster_id, 0):.2f}")
    
    def train_knn(self, embeddings: np.ndarray):
        """
        Train k-NN model
        
        Args:
            embeddings: Training embeddings
        """
        self.knn = NearestNeighbors(n_neighbors=self.k_neighbors, metric='cosine')
        self.knn.fit(embeddings)
        print(f"Trained k-NN with k={self.k_neighbors}")
    
    def detect_kmeans(self, embedding: np.ndarray) -> Dict:
        """
        Detect using k-means clustering
        
        Args:
            embedding: Query embedding to analyze
            
        Returns:
            Detection result
        """
        if self.kmeans is None:
            raise ValueError("K-means model not trained")
        
        # Predict cluster
        cluster_id = self.kmeans.predict(embedding.reshape(1, -1))[0]
        
        # Calculate distance to cluster centroid
        centroid = self.kmeans.cluster_centers_[cluster_id]
        distance = np.linalg.norm(embedding - centroid)
        
        # Calculate cluster density (silhouette score approximation)
        # In production, use actual silhouette score with full dataset
        cluster_density = 1.0 / (1.0 + distance)  # Simplified metric
        
        # Detection
        is_malicious = (
            cluster_id == self.credential_cluster_id and
            distance < 0.5  # Close to credential cluster centroid
        )
        
        return {
            'method': 'kmeans',
            'cluster_id': int(cluster_id),
            'is_credential_cluster': cluster_id == self.credential_cluster_id,
            'distance_to_centroid': float(distance),
            'cluster_density': float(cluster_density),
            'is_malicious': is_malicious,
            'confidence': float(1.0 - distance) if is_malicious else 0.0
        }
    
    def detect_knn(
        self,
        embedding: np.ndarray,
        credential_labels: List[bool]
    ) -> Dict:
        """
        Detect using k-NN
        
        Args:
            embedding: Query embedding to analyze
            credential_labels: Labels for training data (True if credential-related)
            
        Returns:
            Detection result
        """
        if self.knn is None:
            raise ValueError("k-NN model not trained")
        
        # Find k nearest neighbors
        distances, indices = self.knn.kneighbors(embedding.reshape(1, -1))
        
        # Count credential neighbors
        credential_neighbors = sum(
            1 for idx in indices[0] if credential_labels[idx]
        )
        
        # Average distance
        avg_distance = float(np.mean(distances))
        
        # Detection: majority of neighbors are credential-related
        is_malicious = credential_neighbors >= (self.k_neighbors / 2)
        
        return {
            'method': 'knn',
            'k': self.k_neighbors,
            'credential_neighbors': credential_neighbors,
            'avg_distance': avg_distance,
            'is_malicious': is_malicious,
            'confidence': float(credential_neighbors / self.k_neighbors)
        }
    
    def detect_dbscan_anomaly(
        self,
        embeddings: np.ndarray,
        query_embedding: np.ndarray,
        eps: float = 0.3,
        min_samples: int = 3
    ) -> Dict:
        """
        Detect anomalies using DBSCAN clustering
        
        Args:
            embeddings: All embeddings including query
            query_embedding: Query to analyze
            eps: DBSCAN epsilon parameter
            min_samples: Minimum samples for core point
            
        Returns:
            Detection result
        """
        # Add query to embeddings
        all_embeddings = np.vstack([embeddings, query_embedding.reshape(1, -1)])
        
        # Run DBSCAN
        dbscan = DBSCAN(eps=eps, min_samples=min_samples, metric='cosine')
        labels = dbscan.fit_predict(all_embeddings)
        
        # Check query label (last item)
        query_label = labels[-1]
        
        # -1 indicates noise/anomaly
        is_anomaly = query_label == -1
        
        # Count cluster sizes
        unique_labels = set(labels)
        cluster_sizes = {
            label: np.sum(labels == label)
            for label in unique_labels if label != -1
        }
        
        return {
            'method': 'dbscan',
            'query_label': int(query_label),
            'is_anomaly': is_anomaly,
            'is_malicious': is_anomaly,  # Anomalies are suspicious
            'cluster_sizes': cluster_sizes,
            'total_clusters': len(cluster_sizes),
            'confidence': 0.8 if is_anomaly else 0.2
        }


def main():
    """Demonstration of clustering-based detection"""
    print("=" * 80)
    print("SAFE-T1505: Clustering-Based Anomaly Detection Example")
    print("=" * 80)
    print()
    
    # Generate synthetic training data
    np.random.seed(42)
    
    # Benign queries (cluster 1)
    benign_embeddings = np.random.randn(30, 384) + np.array([1.0, 0.0] + [0.0] * 382)
    benign_labels = ['benign'] * 30
    
    # Credential queries (cluster 2)
    credential_embeddings = np.random.randn(20, 384) + np.array([0.0, 1.5] + [0.0] * 382)
    credential_labels = ['credential'] * 20
    
    # Mix training data
    train_embeddings = np.vstack([benign_embeddings, credential_embeddings])
    train_labels = benign_labels + credential_labels
    
    # Normalize
    train_embeddings = train_embeddings / np.linalg.norm(
        train_embeddings, axis=1, keepdims=True
    )
    
    print(f"Training data: {len(train_embeddings)} embeddings")
    print(f"  - Benign: {len(benign_labels)}")
    print(f"  - Credential: {len(credential_labels)}")
    print()
    
    # Initialize detector
    detector = ClusteringAnomalyDetector(n_clusters=3, k_neighbors=5)
    
    # Train models
    print("-" * 80)
    print("TRAINING MODELS")
    print("-" * 80)
    detector.train_kmeans(train_embeddings, train_labels)
    detector.train_knn(train_embeddings)
    print()
    
    # Test queries
    print("-" * 80)
    print("TESTING DETECTION")
    print("-" * 80)
    
    # Test case 1: Benign query (near benign cluster)
    test_benign = np.random.randn(384) + np.array([1.0, 0.0] + [0.0] * 382)
    test_benign = test_benign / np.linalg.norm(test_benign)
    
    print("\nTest 1: Benign Query")
    print("-" * 40)
    
    kmeans_result = detector.detect_kmeans(test_benign)
    print(f"K-means Detection:")
    print(f"  Cluster: {kmeans_result['cluster_id']}")
    print(f"  Is Credential Cluster: {kmeans_result['is_credential_cluster']}")
    print(f"  Distance to Centroid: {kmeans_result['distance_to_centroid']:.4f}")
    print(f"  Malicious: {kmeans_result['is_malicious']}")
    
    credential_flags = [label == 'credential' for label in train_labels]
    knn_result = detector.detect_knn(test_benign, credential_flags)
    print(f"\nk-NN Detection:")
    print(f"  Credential Neighbors: {knn_result['credential_neighbors']}/{knn_result['k']}")
    print(f"  Average Distance: {knn_result['avg_distance']:.4f}")
    print(f"  Malicious: {knn_result['is_malicious']}")
    
    # Test case 2: Credential query (near credential cluster)
    test_credential = np.random.randn(384) + np.array([0.0, 1.5] + [0.0] * 382)
    test_credential = test_credential / np.linalg.norm(test_credential)
    
    print("\n\nTest 2: Credential Extraction Query")
    print("-" * 40)
    
    kmeans_result = detector.detect_kmeans(test_credential)
    print(f"K-means Detection:")
    print(f"  Cluster: {kmeans_result['cluster_id']}")
    print(f"  Is Credential Cluster: {kmeans_result['is_credential_cluster']}")
    print(f"  Distance to Centroid: {kmeans_result['distance_to_centroid']:.4f}")
    print(f"  Malicious: {kmeans_result['is_malicious']}")
    print(f"  Confidence: {kmeans_result['confidence']:.4f}")
    
    knn_result = detector.detect_knn(test_credential, credential_flags)
    print(f"\nk-NN Detection:")
    print(f"  Credential Neighbors: {knn_result['credential_neighbors']}/{knn_result['k']}")
    print(f"  Average Distance: {knn_result['avg_distance']:.4f}")
    print(f"  Malicious: {knn_result['is_malicious']}")
    print(f"  Confidence: {knn_result['confidence']:.4f}")
    
    # Test case 3: Anomaly detection with DBSCAN
    test_anomaly = np.random.randn(384) + np.array([2.0, 2.0] + [0.0] * 382)
    test_anomaly = test_anomaly / np.linalg.norm(test_anomaly)
    
    print("\n\nTest 3: Anomalous Query (DBSCAN)")
    print("-" * 40)
    
    dbscan_result = detector.detect_dbscan_anomaly(
        train_embeddings,
        test_anomaly,
        eps=0.3,
        min_samples=3
    )
    print(f"DBSCAN Detection:")
    print(f"  Query Label: {dbscan_result['query_label']}")
    print(f"  Is Anomaly: {dbscan_result['is_anomaly']}")
    print(f"  Malicious: {dbscan_result['is_malicious']}")
    print(f"  Total Clusters: {dbscan_result['total_clusters']}")
    print(f"  Confidence: {dbscan_result['confidence']:.4f}")
    
    print()
    print("=" * 80)
    print("IMPLEMENTATION NOTES")
    print("=" * 80)
    print("✓ K-means clustering identifies credential query patterns")
    print("✓ k-NN detects queries near known credential examples")
    print("✓ DBSCAN identifies anomalous queries (potential attacks)")
    print("✓ Multiple algorithms provide ensemble detection")
    print("✓ Based on research: arXiv:0806.2414, arXiv:1306.6709")
    print("=" * 80)


if __name__ == "__main__":
    main()

