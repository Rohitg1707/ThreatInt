"""
Machine Learning components for threat intelligence analysis
"""
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import silhouette_score
import re
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class MLThreatEngine:
    def __init__(self, storage):
        self.storage = storage
        self.conn = storage._conn
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
    
    def enhanced_severity_scoring(self, ioc_data):
        """ML-enhanced severity scoring using multiple features"""
        try:
            features = self._extract_features(ioc_data)
            
            # Rule-based baseline (existing scoring)
            base_score = ioc_data.get('severity_score', 0)
            
            # ML enhancements
            context_score = self._calculate_context_score(ioc_data)
            reputation_score = self._calculate_reputation_score(ioc_data)
            temporal_score = self._calculate_temporal_score(ioc_data)
            structural_score = self._calculate_structural_score(ioc_data)
            
            # Weighted combination with research-backed weights
            enhanced_score = (
                base_score * 0.3 +        # Original heuristics
                context_score * 0.25 +    # Context analysis
                reputation_score * 0.2 +  # Source reputation
                temporal_score * 0.15 +   # Temporal factors
                structural_score * 0.1    # Structural analysis
            )
            
            # Ensure score is within valid range
            return min(max(enhanced_score, 0), 10)
        
        except Exception as e:
            logger.warning(f"Error in enhanced severity scoring: {e}")
            return ioc_data.get('severity_score', 0)
    
    def _extract_features(self, ioc_data):
        """Extract comprehensive ML features from IOC data"""
        features = {}
        
        raw_value = str(ioc_data.get('raw', ''))
        types = ioc_data.get('types', [])
        if isinstance(types, str):
            types = json.loads(types)
        meta = ioc_data.get('meta', {})
        
        # Basic string features
        features['length'] = len(raw_value)
        features['entropy'] = self._calculate_entropy(raw_value)
        features['digit_ratio'] = len(re.findall(r'\d', raw_value)) / max(len(raw_value), 1)
        features['special_char_ratio'] = len(re.findall(r'[^a-zA-Z0-9.]', raw_value)) / max(len(raw_value), 1)
        features['upper_ratio'] = len(re.findall(r'[A-Z]', raw_value)) / max(len(raw_value), 1)
        
        # Type-based features
        features['is_ip'] = int('ip' in types)
        features['is_domain'] = int('domain' in types)
        features['is_hash'] = int('hash' in types)
        features['is_url'] = int('url' in types)
        features['type_count'] = len(types)
        
        # Domain-specific features
        if 'domain' in types or 'url' in types:
            features['subdomain_count'] = raw_value.count('.')
            features['has_suspicious_tld'] = int(any(tld in raw_value.lower() for tld in 
                ['.tk', '.ml', '.ga', '.cf', '.bit']))
            features['domain_length'] = len(raw_value.split('.')[0]) if '.' in raw_value else 0
        else:
            features['subdomain_count'] = 0
            features['has_suspicious_tld'] = 0
            features['domain_length'] = 0
        
        # IP-specific features
        if 'ip' in types:
            try:
                parts = raw_value.split('.')
                if len(parts) == 4:
                    features['ip_private'] = int(parts[0] in ['10', '172', '192'])
                    features['ip_first_octet'] = int(parts[0]) if parts[0].isdigit() else 0
                else:
                    features['ip_private'] = 0
                    features['ip_first_octet'] = 0
            except:
                features['ip_private'] = 0
                features['ip_first_octet'] = 0
        else:
            features['ip_private'] = 0
            features['ip_first_octet'] = 0
        
        # Context features from metadata
        description = str(meta.get('description', ''))
        pulse_name = str(meta.get('pulse_name', ''))
        combined_text = (description + ' ' + pulse_name).lower()
        
        features['description_length'] = len(description)
        features['has_description'] = int(len(description) > 0)
        features['malware_keywords'] = sum(1 for word in 
            ['malware', 'trojan', 'backdoor', 'ransomware', 'botnet'] if word in combined_text)
        features['apt_keywords'] = sum(1 for word in 
            ['apt', 'targeted', 'campaign', 'advanced'] if word in combined_text)
        
        return features
    
    def _calculate_entropy(self, s):
        """Calculate Shannon entropy of string"""
        if not s:
            return 0
        
        # Get probability of each character
        prob = {}
        for char in s:
            prob[char] = prob.get(char, 0) + 1
        
        # Convert to probabilities
        length = len(s)
        for char in prob:
            prob[char] = prob[char] / length
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in prob.values() if p > 0)
        return entropy
    
    def _calculate_context_score(self, ioc_data):
        """Score based on contextual information from threat intelligence"""
        meta = ioc_data.get('meta', {})
        description = str(meta.get('description', '')).lower()
        pulse_name = str(meta.get('pulse_name', '')).lower()
        
        # Combine all text for analysis
        text = description + ' ' + pulse_name
        
        # High-risk indicators
        high_risk_patterns = [
            r'\bapt\b', r'\btargeted\b', r'\bcampaign\b', r'\ransomware\b',
            r'\btrojan\b', r'\bbackdoor\b', r'\bc2\b', r'\bcommand.{0,10}control\b',
            r'\bbotnet\b', r'\bexfiltrat\b', r'\bpersistent\b'
        ]
        
        medium_risk_patterns = [
            r'\bmalware\b', r'\bsuspicious\b', r'\bphishing\b', r'\bscam\b',
            r'\bmalicious\b', r'\bthreat\b', r'\battack\b'
        ]
        
        low_risk_patterns = [
            r'\bunknown\b', r'\bgeneric\b', r'\btest\b'
        ]
        
        high_score = sum(1 for pattern in high_risk_patterns if re.search(pattern, text))
        medium_score = sum(1 for pattern in medium_risk_patterns if re.search(pattern, text))
        low_score = sum(1 for pattern in low_risk_patterns if re.search(pattern, text))
        
        # Calculate weighted score
        context_score = high_score * 3 + medium_score * 1.5 - low_score * 0.5
        
        return min(max(context_score, 0), 10)
    
    def _calculate_reputation_score(self, ioc_data):
        """Score based on source reputation and historical frequency"""
        source = ioc_data.get('source', 'unknown')
        raw_value = ioc_data.get('raw', '')
        
        # Check historical frequency of this IOC
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE raw = ?", (raw_value,))
        frequency = cursor.fetchone()[0]
        
        # Source reputation weights (can be tuned based on experience)
        source_weights = {
            'otx': 1.0,
            'virustotal': 1.2,
            'shodan': 0.8,
            'abuseipdb': 1.1,
            'unknown': 0.5
        }
        
        base_weight = source_weights.get(source.lower(), 0.7)
        
        # Frequency-based scoring
        if frequency == 1:
            freq_score = 2.0  # New IOC, moderate suspicion
        elif frequency <= 3:
            freq_score = 3.0  # Moderate frequency, higher suspicion
        elif frequency <= 10:
            freq_score = 2.5  # High frequency might be legitimate
        else:
            freq_score = 1.5  # Very high frequency, likely false positive
        
        return min(base_weight * freq_score, 10)
    
    def _calculate_temporal_score(self, ioc_data):
        """Score based on temporal patterns and recency"""
        first_seen = ioc_data.get('first_seen', '')
        
        try:
            if first_seen:
                seen_dt = pd.to_datetime(first_seen)
                now = pd.Timestamp.now(tz=seen_dt.tz if seen_dt.tz else None)
                hours_diff = (now - seen_dt).total_seconds() / 3600
                
                # Recent IOCs are generally more suspicious
                if hours_diff < 1:
                    return 4.0  # Very recent
                elif hours_diff < 6:
                    return 3.5  # Recent
                elif hours_diff < 24:
                    return 3.0  # Within day
                elif hours_diff < 168:  # Within week
                    return 2.0
                else:
                    return 1.0  # Old IOC
            else:
                return 1.5  # No timestamp data
                
        except Exception:
            return 1.5  # Default for parsing errors
    
    def _calculate_structural_score(self, ioc_data):
        """Score based on structural analysis of the indicator"""
        raw_value = str(ioc_data.get('raw', ''))
        types = ioc_data.get('types', [])
        if isinstance(types, str):
            types = json.loads(types)
        
        score = 0
        
        # Domain generation algorithm (DGA) detection for domains
        if 'domain' in types:
            # Check for DGA patterns
            domain_part = raw_value.split('.')[0] if '.' in raw_value else raw_value
            
            # High entropy suggests DGA
            entropy = self._calculate_entropy(domain_part)
            if entropy > 4.0:
                score += 2.0
            
            # Consonant/vowel ratio (DGA domains often have unusual ratios)
            consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', domain_part.lower()))
            vowels = len(re.findall(r'[aeiou]', domain_part.lower()))
            if vowels > 0:
                cv_ratio = consonants / vowels
                if cv_ratio > 3.0 or cv_ratio < 0.5:
                    score += 1.0
            
            # Length anomalies
            if len(domain_part) > 15 or len(domain_part) < 4:
                score += 0.5
        
        # IP address analysis
        elif 'ip' in types:
            try:
                parts = [int(p) for p in raw_value.split('.')]
                
                # Check for unusual IP patterns
                if parts[0] in [0, 127, 255]:  # Reserved/special ranges
                    score -= 1.0
                elif parts[0] in [10] or (parts[0] == 172 and 16 <= parts[1] <= 31) or (parts[0] == 192 and parts[1] == 168):
                    score -= 2.0  # Private IP ranges
                else:
                    score += 1.0  # Public IP
                    
            except (ValueError, IndexError):
                pass  # Invalid IP format
        
        return min(max(score, 0), 10)
    
    def cluster_similar_iocs(self, min_samples=3, eps=0.3):
        """Cluster similar IOCs using DBSCAN and multiple similarity metrics"""
        try:
            # Get IOCs with their features
            query = "SELECT raw, types, meta_json, severity_score FROM iocs LIMIT 1000"  # Limit for performance
            cursor = self.conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            
            if len(rows) < min_samples:
                return {'clusters': {}, 'noise_points': [], 'metrics': {'silhouette_score': -1}}
            
            # Prepare data
            iocs_data = []
            features_list = []
            
            for row in rows:
                try:
                    ioc_data = {
                        'raw': row[0],
                        'types': json.loads(row[1]) if row[1] else [],
                        'meta': json.loads(row[2]) if row[2] else {},
                        'severity_score': row[3]
                    }
                    iocs_data.append(ioc_data)
                    
                    # Extract features for clustering
                    features = self._extract_features(ioc_data)
                    features_list.append(list(features.values()))
                    
                except (json.JSONDecodeError, ValueError):
                    continue
            
            if len(features_list) < min_samples:
                return {'clusters': {}, 'noise_points': [], 'metrics': {'silhouette_score': -1}}
            
            # Normalize features
            X = self.scaler.fit_transform(features_list)
            
            # Perform clustering
            clustering = DBSCAN(eps=eps, min_samples=min_samples, metric='euclidean').fit(X)
            labels = clustering.labels_
            
            # Calculate metrics
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            n_noise = list(labels).count(-1)
            
            silhouette_avg = -1
            if n_clusters > 1:
                try:
                    silhouette_avg = silhouette_score(X, labels)
                except ValueError:
                    silhouette_avg = -1
            
            # Group results
            clusters = defaultdict(list)
            noise_points = []
            
            for idx, label in enumerate(labels):
                if label == -1:
                    noise_points.append(iocs_data[idx]['raw'])
                else:
                    clusters[f"cluster_{label}"].append({
                        'indicator': iocs_data[idx]['raw'],
                        'types': iocs_data[idx]['types'],
                        'severity': iocs_data[idx]['severity_score']
                    })
            
            return {
                'clusters': dict(clusters),
                'noise_points': noise_points,
                'metrics': {
                    'n_clusters': n_clusters,
                    'n_noise': n_noise,
                    'silhouette_score': round(silhouette_avg, 3),
                    'total_points': len(iocs_data)
                }
            }
            
        except Exception as e:
            logger.error(f"Error in IOC clustering: {e}")
            return {'clusters': {}, 'noise_points': [], 'metrics': {'error': str(e)}}
    
    def predict_threat_evolution(self, days_ahead=7):
        """Predict threat evolution patterns using temporal analysis"""
        try:
            # Get historical data
            query = """
            SELECT DATE(added_at) as date, COUNT(*) as daily_count, AVG(severity_score) as avg_severity
            FROM iocs 
            WHERE added_at >= datetime('now', '-30 days')
            GROUP BY DATE(added_at)
            ORDER BY date
            """
            
            cursor = self.conn.cursor()
            cursor.execute(query)
            historical_data = cursor.fetchall()
            
            if len(historical_data) < 7:  # Need at least a week of data
                return {'prediction': 'insufficient_data', 'confidence': 0}
            
            # Simple trend analysis
            daily_counts = [row[1] for row in historical_data]
            avg_severities = [row[2] for row in historical_data if row[2]]
            
            # Calculate trends
            volume_trend = np.polyfit(range(len(daily_counts)), daily_counts, 1)[0]
            severity_trend = np.polyfit(range(len(avg_severities)), avg_severities, 1)[0] if avg_severities else 0
            
            # Make predictions
            last_volume = daily_counts[-1] if daily_counts else 0
            last_severity = avg_severities[-1] if avg_severities else 0
            
            predicted_volume = max(0, last_volume + (volume_trend * days_ahead))
            predicted_severity = max(0, min(10, last_severity + (severity_trend * days_ahead)))
            
            # Confidence based on data consistency
            volume_variance = np.var(daily_counts) if len(daily_counts) > 1 else 0
            confidence = min(100, max(0, 100 - (volume_variance / max(np.mean(daily_counts), 1)) * 50))
            
            return {
                'prediction': {
                    'predicted_daily_volume': round(predicted_volume, 1),
                    'predicted_avg_severity': round(predicted_severity, 2),
                    'volume_trend': 'increasing' if volume_trend > 0 else 'decreasing',
                    'severity_trend': 'increasing' if severity_trend > 0 else 'decreasing'
                },
                'confidence': round(confidence, 1),
                'based_on_days': len(historical_data)
            }
            
        except Exception as e:
            logger.error(f"Error in threat evolution prediction: {e}")
            return {'prediction': 'error', 'error': str(e), 'confidence': 0}
    
    def export_ml_analysis_report(self, output_path="out\\ml_analysis_report.json"):
        """Export comprehensive ML analysis report"""
        try:
            # Perform all ML analyses
            clustering_results = self.cluster_similar_iocs()
            threat_prediction = self.predict_threat_evolution()
            
            # Sample some IOCs for enhanced scoring demonstration
            cursor = self.conn.cursor()
            cursor.execute("SELECT raw, types, meta_json, severity_score FROM iocs ORDER BY severity_score DESC LIMIT 10")
            sample_iocs = cursor.fetchall()
            
            enhanced_scoring_examples = []
            for row in sample_iocs:
                try:
                    ioc_data = {
                        'raw': row[0],
                        'types': json.loads(row[1]) if row[1] else [],
                        'meta': json.loads(row[2]) if row[2] else {},
                        'severity_score': row[3]
                    }
                    
                    enhanced_score = self.enhanced_severity_scoring(ioc_data)
                    enhanced_scoring_examples.append({
                        'indicator': row[0],
                        'original_score': row[3],
                        'enhanced_score': round(enhanced_score, 2),
                        'improvement': round(enhanced_score - row[3], 2)
                    })
                except:
                    continue
            
            # Compile report
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'ml_analysis_summary': {
                    'clustering': clustering_results['metrics'],
                    'threat_prediction': threat_prediction,
                    'enhanced_scoring_samples': len(enhanced_scoring_examples)
                },
                'clustering_results': clustering_results,
                'threat_evolution_prediction': threat_prediction,
                'enhanced_scoring_examples': enhanced_scoring_examples
            }
            
            # Export report
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"ML analysis report exported to: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting ML analysis report: {e}")
            return None