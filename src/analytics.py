import sqlite3
import json
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ThreatAnalytics:
    def __init__(self, storage):
        self.storage = storage
        self.conn = storage._conn
    
    def campaign_attribution(self, time_window_hours=24):
        """Group IOCs by potential campaigns using temporal and infrastructure analysis"""
        query = """
        SELECT raw, types, source, severity_score, first_seen, meta_json 
        FROM iocs 
        WHERE added_at >= datetime('now', '-{} hours')
        ORDER BY first_seen
        """.format(time_window_hours)
        
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        
        if not rows:
            return {}
        
        # Convert to list of dictionaries for easier processing
        iocs = []
        for row in rows:
            try:
                ioc_data = {
                    'raw': row[0],
                    'types': json.loads(row[1]) if row[1] else [],
                    'source': row[2],
                    'severity_score': row[3],
                    'first_seen': row[4],
                    'meta': json.loads(row[5]) if row[5] else {}
                }
                iocs.append(ioc_data)
            except json.JSONDecodeError:
                continue
        
        # Campaign clustering logic
        campaigns = defaultdict(list)
        
        for ioc in iocs:
            campaign_key = self._generate_campaign_key(ioc)
            campaigns[campaign_key].append(ioc)
        
        # Filter out single-IOC campaigns (likely not real campaigns)
        filtered_campaigns = {k: v for k, v in campaigns.items() if len(v) > 1}
        
        return dict(filtered_campaigns)
    
    def _generate_campaign_key(self, ioc):
        """Generate a key for campaign clustering"""
        meta = ioc.get('meta', {})
        
        # Try to extract campaign identifiers from metadata
        pulse_name = str(meta.get('pulse_name', meta.get('name', 'unknown')))[:30]
        source = ioc.get('source', 'unknown')
        
        # Time-based clustering (group by 6-hour windows)
        try:
            if ioc.get('first_seen'):
                dt = pd.to_datetime(ioc['first_seen'])
                time_bucket = dt.floor('6H').strftime('%Y%m%d_%H')
            else:
                time_bucket = 'unknown'
        except:
            time_bucket = 'unknown'
        
        return f"{source}_{pulse_name}_{time_bucket}".replace(' ', '_')
    
    def infrastructure_reuse_analysis(self):
        """Advanced infrastructure reuse detection"""
        query = """
        SELECT raw, COUNT(*) as frequency,
               GROUP_CONCAT(DISTINCT source) as sources,
               GROUP_CONCAT(DISTINCT json_extract(meta_json, '$.pulse_name')) as pulse_names,
               AVG(severity_score) as avg_severity
        FROM iocs 
        WHERE (types LIKE '%"ip"%' OR types LIKE '%"domain"%')
        GROUP BY raw
        HAVING COUNT(*) > 1
        ORDER BY frequency DESC, avg_severity DESC
        """
        
        cursor = self.conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        
        infrastructure_analysis = []
        for row in results:
            infrastructure_analysis.append({
                'indicator': row[0],
                'frequency': row[1],
                'sources': row[2].split(',') if row[2] else [],
                'campaigns': [name for name in row[3].split(',') if name and name != 'None'] if row[3] else [],
                'avg_severity': round(row[4], 2) if row[4] else 0
            })
        
        return infrastructure_analysis
    
    def temporal_pattern_analysis(self, days=7):
        """Analyze temporal patterns in threat activity"""
        query = """
        SELECT 
            DATE(added_at) as date,
            CAST(strftime('%H', added_at) AS INTEGER) as hour,
            COUNT(*) as ioc_count,
            ROUND(AVG(severity_score), 2) as avg_severity,
            COUNT(DISTINCT source) as unique_sources
        FROM iocs 
        WHERE added_at >= datetime('now', '-{} days')
        GROUP BY DATE(added_at), CAST(strftime('%H', added_at) AS INTEGER)
        ORDER BY date DESC, hour DESC
        """.format(days)
        
        cursor = self.conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        
        temporal_data = []
        for row in results:
            temporal_data.append({
                'date': row[0],
                'hour': row[1],
                'ioc_count': row[2],
                'avg_severity': row[3],
                'unique_sources': row[4]
            })
        
        return temporal_data
    
    def threat_landscape_summary(self):
        """Generate comprehensive threat landscape report"""
        summary = {}
        cursor = self.conn.cursor()
        
        # Total IOCs by type
        cursor.execute("SELECT types, COUNT(*) FROM iocs GROUP BY types ORDER BY COUNT(*) DESC")
        summary['ioc_types'] = dict(cursor.fetchall())
        
        # Severity distribution
        cursor.execute("SELECT severity_score, COUNT(*) FROM iocs GROUP BY severity_score ORDER BY severity_score DESC")
        summary['severity_distribution'] = dict(cursor.fetchall())
        
        # Top sources
        cursor.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10")
        summary['top_sources'] = dict(cursor.fetchall())
        
        # Recent activity statistics
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE added_at >= datetime('now', '-1 day')")
        summary['recent_24h'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE added_at >= datetime('now', '-7 days')")
        summary['recent_7d'] = cursor.fetchone()[0]
        
        # High severity IOCs
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE severity_score >= 5")
        summary['high_severity_count'] = cursor.fetchone()[0]
        
        # Total unique indicators
        cursor.execute("SELECT COUNT(DISTINCT raw) FROM iocs")
        summary['unique_indicators'] = cursor.fetchone()[0]
        
        return summary
    
    def detect_anomalies(self):
        """Detect anomalous patterns in threat data"""
        anomalies = []
        
        # Sudden spikes in IOC volume
        query = """
        SELECT DATE(added_at) as date, COUNT(*) as daily_count
        FROM iocs 
        WHERE added_at >= datetime('now', '-30 days')
        GROUP BY DATE(added_at)
        ORDER BY daily_count DESC
        LIMIT 5
        """
        
        cursor = self.conn.cursor()
        cursor.execute(query)
        daily_counts = cursor.fetchall()
        
        if daily_counts:
            avg_daily = sum(count for _, count in daily_counts) / len(daily_counts)
            
            for date, count in daily_counts:
                if count > avg_daily * 2:  # More than 2x average
                    anomalies.append({
                        'type': 'volume_spike',
                        'date': date,
                        'count': count,
                        'description': f'Unusual volume spike: {count} IOCs (avg: {avg_daily:.1f})'
                    })
        
        # Unusual severity patterns
        cursor.execute("""
        SELECT severity_score, COUNT(*) as count
        FROM iocs 
        WHERE added_at >= datetime('now', '-7 days')
        GROUP BY severity_score
        HAVING COUNT(*) > (SELECT AVG(score_count) * 1.5 FROM 
            (SELECT COUNT(*) as score_count FROM iocs GROUP BY severity_score))
        """)
        
        unusual_severities = cursor.fetchall()
        for severity, count in unusual_severities:
            anomalies.append({
                'type': 'severity_anomaly',
                'severity': severity,
                'count': count,
                'description': f'Unusual severity pattern: {count} IOCs with score {severity}'
            })
        
        return anomalies
    
    def export_campaign_report(self, output_path="out\\campaign_report.json"):
        """Export detailed campaign attribution report"""
        campaigns = self.campaign_attribution(time_window_hours=168)  # Last week
        infrastructure = self.infrastructure_reuse_analysis()
        temporal = self.temporal_pattern_analysis()
        summary = self.threat_landscape_summary()
        anomalies = self.detect_anomalies()
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': summary,
            'campaigns': campaigns,
            'infrastructure_reuse': infrastructure,
            'temporal_patterns': temporal,
            'anomalies': anomalies,
            'statistics': {
                'total_campaigns': len(campaigns),
                'reused_infrastructure_count': len(infrastructure),
                'temporal_data_points': len(temporal)
            }
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"Campaign report exported to: {output_path}")
            return output_path
        
        except Exception as e:
            print(f"Error exporting campaign report: {e}")
            return None