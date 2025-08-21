import sqlite3
import json
import os
from pathlib import Path
import glob

def analyze_current_data():
    print("=== ThreatInt Data Analysis ===\n")
    
    # Check if out directory exists
    if not os.path.exists("out"):
        print("❌ 'out' directory not found")
        return
    
    # Check database
    db_path = "out\\iocs.db"
    if os.path.exists(db_path):
        print("✅ Database found!")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Basic stats
            cursor.execute("SELECT COUNT(*) FROM iocs")
            total_iocs = cursor.fetchone()[0]
            print(f"📊 Total IOCs in database: {total_iocs}")
            
            if total_iocs > 0:
                # IOC types breakdown
                cursor.execute("SELECT types, COUNT(*) FROM iocs GROUP BY types")
                types_count = cursor.fetchall()
                print("\n📋 IOC Types Distribution:")
                for ioc_type, count in types_count:
                    print(f"  {ioc_type}: {count}")
                
                # Severity distribution
                cursor.execute("SELECT severity_score, COUNT(*) FROM iocs GROUP BY severity_score ORDER BY severity_score DESC")
                severity_dist = cursor.fetchall()
                print("\n⚠️ Severity Score Distribution:")
                for score, count in severity_dist:
                    print(f"  Score {score}: {count} IOCs")
                
                # Top sources
                cursor.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source")
                sources = cursor.fetchall()
                print("\n🔗 Sources:")
                for source, count in sources:
                    print(f"  {source}: {count}")
                
                # Recent activity
                cursor.execute("SELECT COUNT(*) FROM iocs WHERE added_at >= datetime('now', '-1 day')")
                recent_count = cursor.fetchone()[0]
                print(f"\n🕐 IOCs added in last 24 hours: {recent_count}")
                
                # Sample IOCs
                cursor.execute("SELECT raw, types, severity_score FROM iocs ORDER BY severity_score DESC LIMIT 5")
                samples = cursor.fetchall()
                print("\n🔍 Top 5 IOCs by Severity:")
                for raw, types, score in samples:
                    print(f"  {score}: {raw} ({types})")
                
            conn.close()
            
        except Exception as e:
            print(f"❌ Error reading database: {e}")
    else:
        print("❌ Database file not found")
    
    # Check JSON files
    json_pattern = os.path.join("out", "iocs_*.json")
    json_files = glob.glob(json_pattern)
    
    if json_files:
        # Get the most recent JSON file
        latest_json = max(json_files, key=os.path.getctime)
        print(f"\n📄 Latest JSON export: {os.path.basename(latest_json)}")
        
        try:
            with open(latest_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"📄 JSON file contains {len(data)} records")
            
            if data:
                print("\n🔍 Sample IOC structure:")
                sample = data[0]
                for key, value in sample.items():
                    if key == 'meta' and isinstance(value, dict):
                        print(f"  {key}: {{...}} (dict with {len(value)} keys)")
                    elif isinstance(value, str) and len(value) > 50:
                        print(f"  {key}: {value[:47]}...")
                    else:
                        print(f"  {key}: {value}")
                        
                # JSON file statistics
                ioc_types_json = {}
                severity_scores_json = {}
                
                for item in data:
                    # Count types
                    types = item.get('types', [])
                    if isinstance(types, list):
                        for t in types:
                            ioc_types_json[t] = ioc_types_json.get(t, 0) + 1
                    
                    # Count severity scores
                    score = item.get('severity_score', 0)
                    severity_scores_json[score] = severity_scores_json.get(score, 0) + 1
                
                print(f"\n📈 JSON Analysis:")
                print(f"  Unique IOC types: {len(ioc_types_json)}")
                print(f"  Severity range: {min(severity_scores_json.keys())} - {max(severity_scores_json.keys())}")
                
        except Exception as e:
            print(f"❌ Error reading JSON file: {e}")
    else:
        print("❌ No JSON export files found")
    
    # Check logs if they exist
    log_files = glob.glob("out\\*.log")
    if log_files:
        print(f"\n📋 Found {len(log_files)} log file(s)")
        for log_file in log_files:
            size = os.path.getsize(log_file)
            print(f"  {os.path.basename(log_file)}: {size} bytes")
    
    print("\n" + "="*50)
    print("Analysis complete!")

if __name__ == "__main__":
    analyze_current_data()