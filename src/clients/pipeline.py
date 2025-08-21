# src/pipeline.py
from clients.otx_client import OTXClient
from normalizer import normalize_indicator
from storage import Storage
from alerting import alert_on_ioc
import os

def run_once(db_path="./out/iocs.db", limit=50):
    otx = OTXClient()
    storage = Storage(db_path, out_dir=os.path.dirname(db_path) or "./out")
    # fetch pulses
    resp = otx.get_subscribed_pulses(limit=limit)
    pulses = resp.get("results", []) if isinstance(resp, dict) else resp
    added = 0
    for p in pulses:
        # many pulses include 'indicators' list; else skip or implement get_pulse_indicators
        indicators = p.get("indicators") or p.get("observables") or []
        for ind in indicators:
            # ensure we attach source metadata
            ind.setdefault("source", "otx")
            normalized = normalize_indicator(ind)
            stored = storage.store_ioc(normalized)
            if stored:
                added += 1
            alert_on_ioc(normalized)
    print(f"Fetched {len(pulses)} pulses, added {added} new IOCs")
    # export snapshot
    fname = storage.export_json()
    print("Exported JSON to", fname)
    return storage

if __name__ == "__main__":
    run_once()
