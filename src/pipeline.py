from src.clients.otx_client import OTXClient
from src.normalizer import normalize_indicator
from src.storage import Storage
from src.alerting import alert_on_ioc
import os

def run_once(db_path=None, limit=50):
    storage = Storage(db_path)
    otx = OTXClient()

    resp = otx.get_subscribed_pulses(limit=limit)
    pulses = resp.get("results", []) if isinstance(resp, dict) else resp
    added = 0
    for p in pulses:
        indicators = p.get("indicators") or p.get("observables") or []
        for ind in indicators:
            ind.setdefault("source", "otx")
            normalized = normalize_indicator(ind)
            stored = storage.store_ioc(normalized)
            if stored:
                added += 1
            alert_on_ioc(normalized)
    print(f"Fetched {len(pulses)} pulses, added {added} new IOCs")
    fname = storage.export_json()
    print("Exported JSON to", fname)
    return storage

if __name__ == "__main__":
    run_once()
