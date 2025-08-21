
from collections import Counter

def count_ioc_freqs(ioc_list):
    c = Counter()
    for i in ioc_list:
        raw = i if isinstance(i, str) else i.get("raw")
        c[raw] += 1
    return c

def find_reused_infrastructure(storage_conn, min_count=2):
    cur = storage_conn._conn.cursor()
    cur.execute("SELECT raw, COUNT(*) as c FROM iocs GROUP BY raw HAVING c >= ?", (min_count,))
    return cur.fetchall()
