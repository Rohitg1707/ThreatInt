import logging
logger = logging.getLogger("tiagg")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

def alert_on_ioc(normalized):
    if normalized.get("severity_score", 0) >= 5:
        logger.warning(f"ALERT HIGH SEVERITY IOC: {normalized['raw']} score={normalized['severity_score']}")
    elif normalized.get("severity_score", 0) >= 3:
        logger.info(f"Notice: suspicious IOC: {normalized['raw']} score={normalized['severity_score']}")
