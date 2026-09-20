"""
Helper module for research & diagnostic tools to load device configuration
from data/config.json or environment variables.
"""
import os
import json

def get_device_credentials():
    cfg = {}
    config_paths = [
        "data/config.json",
        "../data/config.json",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "config.json")
    ]
    for p in config_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    cfg = json.load(f)
                break
            except Exception:
                pass

    mac = os.getenv("DEVICE_MAC", cfg.get("device_mac", "AA:BB:CC:DD:EE:FF"))
    key = os.getenv("LOCAL_KEY", cfg.get("local_key", "YOUR_16_CHAR_KEY"))
    uuid = os.getenv("DEVICE_UUID", cfg.get("uuid", "YOUR_DEVICE_UUID"))
    dev_id = os.getenv("DEVICE_ID", cfg.get("device_id", "YOUR_DEVICE_ID"))
    return mac, key, uuid, dev_id
