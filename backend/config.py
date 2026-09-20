import json
import os
from pydantic import BaseModel, Field
from typing import Optional

CONFIG_DIR = os.getenv("DATA_DIR", "/app/data")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


class AppConfig(BaseModel):
    device_mac: str = Field(default="", description="Tuya Fingerbot MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    device_name: str = Field(default="Tuya Fingerbot", description="Human readable device name")
    local_key: str = Field(default="", description="16-character Tuya local key (optional if unencrypted)")
    device_id: str = Field(default="", description="Tuya 20-char Device ID (optional)")
    uuid: str = Field(default="", description="Tuya 16-char Device UUID")
    interval_minutes: float = Field(default=11.0, description="Automation interval in minutes")
    presses_per_cycle: int = Field(default=2, description="Number of times to press the arm at each interval")
    repeat_delay_seconds: float = Field(default=5.0, description="Delay between consecutive presses in seconds")
    stop_after_hours: Optional[float] = Field(default=None, description="Auto-stop automation after X hours (None or 0 = continuous)")
    arm_duration_seconds: float = Field(default=1.0, description="How long the finger arm holds down before retracting")
    active_hours_enabled: bool = Field(default=False, description="Restrict presses to specific hours")
    active_hours_start: str = Field(default="08:00", description="HH:MM start time")
    active_hours_end: str = Field(default="22:00", description="HH:MM end time")
    max_press_count: int = Field(default=0, description="Stop after N presses (0 = unlimited)")
    auto_start_on_boot: bool = Field(default=False, description="Automatically start automation when container starts")
    port: int = Field(default=8085, description="Web UI port")


def load_config() -> AppConfig:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                return AppConfig(**data)
        except Exception as e:
            print(f"Error loading config from {CONFIG_FILE}: {e}, using defaults")
    config = AppConfig()
    save_config(config)
    return config


def save_config(config: AppConfig):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config.model_dump(), f, indent=2)
