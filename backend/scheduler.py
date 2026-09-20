"""
Automation Scheduler for Fingerbot
Powered by APScheduler with live countdown, interval management,
active hours enforcement, and execution history logging.
"""
import asyncio
import logging
from datetime import datetime, time as dtime
from typing import Dict, Any, List, Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .config import load_config
from .ble_controller import ble_controller

logger = logging.getLogger("fingerbot.scheduler")


class ExecutionLog:
    def __init__(self, message: str, success: bool = True, details: Optional[Dict[str, Any]] = None):
        self.timestamp = datetime.now().isoformat()
        self.message = message
        self.success = success
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "message": self.message,
            "success": self.success,
            "details": self.details
        }


class FingerbotScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.job_id = "fingerbot_press_job"
        self.stop_job_id = "fingerbot_auto_stop_job"
        self.is_running = False
        self.total_presses = 0
        self.failed_presses = 0
        self.last_result: Optional[Dict[str, Any]] = None
        self.logs: List[ExecutionLog] = []
        self.max_logs = 200
        self.session_start_time: Optional[datetime] = None
        self.stop_at: Optional[datetime] = None
        self.stop_after_hours: Optional[float] = None

    def add_log(self, message: str, success: bool = True, details: Optional[Dict[str, Any]] = None):
        log_entry = ExecutionLog(message, success, details)
        self.logs.insert(0, log_entry)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[:self.max_logs]

    def _is_within_active_hours(self) -> bool:
        config = load_config()
        if not config.active_hours_enabled:
            return True

        now = datetime.now().time()
        try:
            start_parts = [int(x) for x in config.active_hours_start.split(":")]
            end_parts = [int(x) for x in config.active_hours_end.split(":")]
            start_t = dtime(start_parts[0], start_parts[1])
            end_t = dtime(end_parts[0], end_parts[1])

            if start_t <= end_t:
                return start_t <= now <= end_t
            else:
                # Spans midnight
                return now >= start_t or now <= end_t
        except Exception as e:
            logger.warning(f"Error parsing active hours: {e}")
            return True

    async def _execute_press(self, is_manual: bool = False):
        config = load_config()

        # Check active hours if not manual trigger
        if not is_manual and not self._is_within_active_hours():
            msg = f"Skipped press: Outside active hours ({config.active_hours_start} - {config.active_hours_end})"
            logger.info(msg)
            self.add_log(msg, success=True, details={"reason": "outside_active_hours"})
            return

        trigger_type = "Manual" if is_manual else "Scheduled"
        logger.info(f"Triggering {trigger_type} Fingerbot press...")

        result = await ble_controller.press_fingerbot(
            arm_duration=config.arm_duration_seconds,
            repeat_count=getattr(config, "presses_per_cycle", 2),
            repeat_delay=getattr(config, "repeat_delay_seconds", 5.0)
        )
        self.last_result = result

        if result.get("success"):
            self.total_presses += 1
            msg = f"{trigger_type} press successful ({result.get('duration_seconds', 0)}s)"
            logger.info(msg)
            self.add_log(msg, success=True, details=result)

            # Check max press count limit
            if not is_manual and config.max_press_count > 0 and self.total_presses >= config.max_press_count:
                limit_msg = f"Reached maximum configured press limit ({config.max_press_count}). Stopping automation."
                logger.info(limit_msg)
                self.add_log(limit_msg, success=True)
                self.stop()
        else:
            self.failed_presses += 1
            err_msg = result.get("error", "Unknown error")
            msg = f"{trigger_type} press failed: {err_msg}"
            logger.error(msg)
            self.add_log(msg, success=False, details=result)
        return result

    async def _auto_stop_session(self):
        hours = self.stop_after_hours
        msg = f"Auto-stop duration reached ({hours}h). Automation stopped."
        logger.info(msg)
        self.add_log(msg, success=True, details={"event": "auto_stop_reached", "hours": hours})
        self.stop(reason=f"auto_stop_{hours}h")

    def start(self, interval_minutes: Optional[float] = None, stop_after_hours: Optional[float] = None, explicit_duration: bool = True) -> Dict[str, Any]:
        config = load_config()
        save_needed = False
        if interval_minutes is not None and interval_minutes > 0:
            config.interval_minutes = interval_minutes
            save_needed = True

        if explicit_duration:
            if stop_after_hours is not None and float(stop_after_hours) > 0:
                config.stop_after_hours = float(stop_after_hours)
            else:
                config.stop_after_hours = None
            save_needed = True

        if save_needed:
            from .config import save_config
            save_config(config)

        interval = config.interval_minutes
        seconds = int(interval * 60)
        if seconds < 5:
            seconds = 5  # minimum 5 seconds safety threshold

        # Ensure background scheduler is running
        if not self.scheduler.running:
            self.scheduler.start()

        # Remove existing interval job if any
        if self.scheduler.get_job(self.job_id):
            self.scheduler.remove_job(self.job_id)

        # Remove existing auto-stop job if any
        if self.scheduler.get_job(self.stop_job_id):
            self.scheduler.remove_job(self.stop_job_id)

        # Schedule recurring interval job
        trigger = IntervalTrigger(seconds=seconds)
        self.scheduler.add_job(
            self._execute_press,
            trigger=trigger,
            id=self.job_id,
            name="fingerbot_interval_press",
            replace_existing=True
        )

        # Handle auto-stop after X hours
        from datetime import timedelta
        now = datetime.now()
        was_already_running = self.is_running
        self.session_start_time = self.session_start_time if was_already_running and self.session_start_time else now

        if config.stop_after_hours and config.stop_after_hours > 0:
            self.stop_after_hours = config.stop_after_hours
            # Auto-stop target from now
            self.stop_at = now + timedelta(hours=config.stop_after_hours)
            self.scheduler.add_job(
                self._auto_stop_session,
                trigger="date",
                run_date=self.stop_at,
                id=self.stop_job_id,
                name="fingerbot_auto_stop",
                replace_existing=True
            )
            duration_msg = f" (Auto-stops in {config.stop_after_hours}h at {self.stop_at.strftime('%H:%M:%S')})"
        else:
            self.stop_after_hours = None
            self.stop_at = None
            duration_msg = " (Continuous mode)"

        self.is_running = True
        action_word = "Automation updated" if was_already_running else "Automation started"
        msg = f"{action_word}: Press every {interval}m ({seconds}s){duration_msg}"
        logger.info(msg)
        self.add_log(msg, success=True)

        return self.get_status()

    def stop(self, reason: Optional[str] = None) -> Dict[str, Any]:
        if self.scheduler.get_job(self.job_id):
            self.scheduler.remove_job(self.job_id)
        if self.scheduler.get_job(self.stop_job_id):
            self.scheduler.remove_job(self.stop_job_id)

        self.is_running = False
        self.session_start_time = None
        self.stop_at = None
        self.stop_after_hours = None

        msg = f"Automation stopped{' (' + reason + ')' if reason else ''}."
        logger.info(msg)
        self.add_log(msg, success=True)
        return self.get_status()

    async def trigger_now(self) -> Dict[str, Any]:
        return await self._execute_press(is_manual=True)

    def get_status(self) -> Dict[str, Any]:
        config = load_config()
        job = self.scheduler.get_job(self.job_id) if self.scheduler.running else None

        next_run = None
        seconds_remaining = None

        if job and job.next_run_time:
            next_run = job.next_run_time.isoformat()
            now = datetime.now(job.next_run_time.tzinfo)
            seconds_remaining = max(0, int((job.next_run_time - now).total_seconds()))

        session_seconds_remaining = None
        if self.is_running and self.stop_at:
            now_dt = datetime.now()
            session_seconds_remaining = max(0, int((self.stop_at - now_dt).total_seconds()))

        return {
            "is_running": self.is_running,
            "interval_minutes": config.interval_minutes,
            "stop_after_hours": self.stop_after_hours or config.stop_after_hours,
            "session_start_time": self.session_start_time.isoformat() if self.session_start_time else None,
            "stop_at": self.stop_at.isoformat() if self.stop_at else None,
            "session_seconds_remaining": session_seconds_remaining,
            "next_run_time": next_run,
            "seconds_remaining": seconds_remaining,
            "total_presses": self.total_presses,
            "failed_presses": self.failed_presses,
            "ble_status": ble_controller.last_status,
            "ble_is_busy": ble_controller.is_busy,
            "last_press_time": ble_controller.last_press_time.isoformat() if ble_controller.last_press_time else None,
            "last_rssi": ble_controller.last_rssi,
            "device_mac": config.device_mac,
            "device_name": config.device_name,
            "arm_duration_seconds": config.arm_duration_seconds,
            "active_hours_enabled": config.active_hours_enabled,
            "active_hours_start": config.active_hours_start,
            "active_hours_end": config.active_hours_end,
            "max_press_count": config.max_press_count,
            "presses_per_cycle": getattr(config, "presses_per_cycle", 2),
            "repeat_delay_seconds": getattr(config, "repeat_delay_seconds", 5.0),
            "has_local_key": bool(config.local_key.strip())
        }

    def get_logs(self) -> List[Dict[str, Any]]:
        return [log.to_dict() for log in self.logs]


# Global scheduler instance
bot_scheduler = FingerbotScheduler()
