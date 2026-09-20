"""
BLE Controller for Tuya Fingerbot using Userspace Google Bumble Stack
Communicates directly with the USB Bluetooth Controller (CSR8510 / 0a12:0001)
without requiring Linux kernel Bluetooth support (CONFIG_BT).
Implements authenticated Tuya BLE v4 protocol with AES-128-CBC session key derivation.
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import Optional, Dict, Any, List

from bumble.transport import open_transport
from bumble.device import Device, Peer
from bumble.core import AdvertisingData
import bumble.hci as hci

from .config import load_config
from .tuya_protocol import (
    TuyaBleCodec,
    PacketReassembler,
    CMD_DEV_INFO,
    CMD_PAIR,
    CMD_DP_CONTROL_V4,
    CMD_STATUS_REPORT_1,
    CMD_STATUS_REPORT_6,
    CMD_STATUS_REPORT_11,
)

logger = logging.getLogger("fingerbot.ble")

# Characteristic Handles on Tuya BLE Fingerbot
TUYA_NOTIFY_CHAR_HANDLE = 17   # 00000002-0000-1001-8001-00805F9B07D0 (WRITE | NOTIFY)
TUYA_WRITE_NORESP_HANDLE = 21  # 00000001-0000-1001-8001-00805F9B07D0 (WRITE_WITHOUT_RESPONSE)


class FingerbotBleController:
    def __init__(self, transport_spec: str = "usb:0"):
        self.transport_spec = transport_spec
        self.lock = asyncio.Lock()
        self.is_busy = False
        self.last_status = "Ready"
        self.last_press_time: Optional[datetime] = None
        self.last_rssi: Optional[int] = -47
        self.last_error: Optional[str] = None

    async def press_fingerbot(
        self,
        arm_duration: float = 2.0,
        repeat_count: int = 2,
        repeat_delay: float = 5.0
    ) -> Dict[str, Any]:
        """
        Connects to the Tuya Fingerbot over BLE, executes the authenticated Tuya BLE v4
        handshake (DEV_INFO -> srand -> session_key -> PAIR_REQ), actuates the physical servo arm
        (DP 1 True / False) for repeat_count cycles, and retracts cleanly.
        """
        async with self.lock:
            self.is_busy = True
            self.last_status = "Connecting"
            self.last_error = None
            start_time = time.time()
            try:
                config = load_config()
                target_mac = config.device_mac.strip().upper()
                local_key = config.local_key.strip()

                if not target_mac or target_mac in ("00:00:00:00:00:00", "--:--:--:--:--:--", "AA:BB:CC:DD:EE:FF"):
                    err_msg = (
                        "Tuya Fingerbot MAC address required: Please configure your device's Bluetooth MAC address in Settings."
                    )
                    self.last_error = err_msg
                    self.last_status = "Requires Device MAC"
                    logger.warning(f"Press aborted: {err_msg}")
                    return {
                        "success": False,
                        "requires_mac": True,
                        "error": err_msg,
                        "target_mac": target_mac
                    }

                if not local_key or len(local_key) < 6:
                    err_msg = (
                        "Tuya Local Key required: Your Fingerbot requires its 16-character Local Key "
                        "to authorize motor movement. Please configure it in Settings."
                    )
                    self.last_error = err_msg
                    self.last_status = "Requires Local Key"
                    logger.warning(f"Press aborted: {err_msg}")
                    return {
                        "success": False,
                        "requires_local_key": True,
                        "error": err_msg,
                        "target_mac": target_mac
                    }

                logger.info(f"Initiating authenticated Tuya BLE v4 press sequence for {target_mac}...")

                reassembler = PacketReassembler()
                codec = TuyaBleCodec(local_key=local_key)
                handshake_event = asyncio.Event()
                pair_event = asyncio.Event()

                def on_notify(value: bytes):
                    logger.debug(f"Received GATT notify fragment: {value.hex()}")
                    full_payload = reassembler.feed(value)
                    if full_payload:
                        parsed = codec.parse_notification(full_payload)
                        if parsed:
                            code, ack, data = parsed
                            logger.info(f"Decrypted notification: code=0x{code:04X}, ack={ack}, len={len(data)}")
                            if code == CMD_DEV_INFO and len(data) >= 12:
                                codec.is_bound = (data[5] != 0)
                                srand = data[6:12]
                                logger.info(f"Device info received: bound={codec.is_bound}, srand={srand.hex()}")
                                codec.set_session_key_from_srand(srand)
                                handshake_event.set()
                            elif code == CMD_PAIR:
                                logger.info(f"Tuya BLE pair confirmed: result={data[0] if data else 'unknown'}")
                                pair_event.set()
                            elif code == CMD_DP_CONTROL_V4:
                                logger.info(f"Tuya BLE v4 DP write ACK received: {data.hex()}")
                            elif code in (CMD_STATUS_REPORT_1, CMD_STATUS_REPORT_6, CMD_STATUS_REPORT_11):
                                logger.info(f"Tuya BLE hardware status report (0x{code:04X}): {data.hex()}")
                        else:
                            logger.warning(f"Failed to decrypt notification payload: {full_payload.hex()}")

                # Open userspace USB transport to CSR8510 dongle
                async with await open_transport(self.transport_spec) as (hci_source, hci_sink):
                    device = Device.from_config_with_hci(None, hci_source, hci_sink)
                    await device.power_on()

                    target_address = hci.Address(target_mac, hci.Address.PUBLIC_DEVICE_ADDRESS)
                    logger.info(f"Connecting to {target_address} via {self.transport_spec}...")
                    self.last_status = "Connecting to device"

                    connection = await asyncio.wait_for(
                        device.connect(target_address, own_address_type=hci.OwnAddressType.PUBLIC),
                        timeout=10.0
                    )
                    logger.info(f"Connected to Fingerbot! Handle: {connection.handle}")
                    self.last_status = "Connected"

                    try:
                        peer = Peer(connection)

                        # Subscribe to Handle 17 for notifications and discover Handle 21 for writes
                        self.last_status = "Discovering services"
                        services = await peer.discover_services()
                        notify_char = None
                        write_char = None
                        for s in services:
                            chars = await s.discover_characteristics()
                            for c in chars:
                                if c.handle == TUYA_NOTIFY_CHAR_HANDLE:
                                    notify_char = c
                                elif c.handle == TUYA_WRITE_NORESP_HANDLE:
                                    write_char = c
                            if notify_char and write_char:
                                break

                        if not notify_char or not write_char:
                            err_msg = "Could not find characteristic handles 17 or 21 on device"
                            logger.error(err_msg)
                            self.last_error = err_msg
                            self.last_status = "Discovery Failed"
                            return {
                                "success": False,
                                "error": err_msg,
                                "target_mac": target_mac
                            }

                        await peer.subscribe(notify_char, on_notify)
                        logger.info("Subscribed to notification characteristic handle 17")

                        # Step 1: Send DEV_INFO request (cmd 0x0000, flag 4, encrypted with login_key)
                        self.last_status = "Authenticating with device"
                        info_packets = codec.build_device_info_request()
                        logger.info(f"Sending DEV_INFO request ({len(info_packets)} fragments)...")
                        for pkt in info_packets:
                            await peer.write_value(write_char, pkt, with_response=False)
                            await asyncio.sleep(0.03)

                        try:
                            await asyncio.wait_for(handshake_event.wait(), timeout=4.0)
                        except asyncio.TimeoutError:
                            raise TimeoutError("Device did not respond to DEV_INFO authentication request.")

                        pair_packets = codec.build_pair_request(
                            uuid=getattr(config, "uuid", "") or "",
                            device_id=getattr(config, "device_id", "") or ""
                        )
                        logger.info(f"Sending PAIR_REQ ({len(pair_packets)} fragments)...")
                        for pkt in pair_packets:
                            await peer.write_value(write_char, pkt, with_response=False)
                            await asyncio.sleep(0.03)

                        try:
                            await asyncio.wait_for(pair_event.wait(), timeout=2.5)
                        except asyncio.TimeoutError:
                            logger.info("Pair ACK timeout, proceeding with actuation under established session key...")

                        # Step 3: Actuate Physical Servo Arm (DP 1 True / False for repeat_count cycles)
                        total_cycles = max(1, int(repeat_count))
                        hold_duration = max(float(arm_duration), 2.0)
                        sn = 3

                        for cycle in range(1, total_cycles + 1):
                            self.last_status = f"Actuating arm ({cycle}/{total_cycles})"
                            logger.info(f"Sending DP 1 True (Extend arm, press {cycle}/{total_cycles})...")
                            dp1_on_packets = codec.build_dp1_command(value=True, sn=sn)
                            sn += 1
                            for pkt in dp1_on_packets:
                                await peer.write_value(write_char, pkt, with_response=False)
                                await asyncio.sleep(0.03)

                            self.last_status = f"Arm extending {cycle}/{total_cycles} ({hold_duration}s)"
                            logger.info(f"Holding servo arm for {hold_duration}s (press {cycle}/{total_cycles})...")
                            await asyncio.sleep(hold_duration)

                            # Retract Arm
                            logger.info(f"Sending DP 1 False (Retract arm, press {cycle}/{total_cycles})...")
                            dp1_off_packets = codec.build_dp1_command(value=False, sn=sn)
                            sn += 1
                            for pkt in dp1_off_packets:
                                await peer.write_value(write_char, pkt, with_response=False)
                                await asyncio.sleep(0.03)

                            if cycle < total_cycles:
                                delay = max(0.5, float(repeat_delay))
                                self.last_status = f"Waiting {delay}s before next press ({cycle}/{total_cycles})..."
                                logger.info(f"Waiting {delay}s between consecutive presses ({cycle}/{total_cycles})...")
                                await asyncio.sleep(delay)
                            else:
                                await asyncio.sleep(1.0)

                        self.last_status = "Completed"
                        self.last_press_time = datetime.now()
                        elapsed = round(time.time() - start_time, 2)
                        status_text = f"Arm pressed {total_cycles}x & retracted" if total_cycles > 1 else "Arm pressed & retracted"
                        logger.info(f"Fingerbot physical press cycle completed successfully ({status_text}) in {elapsed}s")

                        return {
                            "success": True,
                            "timestamp": self.last_press_time.isoformat(),
                            "duration_seconds": elapsed,
                            "target_mac": target_mac,
                            "status": status_text
                        }
                    finally:
                        self.last_status = "Disconnecting"
                        try:
                            await connection.disconnect()
                            logger.info("Disconnected cleanly from Fingerbot.")
                        except Exception as disc_err:
                            logger.debug(f"Disconnect notice: {disc_err}")

            except asyncio.TimeoutError:
                self.last_error = f"Connection timeout: Fingerbot {target_mac} not responding."
                self.last_status = "Timeout"
                logger.error(self.last_error)
                return {
                    "success": False,
                    "error": self.last_error,
                    "target_mac": target_mac
                }
            except Exception as e:
                self.last_error = f"BLE error: {str(e)}"
                self.last_status = "Error"
                logger.exception("Error executing Fingerbot press")
                return {
                    "success": False,
                    "error": self.last_error,
                    "target_mac": target_mac
                }
            finally:
                self.is_busy = False
                if self.last_error:
                    self.last_status = "Error"
                else:
                    self.last_status = "Idle"

    async def scan_nearby(self, duration: float = 4.0) -> List[Dict[str, Any]]:
        """
        Scans for nearby BLE devices and returns discovered devices including RSSI.
        """
        found_devices: Dict[str, Dict[str, Any]] = {}
        config = load_config()
        target_mac = config.device_mac.strip().upper()

        try:
            async with await open_transport(self.transport_spec) as (hci_source, hci_sink):
                device = Device.from_config_with_hci(None, hci_source, hci_sink)
                await device.power_on()

                def on_advertisement(advertisement):
                    addr_str = str(advertisement.address).split("/")[0].upper()
                    name = (
                        advertisement.data.get(AdvertisingData.COMPLETE_LOCAL_NAME) or
                        advertisement.data.get(AdvertisingData.SHORTENED_LOCAL_NAME) or
                        "Unknown"
                    )
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="ignore")

                    service_uuids = advertisement.data.get(AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS) or []
                    complete_service_uuids = advertisement.data.get(AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS) or []
                    all_uuids = list(service_uuids) + list(complete_service_uuids)
                    is_tuya = "TY" in str(name) or addr_str == target_mac or any("FD50" in str(u).upper() for u in all_uuids)

                    found_devices[addr_str] = {
                        "address": addr_str,
                        "name": str(name).strip(),
                        "rssi": advertisement.rssi,
                        "is_target": (addr_str == target_mac),
                        "is_tuya": is_tuya
                    }
                    if addr_str == target_mac:
                        self.last_rssi = advertisement.rssi

                device.on(device.EVENT_ADVERTISEMENT, on_advertisement)
                await device.start_scanning()
                await asyncio.sleep(duration)
                await device.stop_scanning()

        except Exception as e:
            logger.warning(f"Error during BLE scan: {e}")

        results = list(found_devices.values())
        results.sort(key=lambda x: (not x["is_target"], -x["rssi"]))
        return results


# Global singleton instance
ble_controller = FingerbotBleController()
