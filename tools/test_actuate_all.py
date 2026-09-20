import asyncio
import hashlib
import logging
import secrets
import struct
import time
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("actuate_all")

try:
    from ._config import get_device_credentials
except ImportError:
    try:
        from _config import get_device_credentials
    except ImportError:
        import os
        get_device_credentials = lambda: (
            os.getenv("DEVICE_MAC", "AA:BB:CC:DD:EE:FF"),
            os.getenv("LOCAL_KEY", "YOUR_16_CHAR_KEY"),
            os.getenv("DEVICE_UUID", "YOUR_DEVICE_UUID"),
            os.getenv("DEVICE_ID", "YOUR_DEVICE_ID"),
        )

MAC, LOCAL_KEY, UUID, DEV_ID = get_device_credentials()

def calc_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte & 255
        for _ in range(8):
            tmp = crc & 1
            crc >>= 1
            if tmp != 0:
                crc ^= 0xA001
    return crc

def pack_int(value: int) -> bytearray:
    result = bytearray()
    while True:
        curr = value & 0x7F
        value >>= 7
        if value != 0:
            curr |= 0x80
        result.append(curr)
        if value == 0:
            break
    return result

def build_packets(seq_num: int, code: int, data: bytes, key: bytes, security_flag: bytes = b"\x04", protocol_version: int = 2, mtu: int = 20) -> list:
    raw = bytearray()
    raw += struct.pack(">IIHH", seq_num, 0, code, len(data))
    raw += data
    crc = calc_crc16(raw)
    raw += struct.pack(">H", crc)
    while len(raw) % 16 != 0:
        raw += b"\x00"

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    encrypted = security_flag + iv + enc.update(bytes(raw)) + enc.finalize()

    command = []
    packet_num = 0
    pos = 0
    length = len(encrypted)
    while pos < length:
        packet = bytearray()
        packet += pack_int(packet_num)
        if packet_num == 0:
            packet += pack_int(length)
            packet += struct.pack(">B", protocol_version << 4)
        data_part = encrypted[pos : pos + mtu - len(packet)]
        packet += data_part
        command.append(bytes(packet))
        pos += len(data_part)
        packet_num += 1
    return command

async def main():
    key = hashlib.md5(LOCAL_KEY.encode()).digest()
    logger.info(f"Target: {MAC}, Key MD5: {key.hex()}")

    async with await open_transport("usb:0") as (source, sink):
        device = Device.from_config_with_hci(None, source, sink)
        
        # Log all incoming HCI packets from the radio
        def on_hci(pkt):
            pkt_str = str(pkt)
            if "ACL" in pkt_str or "Notification" in pkt_str or "Event" in pkt_str:
                if "HCI_LE_Advertising_Report_Event" not in pkt_str:
                    logger.info(f"[HCI RAW] {pkt_str[:120]}")
        device.host.on("hci_packet", on_hci)

        await device.power_on()
        target = hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS)
        logger.info(f"Connecting to {target}...")
        conn = await asyncio.wait_for(device.connect(target, own_address_type=hci.OwnAddressType.PUBLIC), timeout=10.0)
        logger.info(f"Connected! Handle={conn.handle}")
        peer = Peer(conn)

        conn.on("disconnection", lambda r: logger.info(f"*** DISCONNECTION EVENT: {r} ***"))

        notify_c = None
        write_c = None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17:
                    notify_c = c
                if c.handle == 21:
                    write_c = c

        def on_notify(val: bytes):
            logger.info(f"*** NOTIFICATION on Handle 17: {val.hex()} (len={len(val)}) ***")

        if notify_c:
            await peer.subscribe(notify_c, on_notify)
            logger.info("Subscribed to handle 17")

        seq = 1

        # 1. Send PAIR request (code 1, 44 bytes)
        pair_data = bytearray()
        pair_data += UUID.encode("utf-8")
        pair_data += LOCAL_KEY[:6].encode("utf-8")
        pair_data += DEV_ID.encode("utf-8")
        while len(pair_data) < 44:
            pair_data += b"\x00"

        logger.info("=== STEP 1: Sending PAIR request (code=1) ===")
        for p in build_packets(seq, 1, bytes(pair_data), key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(1.0)

        # 2. Send DP 2 Switch Toggle (1-byte length: [2, 1, 1, 1])
        logger.info("=== STEP 2: Sending DP 2 Switch Toggle (code=2, 1-byte len) ===")
        dp2_1b = struct.pack(">BBB", 2, 1, 1) + bytes([1])
        for p in build_packets(seq, 2, dp2_1b, key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(2.0)

        # 3. Send DP 101 Click (1-byte length: [101, 1, 1, 1])
        logger.info("=== STEP 3: Sending DP 101 Click (code=2, 1-byte len) ===")
        dp101_1b = struct.pack(">BBB", 101, 1, 1) + bytes([1])
        for p in build_packets(seq, 2, dp101_1b, key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(2.0)

        # 4. Send Multi-DP sequence (Mode=0, Down=100%, Up=0%, Sustain=0s, Click=1)
        logger.info("=== STEP 4: Sending Multi-DP Fingerbot sequence ===")
        multi = (
            struct.pack(">BBB", 8, 4, 1) + bytes([0]) +
            struct.pack(">BBB", 9, 2, 4) + struct.pack(">I", 100) +
            struct.pack(">BBB", 15, 2, 4) + struct.pack(">I", 0) +
            struct.pack(">BBB", 10, 2, 4) + struct.pack(">I", 0) +
            struct.pack(">BBB", 101, 1, 1) + bytes([1])
        )
        for p in build_packets(seq, 2, multi, key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(2.0)

        # 5. Send DP 2 Switch Toggle (2-byte length: [2, 1, 0, 1, 1])
        logger.info("=== STEP 5: Sending DP 2 Switch Toggle (code=2, 2-byte len) ===")
        dp2_2b = bytes([2, 1, 0, 1, 1])
        for p in build_packets(seq, 2, dp2_2b, key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(2.0)

        # 6. Send DPS V4 (code=0x0027)
        logger.info("=== STEP 6: Sending DPS V4 (code=0x0027) DP 2 ===")
        v4_dp2 = bytes.fromhex("00000000010201000101")
        for p in build_packets(seq, 0x0027, v4_dp2, key, b"\x04", 2, 20):
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)
        seq += 1
        await asyncio.sleep(2.0)

        # 7. Write DP 2 directly to Handle 17 (which is WRITE|NOTIFY)
        logger.info("=== STEP 7: Sending DP 2 to Handle 17 (write with response) ===")
        try:
            for p in build_packets(seq, 2, dp2_1b, key, b"\x04", 2, 20):
                logger.info(f"  TX to H17: {p.hex()}")
                await peer.write_value(notify_c, p, with_response=True)
                await asyncio.sleep(0.03)
            seq += 1
        except Exception as e:
            logger.warning(f"Write to H17 failed: {e}")

        logger.info("=== Holding connection open for 4.0s to allow physical movement ===")
        await asyncio.sleep(4.0)
        await conn.disconnect()
        logger.info("Disconnected cleanly. All steps complete!")

if __name__ == "__main__":
    asyncio.run(main())
