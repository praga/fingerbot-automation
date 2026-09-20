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
logger = logging.getLogger("tuya_bumble")

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

def aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

def aes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()

def build_packets(sn: int, ack_sn: int, code: int, data: bytes, key: bytes, security_flag: int, mtu: int = 20) -> list:
    raw = struct.pack(">IIHH", sn, ack_sn, code, len(data)) + data
    crc = calc_crc16(raw)
    raw += struct.pack(">H", crc)
    while len(raw) % 16 != 0:
        raw += b"\x00"

    iv = secrets.token_bytes(16)
    encrypted = bytes([security_flag]) + iv + aes_encrypt(key, iv, raw)

    chunks = []
    packet_num = 0
    pos = 0
    length = len(encrypted)
    while pos < length:
        chunk = bytearray()
        chunk.append(packet_num)
        if packet_num == 0:
            chunk.append(length)
            chunk.append(2 << 4)  # v2 -> 0x20
        space = mtu - len(chunk)
        sub = encrypted[pos : pos + space]
        chunk += sub
        chunks.append(bytes(chunk))
        pos += len(sub)
        packet_num += 1
    return chunks

class TuyaParser:
    def __init__(self, key_mgr):
        self.key_mgr = key_mgr
        self.buf = bytearray()
        self.exp_len = 0
        self.exp_num = 0

    def feed(self, chunk: bytes):
        if not chunk:
            return None
        p_num = chunk[0]
        pos = 1
        if p_num == 0:
            if len(chunk) < 3:
                return None
            self.exp_len = chunk[1]
            pos = 3
            self.buf = bytearray()
            self.exp_num = 0
        if p_num != self.exp_num:
            logger.warning(f"Seq mismatch: {p_num} vs {self.exp_num}")
            self.buf = bytearray()
            return None
        self.buf += chunk[pos:]
        self.exp_num += 1
        if len(self.buf) >= self.exp_len:
            completed = bytes(self.buf[:self.exp_len])
            self.buf = bytearray()
            self.exp_num = 0
            self.exp_len = 0
            return self.parse_payload(completed)
        return None

    def parse_payload(self, raw: bytes):
        sec_flag = raw[0]
        iv = raw[1:17]
        enc = raw[17:]
        key = self.key_mgr.get(sec_flag)
        if not key:
            logger.warning(f"No key for flag {sec_flag}")
            return None
        dec = aes_decrypt(key, iv, enc)
        sn, ack_sn, code, dlen = struct.unpack(">IIHH", dec[:12])
        data = dec[12 : 12 + dlen]
        logger.info(f"Decrypted packet: sn={sn} ack={ack_sn} code={hex(code)} len={dlen} data={data.hex()}")
        return code, data

async def run():
    keys = {}
    login_key_bytes = LOCAL_KEY[:6].encode("utf-8")
    keys[4] = hashlib.md5(login_key_bytes).digest()
    logger.info(f"Login key (k6): {login_key_bytes.decode()} -> MD5: {keys[4].hex()}")

    parser = TuyaParser(keys)
    info_event = asyncio.Event()
    pair_event = asyncio.Event()
    received_srand = [None]

    def on_parsed(code, data):
        if code == 0x0000:
            # Device Info Response: 46 bytes
            logger.info(f"DEVICE INFO RECEIVED: {data.hex()}")
            if len(data) >= 12:
                srand = data[6:12]
                received_srand[0] = srand
                # session key: MD5(login_key + srand)
                keys[5] = hashlib.md5(login_key_bytes + srand).digest()
                logger.info(f"Derived session key (flag 5): {keys[5].hex()} using srand {srand.hex()}")
                info_event.set()
        elif code == 0x0001:
            logger.info(f"PAIR RESPONSE RECEIVED: {data.hex()}")
            pair_event.set()
        else:
            logger.info(f"OTHER PACKET: code={hex(code)} data={data.hex()}")

    async with await open_transport("usb:0") as (source, sink):
        device = Device.from_config_with_hci(None, source, sink)
        await device.power_on()
        target = hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS)
        logger.info(f"Connecting to {target}...")
        conn = await asyncio.wait_for(device.connect(target, own_address_type=hci.OwnAddressType.PUBLIC), timeout=10.0)
        logger.info(f"Connected! Handle={conn.handle}")
        peer = Peer(conn)
        conn.on("disconnection", lambda r: logger.info(f"*** DISCONNECT: {r} ***"))

        notify_c = None
        write_c = None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17:
                    notify_c = c
                elif c.handle == 21:
                    write_c = c

        def on_notify(val: bytes):
            logger.info(f"[H17 NOTIFY raw]: {val.hex()}")
            res = parser.feed(val)
            if res:
                code, data = res
                on_parsed(code, data)

        await peer.subscribe(notify_c, on_notify)
        logger.info("Subscribed to handle 17")

        # Step 1: Send Device Info (code 0, empty data, flag 4)
        logger.info("--> Sending FUN_SENDER_DEVICE_INFO (code 0x0000)...")
        pkts = build_packets(sn=1, ack_sn=0, code=0x0000, data=b"", key=keys[4], security_flag=4, mtu=20)
        for p in pkts:
            logger.info(f"  TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(info_event.wait(), timeout=4.0)
            logger.info("SUCCESS: Device info received and session key established!")
        except asyncio.TimeoutError:
            logger.warning("No device info response received within 4.0s!")

        if 5 in keys:
            # Step 2: Send Pair Request
            logger.info("--> Sending FUN_SENDER_PAIR (code 0x0001)...")
            pair_data = bytearray()
            pair_data += UUID.encode("utf-8")
            pair_data += login_key_bytes
            pair_data += DEV_ID.encode("utf-8")
            while len(pair_data) < 44:
                pair_data += b"\x00"

            pkts = build_packets(sn=2, ack_sn=0, code=0x0001, data=bytes(pair_data), key=keys[5], security_flag=5, mtu=20)
            for p in pkts:
                logger.info(f"  TX: {p.hex()}")
                await peer.write_value(write_c, p, with_response=False)
                await asyncio.sleep(0.03)

            try:
                await asyncio.wait_for(pair_event.wait(), timeout=4.0)
                logger.info("SUCCESS: Paired!")
            except asyncio.TimeoutError:
                logger.warning("No pair response received within 4.0s!")

            # Step 3: Send DP actuation!
            logger.info("--> Sending FUN_SENDER_DPS (code 0x0002) DP 101 Click!")
            dp_101 = bytes([101, 1, 1, 1])
            pkts = build_packets(sn=3, ack_sn=0, code=0x0002, data=dp_101, key=keys[5], security_flag=5, mtu=20)
            for p in pkts:
                logger.info(f"  TX: {p.hex()}")
                await peer.write_value(write_c, p, with_response=False)
                await asyncio.sleep(0.03)

            logger.info("Waiting 3.0s after DP 101...")
            await asyncio.sleep(3.0)

            logger.info("--> Sending Multi-DP Fingerbot sequence...")
            multi = (
                struct.pack(">BBB", 8, 4, 1) + bytes([0]) +
                struct.pack(">BBB", 9, 2, 4) + struct.pack(">I", 80) +
                struct.pack(">BBB", 15, 2, 4) + struct.pack(">I", 0) +
                struct.pack(">BBB", 10, 2, 4) + struct.pack(">I", 0) +
                struct.pack(">BBB", 101, 1, 1) + bytes([1])
            )
            pkts = build_packets(sn=4, ack_sn=0, code=0x0002, data=multi, key=keys[5], security_flag=5, mtu=20)
            for p in pkts:
                logger.info(f"  TX: {p.hex()}")
                await peer.write_value(write_c, p, with_response=False)
                await asyncio.sleep(0.03)

            logger.info("Holding connection for 5.0s for physical servo movement...")
            await asyncio.sleep(5.0)

        await conn.disconnect()
        logger.info("Disconnected cleanly.")

if __name__ == "__main__":
    asyncio.run(run())
