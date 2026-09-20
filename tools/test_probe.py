import asyncio
import logging
import secrets
import struct
import hashlib
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("probe")

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

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()

def build_packets(seq_num: int, code: int, data: bytes, key: bytes, security_flag: bytes = b'\x04', protocol_version: int = 2, mtu: int = 20) -> list:
    iv = secrets.token_bytes(16)
    raw = bytearray()
    raw += struct.pack('>IIHH', seq_num, 0, code, len(data))
    raw += data
    crc = calc_crc16(raw)
    raw += struct.pack('>H', crc)
    while len(raw) % 16 != 0:
        raw += b'\x00'

    encrypted = security_flag + iv + aes_cbc_encrypt(key, iv, bytes(raw))

    command = []
    packet_num = 0
    pos = 0
    length = len(encrypted)
    while pos < length:
        packet = bytearray()
        packet += pack_int(packet_num)
        if packet_num == 0:
            packet += pack_int(length)
            packet += struct.pack('>B', protocol_version << 4)
        data_part = encrypted[pos:pos + mtu - len(packet)]
        packet += data_part
        command.append(bytes(packet))
        pos += len(data_part)
        packet_num += 1
    return command

async def test():
    async with await open_transport('usb:0') as (source, sink):
        device = Device.from_config_with_hci(None, source, sink)
        await device.power_on()
        target = hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS)
        logger.info(f"Connecting to {target}...")
        conn = await asyncio.wait_for(device.connect(target, own_address_type=hci.OwnAddressType.PUBLIC), timeout=10.0)
        logger.info(f"Connected! handle={conn.handle}")
        peer = Peer(conn)

        notify_c = None
        write_c = None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17:
                    notify_c = c
                if c.handle == 21:
                    write_c = c

        def on_notify(val):
            logger.info(f"*** NOTIFY RECEIVED: {val.hex()} (len={len(val)}) ***")

        if notify_c:
            await peer.subscribe(notify_c, on_notify)
            logger.info("Subscribed to handle 17")

        key_full = hashlib.md5(LOCAL_KEY.encode()).digest()

        # TEST 1: Pair Request (code = 1)
        pair_data = bytearray()
        pair_data += UUID.encode('utf-8')
        pair_data += LOCAL_KEY[:6].encode('utf-8')
        pair_data += DEV_ID.encode('utf-8')
        while len(pair_data) < 44:
            pair_data += b'\x00'

        logger.info("--- TEST 1: Send PAIR Request (code=1) ---")
        for p in build_packets(1, 1, bytes(pair_data), key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(1.5)

        # TEST 2: DP 101 Click (code = 2, 1-byte len: 101, 1, 1, 1)
        logger.info("--- TEST 2: DP 101 Click (code=2, 1-byte len) ---")
        for p in build_packets(2, 2, bytes([101, 1, 1, 1]), key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(2.0)

        # TEST 3: DP 2 Toggle Switch True (code = 2, 1-byte len: 2, 1, 1, 1)
        logger.info("--- TEST 3: DP 2 Switch True (code=2, 1-byte len) ---")
        for p in build_packets(3, 2, bytes([2, 1, 1, 1]), key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(2.0)

        # TEST 4: DP 101 Click (code = 2, 2-byte len: 101, 1, 0, 1, 1)
        logger.info("--- TEST 4: DP 101 Click (code=2, 2-byte len) ---")
        for p in build_packets(4, 2, bytes([101, 1, 0, 1, 1]), key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(2.0)

        # TEST 5: Multi-DP sequence (Mode=0, Down=100%, Sustain=0s, Click=1)
        logger.info("--- TEST 5: Multi-DP Fingerbot sequence ---")
        multi_1b = (
            struct.pack('>BBB', 8, 4, 1) + bytes([0]) +
            struct.pack('>BBB', 9, 2, 4) + struct.pack('>I', 100) +
            struct.pack('>BBB', 10, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 101, 1, 1) + bytes([1])
        )
        for p in build_packets(5, 2, multi_1b, key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(2.0)

        # TEST 6: DPS V4 (code = 0x0027)
        logger.info("--- TEST 6: DPS V4 (code=0x0027) ---")
        v4_data = bytes.fromhex('00000000016501000101')
        for p in build_packets(6, 0x0027, v4_data, key_full, b'\x04', 2, 20):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(write_c, p, with_response=False)
            await asyncio.sleep(0.04)
        await asyncio.sleep(2.0)

        await conn.disconnect()
        logger.info("Disconnected cleanly")

asyncio.run(test())
