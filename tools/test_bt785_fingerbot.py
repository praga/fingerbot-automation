import asyncio
import hashlib
import logging
import secrets
import struct
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bt785_test")

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

def make_command_fragments(sn: int, rn: int, cmd: int, data: bytes, key: bytes, flag: int = 4, version: int = 2) -> list:
    # 1. Build CommandFrame with CRC
    b = bytearray()
    b += struct.pack(">IIHH", sn, rn, cmd, len(data))
    b += data
    crc = calc_crc16(bytes(b))
    frame_bytes = bytes(b) + struct.pack(">H", crc)

    # 2. PKCS#7 Pad & Encrypt
    iv = secrets.token_bytes(16)
    pad_len = (-len(frame_bytes)) % 16
    padded = frame_bytes + bytes([pad_len]) * pad_len
    encrypted_data = aes_encrypt(key, iv, padded)

    # 3. EncryptedPacket: flag (1B) + iv (16B) + encrypted_data
    payload = bytes([flag]) + iv + encrypted_data

    # 4. Fragment into max 23-byte chunks (bt785 style)
    fragments = []
    packet_nr = 0
    maxsize = 23
    chunk = bytearray()
    chunk += struct.pack("BBB", packet_nr, len(payload), version << 4)
    for d in payload:
        if len(chunk) % maxsize == 0:
            fragments.append(bytes(chunk))
            packet_nr += 1
            chunk = bytearray([packet_nr])
        chunk.append(d)
    if len(chunk) > 1:
        fragments.append(bytes(chunk))

    return fragments

async def main():
    key_6 = hashlib.md5(LOCAL_KEY[:6].encode("utf-8")).digest()
    key_16 = hashlib.md5(LOCAL_KEY.encode("utf-8")).digest()

    for key_name, key in [("key_6", key_6), ("key_16", key_16)]:
        logger.info(f"=== TESTING bt785 request_device_info with {key_name} ({key.hex()}) ===")
        async with await open_transport("usb:0") as (source, sink):
            device = Device.from_config_with_hci(None, source, sink)
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

            notif_event = asyncio.Event()
            received_notifs = []

            def on_notify(val: bytes):
                logger.info(f"[NOTIFY on H17] len={len(val)}: {val.hex()}")
                received_notifs.append(val)
                notif_event.set()

            if notify_c:
                await peer.subscribe(notify_c, on_notify)
                logger.info("Subscribed to handle 17")

            # Step 1: Request Device Info with data = bytes([0, 0xF3])
            logger.info("Sending request_device_info (data=[0x00, 0xF3])...")
            frags = make_command_fragments(sn=1, rn=0, cmd=0, data=bytes([0, 0xF3]), key=key, flag=4, version=2)
            for f in frags:
                logger.info(f"  TX ({len(f)}B): {f.hex()}")
                await peer.write_value(write_c, f, with_response=False)
                await asyncio.sleep(0.02)

            try:
                await asyncio.wait_for(notif_event.wait(), timeout=3.0)
                logger.info(f"RECEIVED NOTIFICATION with {key_name}! Count={len(received_notifs)}")
                await asyncio.sleep(1.0)
                await conn.disconnect()
                return
            except asyncio.TimeoutError:
                logger.warning(f"No notification received within 3.0s with {key_name}")

            await asyncio.sleep(1.0)
            try:
                await conn.disconnect()
            except Exception:
                pass

if __name__ == "__main__":
    asyncio.run(main())
