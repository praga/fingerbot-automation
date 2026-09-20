import asyncio
import hashlib
import logging
import secrets
from struct import pack, unpack
from Crypto.Cipher import AES
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("fingerbot_live")

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

def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc

def encrypt_packet(key: bytes, security_flag: int, iv: bytes, data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    if pad_len != 16:
        data = data + (b"\x00" * pad_len)
    elif len(data) % 16 != 0:
        data = data + (b"\x00" * (16 - (len(data) % 16)))
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(data)
    return bytes([security_flag]) + iv + enc

def split_packet(protocol_version: int, data: bytes, mtu: int = 20) -> list:
    packets = []
    pkt_num = 0
    pos = 0
    total_len = len(data)
    while pos < total_len:
        b = bytearray()
        b += pkt_num.to_bytes(1, byteorder="big")
        if pkt_num == 0:
            b += pack(">B", total_len)
            b += pack("<B", protocol_version << 4)
        chunk = data[pos : pos + mtu - len(b)]
        b += chunk
        packets.append(bytes(b))
        pos += len(chunk)
        pkt_num += 1
    return packets

def make_request(cmd: int, data: bytes, sn: int, key: bytes, flag: int, protocol_version: int = 2, mtu: int = 20) -> list:
    raw = pack(">IIHH", sn, 0, cmd, len(data)) + data
    raw += pack(">H", crc16(raw))
    iv = secrets.token_bytes(16)
    encrypted = encrypt_packet(key, flag, iv, raw)
    return split_packet(protocol_version, encrypted, mtu)

def decrypt_payload(raw_enc: bytes, key: bytes):
    try:
        flag = raw_enc[0]
        iv = raw_enc[1:17]
        ciphertext = raw_enc[17:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        sn, ack, code, length = unpack(">IIHH", decrypted[:12])
        data = decrypted[12 : 12 + length]
        crc_recv = unpack(">H", decrypted[12 + length : 14 + length])[0]
        crc_calc = crc16(decrypted[: 12 + length])
        return flag, sn, ack, code, data, (crc_recv == crc_calc)
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

class Reassembler:
    def __init__(self):
        self.reset()

    def reset(self):
        self.buf = bytearray()
        self.expected_len = 0
        self.expected_pkt = 0

    def feed(self, arr: bytes):
        if not arr:
            return None
        pkt_num = arr[0]
        pos = 1
        if pkt_num == 0:
            self.buf = bytearray()
            self.expected_len = arr[1]
            # arr[2] is protocol version
            pos = 3
            self.expected_pkt = 0

        if pkt_num == self.expected_pkt:
            self.buf += arr[pos:]
            self.expected_pkt += 1
            if len(self.buf) >= self.expected_len:
                res = bytes(self.buf[:self.expected_len])
                self.reset()
                return res
        else:
            logger.warning(f"Unexpected pkt_num {pkt_num}, expected {self.expected_pkt}")
            self.reset()
        return None

async def run_live_test():
    login_key_bytes = LOCAL_KEY[:6].encode("utf-8")
    k_login_6 = hashlib.md5(login_key_bytes).digest()
    k_login_16 = hashlib.md5(LOCAL_KEY.encode("utf-8")).digest()

    for label, k_login, key_prefix in [
        ("6-char prefix MD5", k_login_6, login_key_bytes),
        ("16-char full MD5", k_login_16, LOCAL_KEY.encode("utf-8"))
    ]:
        logger.info(f"\n========================================================")
        logger.info(f"STARTING HANDSHAKE TEST WITH: {label} ({k_login.hex()})")
        logger.info(f"========================================================")

        async with await open_transport("usb:0") as (source, sink):
            device = Device.from_config_with_hci(None, source, sink)
            await device.power_on()
            target = hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS)
            logger.info(f"Connecting to {target}...")
            conn = await asyncio.wait_for(
                device.connect(target, own_address_type=hci.OwnAddressType.PUBLIC),
                timeout=8.0
            )
            logger.info(f"Connected! Handle: {conn.handle}")
            peer = Peer(conn)

            conn.on("disconnection", lambda r: logger.info(f"*** PERIPHERAL DISCONNECTED: {r} ***"))

            # Discover handles
            notify_char = None
            write_char = None
            for s in await peer.discover_services():
                for c in await s.discover_characteristics():
                    if c.handle == 17:
                        notify_char = c
                    elif c.handle == 21:
                        write_char = c

            if not notify_char or not write_char:
                logger.error("Could not find characteristics 17 or 21!")
                await conn.disconnect()
                continue

            reassembler = Reassembler()
            device_info_event = asyncio.Event()
            pair_event = asyncio.Event()
            state = {"srand": None, "proto": 2, "session_key": None}

            def on_notification(val: bytes):
                logger.info(f"RAW NOTIFY ({len(val)}B): {val.hex()}")
                complete = reassembler.feed(val)
                if complete:
                    logger.info(f"COMPLETE NOTIFY ({len(complete)}B): {complete.hex()}")
                    # Try decrypting with login key or session key
                    current_key = state["session_key"] if complete[0] == 5 else k_login
                    parsed = decrypt_payload(complete, current_key)
                    if parsed:
                        flag, sn, ack, code, data, crc_ok = parsed
                        logger.info(f"DECRYPTED NOTIFY: code=0x{code:04X}, CRC_OK={crc_ok}, data={data.hex()}")
                        if code == 0:  # FUN_SENDER_DEVICE_INFO
                            if len(data) >= 12:
                                state["proto"] = data[2]
                                state["srand"] = data[6:12]
                                logger.info(f"--> GOT SRAND: {state['srand'].hex()}, Protocol: {state['proto']}")
                                device_info_event.set()
                        elif code == 1:  # FUN_SENDER_PAIR
                            logger.info(f"--> PAIR CONFIRMED: data={data.hex()}")
                            pair_event.set()

            await peer.subscribe(notify_char, on_notification)
            logger.info("Subscribed to Handle 17 notifications")

            # STEP 1: Send FUN_SENDER_DEVICE_INFO (code 0)
            logger.info("STEP 1: Sending FUN_SENDER_DEVICE_INFO (code=0x0000)...")
            info_pkts = make_request(cmd=0, data=b"", sn=1, key=k_login, flag=4, protocol_version=2, mtu=20)
            for p in info_pkts:
                logger.info(f"  TX ({len(p)}B): {p.hex()}")
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.02)

            # Wait for response with srand
            try:
                await asyncio.wait_for(device_info_event.wait(), timeout=3.5)
                logger.info("SUCCESS! Device Info handshake response received!")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout waiting for FUN_SENDER_DEVICE_INFO response with {label}")
                await conn.disconnect()
                await asyncio.sleep(1.0)
                continue

            # STEP 2: Derive Session Key
            state["session_key"] = hashlib.md5(key_prefix + state["srand"]).digest()
            logger.info(f"STEP 2: Derived Session Key: {state['session_key'].hex()}")

            # STEP 3: Send FUN_SENDER_PAIR (code 1)
            logger.info("STEP 3: Sending FUN_SENDER_PAIR (code=0x0001)...")
            pair_data = bytearray()
            pair_data += UUID.encode("utf-8")
            pair_data += login_key_bytes
            pair_data += DEV_ID.encode("utf-8")
            while len(pair_data) < 44:
                pair_data += b"\x00"

            pair_pkts = make_request(cmd=1, data=bytes(pair_data), sn=2, key=state["session_key"], flag=5, protocol_version=state["proto"], mtu=20)
            for p in pair_pkts:
                logger.info(f"  TX PAIR ({len(p)}B): {p.hex()}")
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.02)

            try:
                await asyncio.wait_for(pair_event.wait(), timeout=2.5)
                logger.info("SUCCESS! Pair handshake confirmed by device!")
            except asyncio.TimeoutError:
                logger.info("Pair response not received or timed out, proceeding to DP actuation...")

            # STEP 4: Send DP 2 Switch True (code 2) and Multi-DP Click
            logger.info("STEP 4: Dispatching ACTUATION DPS under authenticated session...")
            
            # 1. DP 2 Switch Toggle (True)
            dp2_data = pack(">BBB", 2, 1, 1) + bytes([1])
            dp2_pkts = make_request(cmd=2, data=dp2_data, sn=3, key=state["session_key"], flag=5, protocol_version=state["proto"], mtu=20)
            for p in dp2_pkts:
                logger.info(f"  TX DP 2 ({len(p)}B): {p.hex()}")
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.02)
            await asyncio.sleep(0.5)

            # 2. Multi-DP Click Sequence (Mode=0, Down=100%, Sustain=0s, Click=1)
            multi_dps = (
                pack(">BBB", 8, 4, 1) + bytes([0]) +
                pack(">BBB", 9, 2, 4) + pack(">I", 100) +
                pack(">BBB", 15, 2, 4) + pack(">I", 0) +
                pack(">BBB", 10, 2, 4) + pack(">I", 0) +
                pack(">BBB", 101, 1, 1) + bytes([1])
            )
            multi_pkts = make_request(cmd=2, data=multi_dps, sn=4, key=state["session_key"], flag=5, protocol_version=state["proto"], mtu=20)
            for p in multi_pkts:
                logger.info(f"  TX Multi-DP ({len(p)}B): {p.hex()}")
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.02)

            logger.info("\n*** HOLDING CONNECTION OPEN FOR 5 SECONDS TO OBSERVE MOTOR MOVEMENT ***")
            await asyncio.sleep(5.0)

            # Release switch (DP 2 = False)
            dp2_off = pack(">BBB", 2, 1, 1) + bytes([0])
            dp2_off_pkts = make_request(cmd=2, data=dp2_off, sn=5, key=state["session_key"], flag=5, protocol_version=state["proto"], mtu=20)
            for p in dp2_off_pkts:
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.02)

            await asyncio.sleep(1.0)
            await conn.disconnect()
            logger.info("Cleanly disconnected after successful actuation test!")
            return

if __name__ == "__main__":
    asyncio.run(run_live_test())
