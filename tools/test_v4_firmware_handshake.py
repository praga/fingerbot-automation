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
logger = logging.getLogger("tuya_v4_live")

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

def unpack_int(data: bytes, start_pos: int = 0):
    result = 0
    offset = 0
    while offset < 5:
        pos = start_pos + offset
        if pos >= len(data):
            break
        curr = data[pos]
        result |= (curr & 0x7F) << (offset * 7)
        offset += 1
        if (curr & 0x80) == 0:
            break
    return result, start_pos + offset

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()

def build_packets(seq_num: int, code: int, data: bytes, key: bytes, security_flag: int = 4, protocol_version: int = 4, mtu: int = 20) -> list:
    iv = secrets.token_bytes(16)
    raw = bytearray()
    raw += struct.pack(">IIHH", seq_num, 0, code, len(data))
    raw += data
    crc = calc_crc16(bytes(raw))
    raw += struct.pack(">H", crc)
    while len(raw) % 16 != 0:
        raw += b"\x00"

    encrypted = bytes([security_flag]) + iv + aes_cbc_encrypt(key, iv, bytes(raw))

    chunks = []
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
        chunks.append(bytes(packet))
        pos += len(data_part)
        packet_num += 1

    return chunks

class Reassembler:
    def __init__(self):
        self.reset()

    def reset(self):
        self.buf = bytearray()
        self.expected_len = 0
        self.expected_pkt = 0

    def feed(self, chunk: bytes):
        if not chunk:
            return None
        try:
            packet_num, pos = unpack_int(chunk, 0)
            if packet_num == 0:
                self.buf = bytearray()
                self.expected_len, pos = unpack_int(chunk, pos)
                pos += 1  # version byte
                self.expected_pkt = 0

            if packet_num != self.expected_pkt:
                logger.warning(f"Unexpected pkt {packet_num}, expected {self.expected_pkt}")
                self.reset()
                return None

            self.buf += chunk[pos:]
            self.expected_pkt += 1

            if len(self.buf) >= self.expected_len:
                res = bytes(self.buf[:self.expected_len])
                self.reset()
                return res
        except Exception as e:
            logger.error(f"Reassembly error: {e}")
            self.reset()
        return None

def decrypt_packet(raw_enc: bytes, key: bytes):
    if len(raw_enc) < 17:
        return None
    flag = raw_enc[0]
    iv = raw_enc[1:17]
    ciphertext = raw_enc[17:]
    if len(ciphertext) % 16 != 0:
        return None
    try:
        decrypted = aes_cbc_decrypt(key, iv, ciphertext)
        if len(decrypted) < 12:
            return None
        sn, ack, code, length = struct.unpack(">IIHH", decrypted[:12])
        data_end = 12 + length
        data = decrypted[12:data_end]
        crc_recv = struct.unpack(">H", decrypted[data_end:data_end+2])[0]
        crc_calc = calc_crc16(decrypted[:data_end])
        return flag, sn, ack, code, data, (crc_recv == crc_calc)
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

async def run():
    k_login_16 = hashlib.md5(LOCAL_KEY.encode("utf-8")).digest()
    key_6_bytes = LOCAL_KEY[:6].encode("utf-8")
    key_16_bytes = LOCAL_KEY.encode("utf-8")

    logger.info(f"Target: {MAC}")
    logger.info(f"Login Key (k16): {k_login_16.hex()}")

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

        conn.on("disconnection", lambda r: logger.info(f"*** DISCONNECTED: {r} ***"))

        notify_char = None
        write_char = None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17:
                    notify_char = c
                elif c.handle == 21:
                    write_char = c

        if not notify_char or not write_char:
            logger.error("Chars 17 / 21 not found!")
            await conn.disconnect()
            return

        reassembler = Reassembler()
        events = {
            "dev_info": asyncio.Event(),
            "pair": asyncio.Event(),
        }
        state = {
            "srand": None,
            "session_key": None,
            "is_bound": False,
        }

        def on_notification(val: bytes):
            logger.info(f"RAW NOTIFY ({len(val)}B): {val.hex()}")
            complete = reassembler.feed(val)
            if not complete:
                return
            logger.info(f"COMPLETE NOTIFY ({len(complete)}B): {complete.hex()}")
            flag = complete[0]

            # Try decrypting with login key and session key
            candidates = [("k_login", k_login_16)]
            if state["session_key"]:
                candidates.insert(0, ("session_key", state["session_key"]))

            for name, k in candidates:
                parsed = decrypt_packet(complete, k)
                if parsed:
                    f, sn, ack, code, data, crc_ok = parsed
                    logger.info(f"--> DECRYPTED with {name}: cmd=0x{code:04X}, crc_ok={crc_ok}, len={len(data)}, data={data.hex()}")
                    if code == 0x0000:  # DEV_INFO RESP
                        if len(data) >= 12:
                            state["is_bound"] = (data[5] != 0)
                            state["srand"] = data[6:12]
                            logger.info(f"*** GOT SRAND: {state['srand'].hex()}, bound_flag={state['is_bound']} ***")
                            events["dev_info"].set()
                            return
                    elif code == 0x0001:  # PAIR RESP
                        logger.info(f"*** GOT PAIR RESP: data={data.hex()} (result={data[0] if data else 'none'}) ***")
                        events["pair"].set()
                        return

        await peer.subscribe(notify_char, on_notification)
        logger.info("Subscribed to Handle 17 (CCCD enabled)")

        # STEP 1: Send DEV_INFO (cmd=0x0000) with 2-byte MTU payload
        logger.info("--- STEP 1: Sending DEV_INFO (cmd=0x0000, data=[0x00, 0x14]) ---")
        info_pkts = build_packets(
            seq_num=1,
            code=0x0000,
            data=bytes([0x00, 0x14]),  # 20-byte MTU
            key=k_login_16,
            security_flag=4,
            protocol_version=4,
            mtu=20
        )
        for p in info_pkts:
            logger.info(f"  TX ({len(p)}B): {p.hex()}")
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(events["dev_info"].wait(), timeout=4.0)
            logger.info("SUCCESS: DEV_INFO response received!")
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for DEV_INFO response. Trying 0x00F3 MTU payload...")
            info_pkts_f3 = build_packets(
                seq_num=2,
                code=0x0000,
                data=bytes([0x00, 0xF3]),
                key=k_login_16,
                security_flag=4,
                protocol_version=4,
                mtu=20
            )
            for p in info_pkts_f3:
                logger.info(f"  TX F3 ({len(p)}B): {p.hex()}")
                await peer.write_value(write_char, p, with_response=False)
                await asyncio.sleep(0.03)
            try:
                await asyncio.wait_for(events["dev_info"].wait(), timeout=3.0)
                logger.info("SUCCESS: DEV_INFO response received with 0xF3!")
            except asyncio.TimeoutError:
                logger.warning("DEV_INFO still timed out. Proceeding to direct PAIR_REQ...")

        # Derive session key if srand was obtained
        if state["srand"]:
            # Test both 6-char prefix and 16-char full for session key
            state["session_key_6"] = hashlib.md5(key_6_bytes + state["srand"]).digest()
            state["session_key_16"] = hashlib.md5(key_16_bytes + state["srand"]).digest()
            state["session_key"] = state["session_key_16"]
            logger.info(f"Derived session_key_6: {state['session_key_6'].hex()}")
            logger.info(f"Derived session_key_16: {state['session_key_16'].hex()}")

        # STEP 2: Send PAIR_REQ (cmd=0x0001) with UUID first (16B) + key (6B) + DEV_ID (22B)
        logger.info("--- STEP 2: Sending PAIR_REQ (cmd=0x0001, 44B) ---")
        pair_data = bytearray()
        pair_data += UUID.encode("utf-8")           # 16 bytes
        pair_data += LOCAL_KEY[:6].encode("utf-8")   # 6 bytes
        pair_data += DEV_ID.encode("utf-8")         # 16 bytes
        while len(pair_data) < 44:
            pair_data += b"\x00"

        active_key = state["session_key"] if state["session_key"] else k_login_16
        active_flag = 5 if state["session_key"] else 4

        pair_pkts = build_packets(
            seq_num=3,
            code=0x0001,
            data=bytes(pair_data),
            key=active_key,
            security_flag=active_flag,
            protocol_version=4,
            mtu=20
        )
        for p in pair_pkts:
            logger.info(f"  TX PAIR ({len(p)}B): {p.hex()}")
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(events["pair"].wait(), timeout=3.5)
            logger.info("SUCCESS: PAIR_REQ response confirmed by device!")
        except asyncio.TimeoutError:
            logger.info("Pair response timed out. Trying PAIR_REQ with session_key_6 if available...")
            if state.get("session_key_6"):
                pair_pkts_6 = build_packets(
                    seq_num=4,
                    code=0x0001,
                    data=bytes(pair_data),
                    key=state["session_key_6"],
                    security_flag=5,
                    protocol_version=4,
                    mtu=20
                )
                for p in pair_pkts_6:
                    await peer.write_value(write_char, p, with_response=False)
                    await asyncio.sleep(0.03)
                try:
                    await asyncio.wait_for(events["pair"].wait(), timeout=3.0)
                    logger.info("SUCCESS: PAIR confirmed with session_key_6!")
                    state["session_key"] = state["session_key_6"]
                except asyncio.TimeoutError:
                    pass

        # STEP 3: DISPATCH ACTUATION COMMANDS
        logger.info("--- STEP 3: Dispatching Physical Actuation Commands ---")
        dp_key = state["session_key"] if state["session_key"] else k_login_16
        dp_flag = 5 if state["session_key"] else 4

        # 1. DP 2 Switch Toggle (True)
        logger.info(">> Sending DP 2 Switch True...")
        dp2_on = struct.pack(">BBB", 2, 1, 1) + bytes([1])
        for p in build_packets(5, 2, dp2_on, dp_key, dp_flag, 4, 20):
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        # 2. DP 101 Click (True)
        logger.info(">> Sending DP 101 Click True...")
        dp101 = struct.pack(">BBB", 101, 1, 1) + bytes([1])
        for p in build_packets(6, 2, dp101, dp_key, dp_flag, 4, 20):
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        # 3. Multi-DP Fingerbot Sequence
        logger.info(">> Sending Multi-DP Sequence (Mode=0, Down=100%, Sustain=0s, Click=1)...")
        multi_dps = (
            struct.pack('>BBB', 8, 4, 1) + bytes([0]) +
            struct.pack('>BBB', 9, 2, 4) + struct.pack('>I', 100) +
            struct.pack('>BBB', 15, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 10, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 101, 1, 1) + bytes([1])
        )
        for p in build_packets(7, 2, multi_dps, dp_key, dp_flag, 4, 20):
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        logger.info("Holding connection for 4.0s to allow servo actuation...")
        await asyncio.sleep(4.0)

        # Retract switch: DP 2 False
        logger.info(">> Sending DP 2 Switch False (Retract)...")
        dp2_off = struct.pack(">BBB", 2, 1, 1) + bytes([0])
        for p in build_packets(8, 2, dp2_off, dp_key, dp_flag, 4, 20):
            await peer.write_value(write_char, p, with_response=False)
            await asyncio.sleep(0.03)

        await asyncio.sleep(1.0)
        await conn.disconnect()
        logger.info("Clean disconnection. Handshake test complete.")

if __name__ == "__main__":
    asyncio.run(run())
