import asyncio
import hashlib
import logging
import secrets
import struct
import sys
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("diagnose_motor")

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

_local_key = LOCAL_KEY[:6].encode()
_login_key = hashlib.md5(_local_key).digest()

def crc16(d: bytes) -> int:
    c = 0xFFFF
    for b in d:
        c ^= b & 255
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if (c & 1) else (c >> 1)
    return c

def pack_int(v: int) -> bytearray:
    r = bytearray()
    while True:
        curr = v & 0x7F
        v >>= 7
        if v != 0: curr |= 0x80
        r.append(curr)
        if v == 0: break
    return r

def unpack_int(d: bytes, pos: int = 0):
    res, off = 0, 0
    while off < 5:
        p = pos + off
        if p >= len(d): break
        b = d[p]
        res |= (b & 0x7F) << (off * 7)
        off += 1
        if (b & 0x80) == 0: break
    return res, pos + off

def aes_enc(k: bytes, iv: bytes, d: bytes) -> bytes:
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).encryptor()
    return c.update(d) + c.finalize()

def aes_dec(k: bytes, iv: bytes, d: bytes) -> bytes:
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).decryptor()
    return c.update(d) + c.finalize()

def build_pkts(sn: int, cmd: int, data: bytes, key: bytes, flag: int, proto: int = 4, mtu: int = 20):
    raw = bytearray(struct.pack(">IIHH", sn, 0, cmd, len(data)) + data)
    raw += struct.pack(">H", crc16(bytes(raw)))
    while len(raw) % 16 != 0:
        raw += b"\x00"
    iv = secrets.token_bytes(16)
    body = bytes([flag]) + iv + aes_enc(key, iv, bytes(raw))

    chunks, pnum, pos, L = [], 0, 0, len(body)
    while pos < L:
        pkt = bytearray(pack_int(pnum))
        if pnum == 0:
            pkt += pack_int(L) + struct.pack(">B", proto << 4)
        part = body[pos : pos + mtu - len(pkt)]
        pkt += part
        chunks.append(bytes(pkt))
        pos += len(part)
        pnum += 1
    return chunks

class Reassembler:
    def __init__(self):
        self.buf = bytearray()
        self.expected_len = 0
        self.expected_pkt = 0

    def feed(self, chunk: bytes):
        if not chunk: return None
        pnum, pos = unpack_int(chunk, 0)
        if pnum == 0:
            self.buf = bytearray()
            self.expected_len, pos = unpack_int(chunk, pos)
            pos += 1
            self.expected_pkt = 0
        if pnum != self.expected_pkt:
            self.buf, self.expected_len, self.expected_pkt = bytearray(), 0, 0
            return None
        self.buf += chunk[pos:]
        self.expected_pkt += 1
        if len(self.buf) >= self.expected_len:
            res = bytes(self.buf[:self.expected_len])
            self.buf, self.expected_len, self.expected_pkt = bytearray(), 0, 0
            return res
        return None

async def run(test_target: str = "all"):
    async with await open_transport("usb:0") as (src, dst):
        dev = Device.from_config_with_hci(None, src, dst)
        await dev.power_on()
        logger.info(f"Connecting to {MAC}...")
        conn = await asyncio.wait_for(
            dev.connect(hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS), own_address_type=hci.OwnAddressType.PUBLIC),
            timeout=8.0
        )
        peer = Peer(conn)
        conn.on("disconnection", lambda r: logger.info(f"DISCONNECTED: {r}"))

        h17, h21 = None, None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17: h17 = c
                elif c.handle == 21: h21 = c

        rx = Reassembler()
        state = {"bound": False, "srand": None, "session_key": None}
        dev_info_evt = asyncio.Event()

        def on_notify(val: bytes):
            full = rx.feed(val)
            if not full: return
            flag = full[0]
            keys_to_try = [("login_key", _login_key)]
            if state["session_key"]:
                keys_to_try.insert(0, ("session_key", state["session_key"]))

            for name, k in keys_to_try:
                try:
                    raw = aes_dec(k, full[1:17], full[17:])
                    sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
                    data = raw[12 : 12 + length]
                    logger.info(f"<< RECV: cmd=0x{code:04X} ack={ack} len={length} data={data.hex()}")
                    if code == 0:
                        state["bound"] = (data[5] != 0)
                        state["srand"] = data[6:12]
                        dev_info_evt.set()
                        return
                except Exception:
                    pass

        await peer.subscribe(h17, on_notify)
        logger.info("Subscribed Handle 17")

        # 1. DEV_INFO
        logger.info("--> Sending DEV_INFO...")
        for p in build_pkts(1, 0, bytes([0x00, 0x14]), key=_login_key, flag=4, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        await asyncio.wait_for(dev_info_evt.wait(), timeout=4.0)
        state["session_key"] = hashlib.md5(_local_key + state["srand"]).digest()
        logger.info(f"Session key established: {state['session_key'].hex()}")

        # 2. PAIR_REQ
        logger.info("--> Sending PAIR_REQ...")
        pair_data = bytearray()
        pair_data += UUID.encode()
        pair_data += _local_key
        pair_data += DEV_ID.encode().ljust(22, b"\x00")
        while len(pair_data) < 44: pair_data += b"\x00"

        for p in build_pkts(2, 1, bytes(pair_data), key=state["session_key"], flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        await asyncio.sleep(0.5)

        k_s = state["session_key"]

        # TEST 1: Query all current DP status (cmd = 0x0003 or 0x0027 query)
        logger.info("\n--- TEST 1: Request Status (cmd = 0x0003) ---")
        for p in build_pkts(3, 3, b"", key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        await asyncio.sleep(1.0)

        # TEST 2: Multi-DP sequence via 0x0027
        # Set Mode = 0 (Click), Down% = 100, Up% = 0, Sustain = 1s, Click = True
        logger.info("\n--- TEST 2: Multi-DP 0x0027 (Mode=0 Click, Down=100%, Sustain=1s, Click=1) ---")
        multi_klv = (
            struct.pack('>BBHB', 8, 4, 1, 0) +           # DP 8 (Mode): Enum 0 (Click)
            struct.pack('>BBHI', 9, 2, 4, 100) +         # DP 9 (Down %): Int 100
            struct.pack('>BBHI', 15, 2, 4, 0) +          # DP 15 (Up %): Int 0
            struct.pack('>BBHI', 10, 2, 4, 1) +          # DP 10 (Sustain s): Int 1
            struct.pack('>BBHB', 101, 1, 1, 1)           # DP 101 (Click): Bool 1
        )
        multi_payload = bytes([0x00]) + struct.pack(">I", 10) + multi_klv
        for p in build_pkts(4, 0x0027, multi_payload, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        logger.info("WAITING 4 SECONDS FOR SERVO ACTION...")
        await asyncio.sleep(4.0)

        # TEST 3: Click DP 101 via cmd = 0x0002 with 1-byte length
        logger.info("\n--- TEST 3: DP 101 Click via cmd = 0x0002 (1-byte length format) ---")
        # Format: [dp_id, dp_type, len, val] = [101, 1, 1, 1]
        raw_cmd2_101 = struct.pack('>BBBB', 101, 1, 1, 1)
        for p in build_pkts(5, 2, raw_cmd2_101, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        logger.info("WAITING 4 SECONDS FOR SERVO ACTION...")
        await asyncio.sleep(4.0)

        # TEST 4: Full Multi-DP via cmd = 0x0002 (1-byte length format as in redphx pyfingerbot)
        logger.info("\n--- TEST 4: Multi-DP via cmd = 0x0002 (redphx pyfingerbot format) ---")
        redphx_dps = (
            struct.pack('>BBB', 8, 4, 1) + bytes([0]) +
            struct.pack('>BBB', 9, 2, 4) + struct.pack('>I', 100) +
            struct.pack('>BBB', 15, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 10, 2, 4) + struct.pack('>I', 1) +
            struct.pack('>BBB', 101, 1, 1) + bytes([1])
        )
        for p in build_pkts(6, 2, redphx_dps, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        logger.info("WAITING 4 SECONDS FOR SERVO ACTION...")
        await asyncio.sleep(4.0)

        # TEST 5: Switch Mode via 0x0027: DP 8 = 1 (Switch Mode), then DP 2 = True
        logger.info("\n--- TEST 5: Set Mode = 1 (Switch Mode) and Toggle DP 2 True ---")
        switch_mode = bytes([0x00]) + struct.pack(">I", 20) + struct.pack('>BBHB', 8, 4, 1, 1)
        for p in build_pkts(7, 0x0027, switch_mode, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        await asyncio.sleep(0.5)

        dp2_on = bytes([0x00]) + struct.pack(">IBBHB", 21, 2, 1, 1, 1)
        for p in build_pkts(8, 0x0027, dp2_on, key=k_dp if 'k_dp' in locals() else k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        logger.info("WAITING 4 SECONDS FOR SWITCH ARM MOVEMENT...")
        await asyncio.sleep(4.0)

        # Retract switch
        dp2_off = bytes([0x00]) + struct.pack(">IBBHB", 22, 2, 1, 1, 0)
        for p in build_pkts(9, 0x0027, dp2_off, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        await asyncio.sleep(2.0)

        await conn.disconnect()
        logger.info("Diagnostic completed!")

if __name__ == "__main__":
    asyncio.run(run())
