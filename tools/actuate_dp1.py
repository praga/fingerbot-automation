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
logger = logging.getLogger("actuate_dp1")

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

async def run():
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
                    elif code == 0x8006:
                        # DP report
                        logger.info(f"*** STATUS REPORT DP: {data.hex()} ***")
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

        # 3. ACTUATE MOTOR: DP 1 = True (Extend)
        # Format for 0x0027:
        # [0x00] [sn: 4B] [dp_id: 1B] [dp_type: 1B] [len: 2B] [val: 1B]
        logger.info("\n========================================================")
        logger.info("--> SENDING MOTOR ACTUATE: DP 1 = 1 (EXTEND SERVO ARM)...")
        logger.info("========================================================")
        dp1_extend = bytes([0x00]) + struct.pack(">IBBHB", 100, 1, 1, 1, 1)
        for p in build_pkts(3, 0x0027, dp1_extend, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        logger.info("WAITING 3 SECONDS FOR PHYSICAL SERVO ARM EXTENSION...")
        await asyncio.sleep(3.0)

        # 4. RETRACT MOTOR: DP 1 = False (Retract)
        logger.info("\n========================================================")
        logger.info("--> SENDING MOTOR RETRACT: DP 1 = 0 (RETRACT SERVO ARM)...")
        logger.info("========================================================")
        dp1_retract = bytes([0x00]) + struct.pack(">IBBHB", 101, 1, 1, 1, 0)
        for p in build_pkts(4, 0x0027, dp1_retract, key=k_s, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        logger.info("WAITING 2 SECONDS FOR RETRACTION...")
        await asyncio.sleep(2.0)

        await conn.disconnect()
        logger.info("Physical test completed successfully!")

if __name__ == "__main__":
    asyncio.run(run())
