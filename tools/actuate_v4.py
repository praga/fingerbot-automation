import asyncio, hashlib, logging, secrets, struct
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("tuya_v4")

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

def build_pkts(sn: int, cmd: int, data: bytes, key: bytes, flag: int = 4, proto: int = 4, mtu: int = 20):
    iv = secrets.token_bytes(16)
    raw = bytearray(struct.pack(">IIHH", sn, 0, cmd, len(data)) + data)
    raw += struct.pack(">H", crc16(bytes(raw)))
    while len(raw) % 16 != 0: raw += b"\x00"
    enc = bytes([flag]) + iv + aes_enc(key, iv, bytes(raw))
    chunks, pnum, pos, L = [], 0, 0, len(enc)
    while pos < L:
        pkt = bytearray(pack_int(pnum))
        if pnum == 0:
            pkt += pack_int(L) + struct.pack(">B", proto << 4)
        part = enc[pos : pos + mtu - len(pkt)]
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

def decrypt_res(enc: bytes, key: bytes):
    if len(enc) < 17 or len(enc[17:]) % 16 != 0: return None
    try:
        raw = aes_dec(key, enc[1:17], enc[17:])
        if len(raw) < 12: return None
        sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
        data = raw[12 : 12 + length]
        crc_recv = struct.unpack(">H", raw[12 + length : 14 + length])[0]
        return code, data, (crc_recv == crc16(raw[:12 + length]))
    except Exception:
        return None

async def main():
    k_login_16 = hashlib.md5(LOCAL_KEY.encode()).digest()
    logger.info(f"Connecting to {MAC} with key {k_login_16.hex()}...")

    async with await open_transport("usb:0") as (src, dst):
        dev = Device.from_config_with_hci(None, src, dst)
        await dev.power_on()
        conn = await asyncio.wait_for(dev.connect(hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS), own_address_type=hci.OwnAddressType.PUBLIC), timeout=8.0)
        peer = Peer(conn)
        conn.on("disconnection", lambda r: logger.info(f"DISCONNECTED: {r}"))

        h17, h21 = None, None
        for s in await peer.discover_services():
            for c in await s.discover_characteristics():
                if c.handle == 17: h17 = c
                elif c.handle == 21: h21 = c

        rx = Reassembler()
        state = {"srand": None, "session_key": None}
        dev_info_evt = asyncio.Event()
        pair_evt = asyncio.Event()

        def on_notify(val: bytes):
            logger.info(f"NOTIFY: {val.hex()}")
            full = rx.feed(val)
            if not full: return
            logger.info(f"FULL NOTIFY: {full.hex()}")
            for k in [k_login_16, state["session_key"]]:
                if not k: continue
                dec = decrypt_res(full, k)
                if dec:
                    code, data, ok = dec
                    logger.info(f"DECRYPT: code=0x{code:04X} crc_ok={ok} data={data.hex()}")
                    if code == 0:
                        state["srand"] = data[6:12]
                        logger.info(f"*** GOT SRAND: {state['srand'].hex()} ***")
                        dev_info_evt.set()
                    elif code == 1:
                        logger.info(f"*** PAIR RESP: data={data.hex()} ***")
                        pair_evt.set()

        await peer.subscribe(h17, on_notify)
        logger.info("Subscribed H17")

        # 1. DEV_INFO with 20B MTU payload (0x0014)
        logger.info("STEP 1: DEV_INFO (cmd 0)...")
        for p in build_pkts(1, 0, bytes([0x00, 0x14]), k_login_16, flag=4, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(dev_info_evt.wait(), timeout=3.5)
            logger.info("DEV_INFO ACK RECEIVED!")
        except asyncio.TimeoutError:
            logger.warning("DEV_INFO timeout, trying direct PAIR_REQ...")

        if state["srand"]:
            state["session_key"] = hashlib.md5(LOCAL_KEY.encode() + state["srand"]).digest()
            logger.info(f"Session key derived: {state['session_key'].hex()}")

        # 2. PAIR_REQ: 16B UUID + 6B key + 22B DEV_ID
        logger.info("STEP 2: PAIR_REQ (cmd 1)...")
        pair_d = bytearray(UUID.encode()) + LOCAL_KEY[:6].encode() + DEV_ID.encode()
        while len(pair_d) < 44: pair_d += b"\x00"

        active_k = state["session_key"] if state["session_key"] else k_login_16
        active_f = 5 if state["session_key"] else 4
        for p in build_pkts(2, 1, bytes(pair_d), active_k, flag=active_f, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(pair_evt.wait(), timeout=3.0)
            logger.info("PAIR ACK RECEIVED!")
        except asyncio.TimeoutError:
            logger.warning("PAIR timeout, proceeding to DP actuation...")

        # 3. ACTUATE: DP 2 (Switch True) & DP 101 (Click)
        logger.info("STEP 3: ACTUATING MOTOR...")
        dp_k = state["session_key"] if state["session_key"] else k_login_16
        dp_f = 5 if state["session_key"] else 4

        # DP 2 Switch True
        for p in build_pkts(3, 2, bytes([2, 1, 1, 1]), dp_k, flag=dp_f, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        # DP 101 Click True
        for p in build_pkts(4, 2, bytes([101, 1, 1, 1]), dp_k, flag=dp_f, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        # Multi-DP sequence
        multi = (
            struct.pack('>BBB', 8, 4, 1) + bytes([0]) +
            struct.pack('>BBB', 9, 2, 4) + struct.pack('>I', 100) +
            struct.pack('>BBB', 15, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 10, 2, 4) + struct.pack('>I', 0) +
            struct.pack('>BBB', 101, 1, 1) + bytes([1])
        )
        for p in build_pkts(5, 2, multi, dp_k, flag=dp_f, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        logger.info("HOLDING 5 SECONDS FOR PHYSICAL ARM MOVEMENT...")
        await asyncio.sleep(5.0)

        # Retract: DP 2 False
        for p in build_pkts(6, 2, bytes([2, 1, 1, 0]), dp_k, flag=dp_f, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        await asyncio.sleep(1.0)
        await conn.disconnect()
        logger.info("Test finished cleanly!")

if __name__ == "__main__":
    asyncio.run(main())
