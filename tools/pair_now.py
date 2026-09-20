import asyncio, hashlib, logging, secrets, struct
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pair_now")

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

def build_pkts(sn: int, cmd: int, data: bytes, key: bytes = None, flag: int = 0, proto: int = 4, mtu: int = 20):
    raw = bytearray(struct.pack(">IIHH", sn, 0, cmd, len(data)) + data)
    raw += struct.pack(">H", crc16(bytes(raw)))
    
    if flag == 0 or not key:
        body = bytes([0]) + bytes(raw)
    else:
        while len(raw) % 16 != 0: raw += b"\x00"
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
        logger.info(f"Connecting to unbonded {MAC}...")
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
        state = {"bound": False, "srand": None, "auth_key": None}
        dev_info_evt = asyncio.Event()

        def on_notify(val: bytes):
            logger.info(f"RAW NOTIFY ({len(val)}B): {val.hex()}")
            full = rx.feed(val)
            if not full: return
            logger.info(f"COMPLETE NOTIFY ({len(full)}B): {full.hex()}")
            flag = full[0]
            logger.info(f"Flag={flag}")
            if flag == 0:
                raw = full[1:]
                sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
                data = raw[12 : 12 + length]
                logger.info(f"PLAINTEXT NOTIFY: code=0x{code:04X} data={data.hex()}")
                if code == 0:
                    state["bound"] = (data[5] != 0)
                    state["srand"] = data[6:12]
                    logger.info(f"*** DEV_INFO: bound={state['bound']} srand={state['srand'].hex()} ***")
                    dev_info_evt.set()

        await peer.subscribe(h17, on_notify)
        logger.info("Subscribed Handle 17")

        # Test DEV_INFO with flag=0 (unencrypted)
        logger.info("--- Sending DEV_INFO flag=0 ---")
        for p in build_pkts(1, 0, bytes([0x00, 0x14]), flag=0, proto=4):
            logger.info(f"TX: {p.hex()}")
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(dev_info_evt.wait(), timeout=3.5)
            logger.info("DEV_INFO RECEIVED WITH FLAG=0!")
        except asyncio.TimeoutError:
            logger.warning("DEV_INFO flag=0 timed out. Testing flag=1 and flag=2...")

        await asyncio.sleep(3.0)
        await conn.disconnect()

if __name__ == "__main__":
    asyncio.run(run())
