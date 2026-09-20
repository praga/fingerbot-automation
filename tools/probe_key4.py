import asyncio, hashlib, logging, secrets, struct
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("probe_key4")

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
    raw = bytearray(struct.pack(">IIHH", sn, 0, cmd, len(data)) + data)
    raw += struct.pack(">H", crc16(bytes(raw)))
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
    k6 = LOCAL_KEY[:6].encode()
    candidates = [
        ("md5_k6", hashlib.md5(k6).digest()),
        ("md5_k16", hashlib.md5(LOCAL_KEY.encode()).digest()),
        ("raw_k16", LOCAL_KEY.encode()),
        ("k6_padded", k6.ljust(16, b"\x00")),
        ("md5_uuid_k6", hashlib.md5(UUID.encode() + k6).digest()),
        ("md5_k6_uuid", hashlib.md5(k6 + UUID.encode()).digest()),
        ("md5_devid_k6", hashlib.md5(DEV_ID.encode() + k6).digest()),
        ("beacon_key_md5", hashlib.md5(LOCAL_KEY.encode()).digest()),
    ]

    async with await open_transport("usb:0") as (src, dst):
        dev = Device.from_config_with_hci(None, src, dst)
        await dev.power_on()

        for cand_name, cand_key in candidates:
            logger.info(f"=== TESTING CANDIDATE KEY: {cand_name} ({cand_key.hex()}) ===")
            try:
                conn = await asyncio.wait_for(
                    dev.connect(hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS), own_address_type=hci.OwnAddressType.PUBLIC),
                    timeout=5.0
                )
            except Exception as e:
                logger.warning(f"Connect failed: {e}")
                await asyncio.sleep(1.0)
                continue

            peer = Peer(conn)
            h17, h21 = None, None
            for s in await peer.discover_services():
                for c in await s.discover_characteristics():
                    if c.handle == 17: h17 = c
                    elif c.handle == 21: h21 = c

            rx = Reassembler()
            got_reply = asyncio.Event()

            def on_notify(val: bytes):
                logger.info(f"NOTIFY RECEIVED ({len(val)}B): {val.hex()}")
                full = rx.feed(val)
                if full:
                    logger.info(f"*** FULL NOTIFY ({len(full)}B): {full.hex()} ***")
                    got_reply.set()

            await peer.subscribe(h17, on_notify)

            # Send DEV_INFO with flag=4 using cand_key
            pkts = build_pkts(1, 0, bytes([0x00, 0x14]), cand_key, flag=4, proto=4)
            for p in pkts:
                await peer.write_value(h21, p, with_response=False)
                await asyncio.sleep(0.03)

            try:
                await asyncio.wait_for(got_reply.wait(), timeout=2.5)
                logger.info(f"SUCCESS! KEY FOUND: {cand_name} = {cand_key.hex()}")
                await conn.disconnect()
                return cand_name, cand_key
            except asyncio.TimeoutError:
                logger.info(f"Candidate {cand_name} timed out.")

            await conn.disconnect()
            await asyncio.sleep(0.5)

    logger.warning("No candidate key produced a response.")

if __name__ == "__main__":
    asyncio.run(run())
