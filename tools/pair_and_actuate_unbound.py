import asyncio, hashlib, logging, secrets, struct
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pair_and_actuate")

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
        logger.info("Scanning for reset advertisement (0x50FD with 0x41)...")
        reset_event = asyncio.Event()
        def on_adv(adv):
            addr = str(adv.address)
            if MAC in addr.upper():
                raw = bytes(adv.data).hex() if adv.data else ""
                if "50fd41" in raw:
                    logger.info(f"*** UNBOUND ADV DETECTED: {raw} ***")
                    reset_event.set()
                else:
                    logger.info(f"Adv (waiting for reset): {raw}")
        dev.on("advertisement", on_adv)
        await dev.start_scanning()
        try:
            await asyncio.wait_for(reset_event.wait(), timeout=180.0)
        finally:
            await dev.stop_scanning()

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
        pair_evt = asyncio.Event()

        def on_notify(val: bytes):
            logger.info(f"RAW NOTIFY ({len(val)}B): {val.hex()}")
            full = rx.feed(val)
            if not full: return
            logger.info(f"COMPLETE NOTIFY ({len(full)}B): {full.hex()}")
            flag = full[0]
            logger.info(f"Notification Flag={flag}")

            # Try parsing plaintext or decrypting
            candidates = [("none", None)]
            if state["session_key"]:
                candidates.append(("session", state["session_key"]))
            candidates.append(("login_md5", hashlib.md5(LOCAL_KEY.encode()).digest()))
            candidates.append(("login_raw", LOCAL_KEY.encode()))

            for name, k in candidates:
                try:
                    if flag == 0:
                        raw = full[1:]
                    else:
                        if not k: continue
                        raw = aes_dec(k, full[1:17], full[17:])
                    sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
                    data = raw[12 : 12 + length]
                    logger.info(f"SUCCESS PARSED ({name}): cmd=0x{code:04X} data={data.hex()}")
                    if code == 0: # DEV_INFO
                        state["bound"] = (data[5] != 0)
                        state["srand"] = data[6:12]
                        logger.info(f"*** DEV_INFO: bound={state['bound']} srand={state['srand'].hex()} ***")
                        dev_info_evt.set()
                        return
                    elif code == 1: # PAIR_RESP
                        logger.info(f"*** PAIR_RESP: result={data[0] if data else 'none'} ***")
                        pair_evt.set()
                        return
                except Exception:
                    pass

        await peer.subscribe(h17, on_notify)
        logger.info("Subscribed Handle 17")

        # 1. Send DEV_INFO (flag=0)
        logger.info("--- 1. Sending DEV_INFO (flag=0) ---")
        for p in build_pkts(1, 0, bytes([0x00, 0x14]), flag=0, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        await asyncio.wait_for(dev_info_evt.wait(), timeout=3.5)
        logger.info(f"DEV_INFO received! SRAND = {state['srand'].hex()}")

        # Session key = MD5(login_key + srand)
        # login_key is first 6 bytes of LOCAL_KEY
        key_6 = LOCAL_KEY[:6].encode()
        state["session_key"] = hashlib.md5(key_6 + state["srand"]).digest()
        logger.info(f"Derived session key: {state['session_key'].hex()}")

        # 2. Build 61-byte PAIR_REQ payload:
        # 16B UUID + 6B key + 22B DEV_ID + 1B len (16) + 16B beacon_key
        pair_data = bytearray()
        pair_data += UUID.encode()                      # 16 bytes
        pair_data += key_6                              # 6 bytes
        pair_data += DEV_ID.encode().ljust(22, b"\x00") # 22 bytes
        pair_data += bytes([16])                        # 1 byte (BEACON_KEY_LEN)
        pair_data += LOCAL_KEY.encode()                 # 16 bytes beacon key
        logger.info(f"PAIR_REQ payload length: {len(pair_data)} bytes")

        # Test sending PAIR_REQ with flag=0 (unencrypted)
        logger.info("--- 2. Sending PAIR_REQ (flag=0) ---")
        for p in build_pkts(2, 1, bytes(pair_data), flag=0, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        try:
            await asyncio.wait_for(pair_evt.wait(), timeout=3.5)
            logger.info("PAIR SUCCESS!")
        except asyncio.TimeoutError:
            logger.warning("PAIR flag=0 timeout, testing with flag=2...")
            pair_evt.clear()
            k_p2 = hashlib.md5(LOCAL_KEY.encode()).digest()
            for p in build_pkts(3, 1, bytes(pair_data), key=k_p2, flag=2, proto=4):
                await peer.write_value(h21, p, with_response=False)
                await asyncio.sleep(0.03)
            try:
                await asyncio.wait_for(pair_evt.wait(), timeout=3.5)
                logger.info("PAIR flag=2 SUCCESS!")
            except asyncio.TimeoutError:
                logger.warning("PAIR flag=2 timed out.")

        # 3. ACTUATE MOTOR: DP 2 (Switch True) & DP 101 (Click)
        logger.info("--- 3. ACTUATING PHYSICAL SERVO MOTOR (cmd = 0x0027) ---")
        k_dp = state["session_key"]
        
        # DP 2 True (Bool, len 1, val 1)
        dp2_true = bytes([0x00]) + struct.pack(">IBBHB", 1, 2, 1, 1, 1)
        for p in build_pkts(4, 0x0027, dp2_true, key=k_dp, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        # DP 101 True (Click, Bool, len 1, val 1)
        dp101_true = bytes([0x00]) + struct.pack(">IBBHB", 2, 101, 1, 1, 1)
        for p in build_pkts(5, 0x0027, dp101_true, key=k_dp, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        # Multi-DP sequence with 0x0027
        multi_klv = (
            struct.pack('>BBHB', 8, 4, 1, 0) +
            struct.pack('>BBHI', 9, 2, 4, 100) +
            struct.pack('>BBHI', 15, 2, 4, 0) +
            struct.pack('>BBHI', 10, 2, 4, 0) +
            struct.pack('>BBHB', 101, 1, 1, 1) +
            struct.pack('>BBHB', 2, 1, 1, 1)
        )
        multi_dp = bytes([0x00]) + struct.pack(">I", 3) + multi_klv
        for p in build_pkts(6, 0x0027, multi_dp, key=k_dp, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        logger.info("HOLDING 6 SECONDS FOR PHYSICAL SERVO ARM EXTENSION...")
        await asyncio.sleep(6.0)

        # Retract / DP 2 False
        dp2_false = bytes([0x00]) + struct.pack(">IBBHB", 4, 2, 1, 1, 0)
        for p in build_pkts(7, 0x0027, dp2_false, key=k_dp, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

        await asyncio.sleep(2.0)
        await conn.disconnect()
        logger.info("DONE!")

if __name__ == "__main__":
    asyncio.run(run())
