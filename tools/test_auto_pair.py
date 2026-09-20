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
logger = logging.getLogger("tuya_auto_pair")

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
        # Unencrypted payload
        body = bytes([0]) + bytes(raw)
    else:
        # AES-CBC encrypted payload
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

async def attempt_pairing_and_actuation(dev):
    logger.info(f"Connecting to {MAC}...")
    conn = await asyncio.wait_for(
        dev.connect(hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS), own_address_type=hci.OwnAddressType.PUBLIC),
        timeout=8.0
    )
    peer = Peer(conn)
    logger.info("Connected successfully! Discovering characteristics...")

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
        logger.info(f"COMPLETE FRAME ({len(full)}B): {full.hex()}")
        flag = full[0]
        logger.info(f"Notification security flag = {flag}")
        
        if flag == 0:
            # Plaintext frame
            raw = full[1:]
            sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
            data = raw[12 : 12 + length]
            logger.info(f"PLAINTEXT: cmd=0x{code:04X} len={length} data={data.hex()}")
            if code == 0: # DEV_INFO
                state["bound"] = (data[5] != 0)
                state["srand"] = data[6:12]
                logger.info(f"*** DEV_INFO: bound={state['bound']} srand={state['srand'].hex()} ***")
                dev_info_evt.set()
            elif code == 1: # PAIR_RESP
                logger.info(f"*** PAIR_RESP: result={data[0] if data else 'none'} ***")
                pair_evt.set()
        else:
            # Encrypted frame
            for k_cand in [hashlib.md5(LOCAL_KEY.encode()).digest(), LOCAL_KEY.encode()]:
                try:
                    raw = aes_dec(k_cand, full[1:17], full[17:])
                    sn, ack, code, length = struct.unpack(">IIHH", raw[:12])
                    data = raw[12 : 12 + length]
                    logger.info(f"DECRYPTED (flag {flag}): cmd=0x{code:04X} data={data.hex()}")
                    if code == 0:
                        state["bound"] = (data[5] != 0)
                        state["srand"] = data[6:12]
                        dev_info_evt.set()
                    elif code == 1:
                        pair_evt.set()
                except Exception:
                    pass

    await peer.subscribe(h17, on_notify)
    logger.info("Subscribed to Handle 17.")

    # 1. DEV_INFO with flag=0 (unencrypted) or flag=4
    logger.info("Sending DEV_INFO (cmd 0)...")
    for p in build_pkts(1, 0, bytes([0x00, 0x14]), flag=0, proto=4):
        await peer.write_value(h21, p, with_response=False)
        await asyncio.sleep(0.03)

    try:
        await asyncio.wait_for(dev_info_evt.wait(), timeout=3.0)
        logger.info("DEV_INFO ACK received!")
    except asyncio.TimeoutError:
        logger.warning("DEV_INFO unencrypted timeout, testing flag=4...")
        k16 = hashlib.md5(LOCAL_KEY.encode()).digest()
        for p in build_pkts(2, 0, bytes([0x00, 0x14]), key=k16, flag=4, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)
        try:
            await asyncio.wait_for(dev_info_evt.wait(), timeout=3.0)
            logger.info("DEV_INFO flag=4 ACK received!")
        except asyncio.TimeoutError:
            logger.warning("DEV_INFO timed out completely.")

    # 2. PAIR_REQ (cmd 1): 16B UUID + 6B key + 22B DEV_ID
    logger.info("Sending PAIR_REQ (cmd 1)...")
    pair_payload = bytearray(UUID.encode()) + LOCAL_KEY[:6].encode() + DEV_ID.encode()
    while len(pair_payload) < 44: pair_payload += b"\x00"

    # Send PAIR_REQ
    k_pair = hashlib.md5(LOCAL_KEY.encode()).digest()
    for p in build_pkts(3, 1, bytes(pair_payload), key=k_pair, flag=2, proto=4):
        await peer.write_value(h21, p, with_response=False)
        await asyncio.sleep(0.03)

    try:
        await asyncio.wait_for(pair_evt.wait(), timeout=3.0)
        logger.info("PAIR SUCCESS ACK RECEIVED!")
    except asyncio.TimeoutError:
        logger.warning("PAIR response timed out, attempting direct actuation...")

    # 3. ACTUATE MOTOR: DP 2 (Switch: True) & DP 101 (Click: True)
    logger.info("ACTUATING SERVO MOTOR (DP 2 & DP 101)...")
    k_act = hashlib.md5(LOCAL_KEY.encode() + (state["srand"] or b"\x00"*6)).digest()
    
    for dp_p in [
        bytes([2, 1, 1, 1]),   # Switch ON
        bytes([101, 1, 1, 1]), # Click Mode
    ]:
        for p in build_pkts(4, 2, dp_p, key=k_act, flag=5, proto=4):
            await peer.write_value(h21, p, with_response=False)
            await asyncio.sleep(0.03)

    logger.info("WAITING 4 SECONDS FOR PHYSICAL ARM MOVEMENT...")
    await asyncio.sleep(4.0)

    # Retract / Switch OFF
    for p in build_pkts(5, 2, bytes([2, 1, 1, 0]), key=k_act, flag=5, proto=4):
        await peer.write_value(h21, p, with_response=False)
        await asyncio.sleep(0.03)

    await asyncio.sleep(1.0)
    await conn.disconnect()
    logger.info("Finished session successfully!")

async def main():
    async with await open_transport("usb:0") as (src, dst):
        dev = Device.from_config_with_hci(None, src, dst)
        await dev.power_on()
        logger.info("Dongle powered on. Monitoring advertisements for reset...")

        reset_detected = False
        def on_adv(adv):
            nonlocal reset_detected
            addr = str(adv.address)
            if MAC in addr.upper():
                raw = bytes(adv.data).hex() if adv.data else ""
                # Check byte 11 in service data (0x50FD)
                # Bit 3 is 0x08 (bound_flag). When reset, bit 3 becomes 0!
                is_bound = True
                if "50fd" in raw:
                    idx = raw.find("50fd") + 4
                    if idx + 2 <= len(raw):
                        fc = int(raw[idx:idx+2], 16)
                        is_bound = bool(fc & 0x08)
                logger.info(f"Adv: RSSI={adv.rssi} BoundBit={is_bound} Raw={raw}")
                if not is_bound:
                    reset_detected = True

        dev.on("advertisement", on_adv)
        await dev.start_scanning()

        logger.info("Scanning for 60 seconds. PLEASE PRESS AND HOLD RESET BUTTON NOW...")
        for i in range(120):
            if reset_detected:
                logger.info("RESET DETECTED! Stopping scan and initiating pairing...")
                break
            await asyncio.sleep(0.5)

        await dev.stop_scanning()
        await attempt_pairing_and_actuation(dev)

if __name__ == "__main__":
    asyncio.run(main())
