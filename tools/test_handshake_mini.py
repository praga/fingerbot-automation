import asyncio, hashlib, secrets, time
from struct import pack, unpack
from Crypto.Cipher import AES
from bumble.transport import open_transport
from bumble.device import Device, Peer
import bumble.hci as hci

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

def crc16(d):
    c = 0xFFFF
    for b in d:
        c ^= b
        for _ in range(8): c = (c >> 1) ^ 0xA001 if (c & 1) else (c >> 1)
    return c

def make_frags(cmd, data, sn, key, flag, proto=2):
    raw = pack(">IIHH", sn, 0, cmd, len(data)) + data
    raw += pack(">H", crc16(raw))
    pad = (-len(raw)) % 16
    raw += bytes([pad]) * pad
    iv = secrets.token_bytes(16)
    enc = bytes([flag]) + iv + AES.new(key, AES.MODE_CBC, iv).encrypt(raw)
    frags, b, nr = [], bytearray([0, len(enc), proto << 4]), 0
    for d in enc:
        if len(b) == 20:
            frags.append(bytes(b))
            nr += 1
            b = bytearray([nr])
        b += bytes([d])
    if len(b) > 1: frags.append(bytes(b))
    return frags

def decrypt(raw_enc, key):
    try:
        iv, ct = raw_enc[1:17], raw_enc[17:]
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        sn, ack, code, l = unpack(">IIHH", dec[:12])
        return raw_enc[0], code, dec[12:12+l]
    except Exception as e:
        return None

async def send(peer, ch, cmd, data, sn, key, flag, proto=2):
    frags = make_frags(cmd, data, sn, key, flag, proto)
    for f in frags:
        await peer.write_value(ch, f, with_response=False)
        await asyncio.sleep(0.02)

async def main():
    k_login_6 = hashlib.md5(LOCAL_KEY[:6].encode()).digest()
    k_login_16 = hashlib.md5(LOCAL_KEY.encode()).digest()

    for k_name, k_login, pfx in [("key_6", k_login_6, LOCAL_KEY[:6].encode()), ("key_16", k_login_16, LOCAL_KEY.encode())]:
        print(f"\n>>> TESTING {k_name}: {k_login.hex()}")
        async with await open_transport("usb:0") as (s_in, s_out):
            dev = Device.from_config_with_hci(None, s_in, s_out)
            await dev.power_on()
            conn = await asyncio.wait_for(dev.connect(hci.Address(MAC, hci.Address.PUBLIC_DEVICE_ADDRESS)), 8.0)
            print(f"Connected to {MAC}!")
            peer = Peer(conn)
            conn.on("disconnection", lambda r: print(f"*** DISC: {r} ***"))

            svcs = await peer.discover_services()
            ch21 = [c for s in svcs for c in await s.discover_characteristics() if c.handle == 21][0]
            ch17 = [c for s in svcs for c in await s.discover_characteristics() if c.handle == 17][0]

            rx_buf, exp_len, exp_nr = bytearray(), 0, 0
            info_evt = asyncio.Event()
            state = {"srand": None, "proto": 2, "s_key": None}

            def on_notify(val):
                nonlocal rx_buf, exp_len, exp_nr
                nr = val[0]
                pos = 1
                if nr == 0:
                    rx_buf = bytearray()
                    exp_len = val[1]
                    pos = 3
                    exp_nr = 0
                if nr == exp_nr:
                    rx_buf += val[pos:]
                    exp_nr += 1
                    if len(rx_buf) >= exp_len:
                        pkt = bytes(rx_buf[:exp_len])
                        k = state["s_key"] if pkt[0] == 5 else k_login
                        res = decrypt(pkt, k)
                        print(f"[NOTIFY] len={len(pkt)} parsed={res}")
                        if res and res[1] == 0 and len(res[2]) >= 12:
                            state["proto"] = res[2][2]
                            state["srand"] = res[2][6:12]
                            info_evt.set()

            await peer.subscribe(ch17, on_notify)
            print("Subscribed to handle 17. Sending FUN_SENDER_DEVICE_INFO (cmd=0)...")
            await send(peer, ch21, 0, b"", 1, k_login, 4)

            try:
                await asyncio.wait_for(info_evt.wait(), timeout=3.5)
                print(f"--> GOT SRAND: {state['srand'].hex()} proto={state['proto']}")
                s_key = hashlib.md5(pfx + state["srand"]).digest()
                state["s_key"] = s_key
                print(f"--> DERIVED SESSION KEY: {s_key.hex()}")

                # Send PAIR (cmd=1)
                pair_d = UUID.encode() + LOCAL_KEY[:6].encode() + DEV_ID.encode()
                pair_d += b"\x00" * (44 - len(pair_d))
                print("Sending FUN_SENDER_PAIR (cmd=1)...")
                await send(peer, ch21, 1, pair_d, 2, s_key, 5, state["proto"])
                await asyncio.sleep(0.5)

                # Send DP 2 Switch True
                print("Sending DP 2 Switch True (cmd=2)...")
                await send(peer, ch21, 2, bytes([2, 1, 1, 1]), 3, s_key, 5, state["proto"])
                await asyncio.sleep(0.5)

                # Send Multi-DP Click
                multi = pack(">BBB", 8, 4, 1) + bytes([0]) + pack(">BBB", 9, 2, 4) + pack(">I", 100) + pack(">BBB", 15, 2, 4) + pack(">I", 0) + pack(">BBB", 10, 2, 4) + pack(">I", 0) + pack(">BBB", 101, 1, 1) + bytes([1])
                print("Sending Multi-DP Click (cmd=2)...")
                await send(peer, ch21, 2, multi, 4, s_key, 5, state["proto"])

                print("*** HOLDING FOR 5 SECONDS TO OBSERVE MOVEMENT ***")
                await asyncio.sleep(5.0)
                await conn.disconnect()
                print("Test finished successfully!")
                return
            except asyncio.TimeoutError:
                print(f"Timeout waiting for response to cmd 0 with {k_name}")

            await conn.disconnect()
            await asyncio.sleep(1.0)

if __name__ == "__main__":
    asyncio.run(main())
