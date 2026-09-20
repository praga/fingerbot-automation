"""
Tuya BLE Protocol v4 Codec & Packet Builder
Implements the official Tuya BLE application-layer cryptographic protocol
for Tuya BLE v4 devices including Fingerbot / Fingerbot Plus.
"""
import hashlib
import logging
import secrets
import struct
from typing import Optional, List, Tuple, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("fingerbot.tuya_protocol")

# Tuya BLE OpCodes
CMD_DEV_INFO = 0x0000       # FUN_SENDER_DEVICE_INFO
CMD_PAIR = 0x0001           # FUN_SENDER_PAIR
CMD_DP_CONTROL_V2 = 0x0002  # Legacy DP Control
CMD_DEV_STATUS = 0x0003     # Device status
CMD_DP_CONTROL_V4 = 0x0027  # FRM_DP_DATA_WRITE_REQ (Protocol v4)
CMD_STATUS_REPORT_1 = 0x8001
CMD_STATUS_REPORT_6 = 0x8006
CMD_STATUS_REPORT_11 = 0x8011


def calc_crc16(data: bytes) -> int:
    """CRC16-Modbus (polynomial 0xA001, initial 0xFFFF)"""
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


def unpack_int(data: bytes, start_pos: int = 0) -> Tuple[int, int]:
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


class PacketReassembler:
    """
    Reassembles incoming GATT MTU fragment packets into a single complete Tuya BLE payload.
    """
    def __init__(self):
        self.buffer = bytearray()
        self.expected_length = 0
        self.expected_packet_num = 0

    def feed(self, chunk: bytes) -> Optional[bytearray]:
        if not chunk:
            return None
        try:
            packet_num, pos = unpack_int(chunk, 0)
            if packet_num == 0:
                self.buffer = bytearray()
                self.expected_packet_num = 0
                self.expected_length, pos = unpack_int(chunk, pos)
                pos += 1  # Skip protocol version byte (0x40)

            if packet_num != self.expected_packet_num:
                logger.warning(f"Unexpected packet seq {packet_num}, expected {self.expected_packet_num}")
                self.buffer = bytearray()
                self.expected_packet_num = 0
                return None

            self.buffer += chunk[pos:]
            self.expected_packet_num += 1

            if len(self.buffer) >= self.expected_length:
                completed = bytearray(self.buffer[:self.expected_length])
                self.buffer = bytearray()
                self.expected_packet_num = 0
                self.expected_length = 0
                return completed
        except Exception as e:
            logger.warning(f"Error reassembling Tuya BLE packet: {e}")
            self.buffer = bytearray()
            self.expected_packet_num = 0
        return None


class TuyaBleCodec:
    """
    Encoder and decoder for Tuya BLE v4 framed and encrypted packets.
    Uses MD5(local_key[:6]) for login key and MD5(local_key[:6] + srand) for session key.
    """
    def __init__(self, local_key: str, protocol_version: int = 4):
        self.local_key_str = (local_key or "").strip()
        # Official Tuya BLE v4 uses the first 6 characters as the prefix
        self.local_prefix_bytes = self.local_key_str[:6].encode("utf-8")
        self.login_key = hashlib.md5(self.local_prefix_bytes).digest()
        self.session_key: Optional[bytes] = None
        self.protocol_version = protocol_version
        self.current_seq = 1
        self.is_bound = False

    def set_session_key_from_srand(self, srand: bytes):
        """
        Derive session key: MD5(local_key[:6] + srand)
        """
        self.session_key = hashlib.md5(self.local_prefix_bytes + srand).digest()
        logger.info(f"Derived Tuya BLE v4 session key from srand: {self.session_key.hex()}")

    def build_packet(
        self,
        code: int,
        data: bytes,
        is_login: bool = False,
        response_to: int = 0,
        mtu: int = 20
    ) -> List[bytes]:
        """
        Builds encrypted and fragmented GATT MTU packets.
        """
        key = self.login_key if is_login or self.session_key is None else self.session_key
        security_flag = 4 if is_login or self.session_key is None else 5

        raw = bytearray(struct.pack(">IIHH", self.current_seq, response_to, code, len(data)) + data)
        crc = calc_crc16(bytes(raw))
        raw += struct.pack(">H", crc)
        while len(raw) % 16 != 0:
            raw += b"\x00"

        iv = secrets.token_bytes(16)
        encrypted = bytes([security_flag]) + iv + aes_cbc_encrypt(key, iv, bytes(raw))

        chunks = []
        packet_num = 0
        pos = 0
        length = len(encrypted)
        while pos < length:
            pkt = bytearray(pack_int(packet_num))
            if packet_num == 0:
                pkt += pack_int(length) + struct.pack(">B", self.protocol_version << 4)
            part = encrypted[pos : pos + mtu - len(pkt)]
            pkt += part
            chunks.append(bytes(pkt))
            pos += len(part)
            packet_num += 1

        self.current_seq += 1
        return chunks

    def build_device_info_request(self) -> List[bytes]:
        """Tuya BLE Code 0x0000: Device Info request (MTU 20, flag 4)"""
        return self.build_packet(code=CMD_DEV_INFO, data=bytes([0x00, 0x14]), is_login=True)

    def build_pair_request(self, uuid: str = "", device_id: str = "") -> List[bytes]:
        """Tuya BLE Code 0x0001: Pair request (44 bytes payload, flag 5)"""
        data = bytearray()
        data += uuid.encode("utf-8")
        data += self.local_prefix_bytes
        data += device_id.encode("utf-8").ljust(22, b"\x00")
        while len(data) < 44:
            data += b"\x00"
        return self.build_packet(code=CMD_PAIR, data=bytes(data[:44]), is_login=False)

    def build_dp1_command(self, value: bool = True, sn: int = 1) -> List[bytes]:
        """
        DP 1: Fingerbot physical motor switch / trigger using Protocol v4 opcode 0x0027.
        Payload: [0x00] [SN: 4B] [DP_ID: 1B] [DP_TYPE: 1B] [LEN: 2B] [VALUE: 1B]
        """
        dp_payload = bytes([0x00]) + struct.pack(">IBBHB", sn, 1, 1, 1, 1 if value else 0)
        return self.build_packet(code=CMD_DP_CONTROL_V4, data=dp_payload, is_login=False)

    def build_dp2_command(self, value: bool = True, sn: int = 1) -> List[bytes]:
        """
        DP 2: Fingerbot mode setting (0 = Click, 1 = Switch).
        """
        dp_payload = bytes([0x00]) + struct.pack(">IBBHB", sn, 2, 4, 1, 1 if value else 0)
        return self.build_packet(code=CMD_DP_CONTROL_V4, data=dp_payload, is_login=False)

    def build_dp5_stroke(self, stroke_percent: int = 100, sn: int = 1) -> List[bytes]:
        """
        DP 5: Fingerbot arm travel percentage (0-100%).
        """
        dp_payload = bytes([0x00]) + struct.pack(">IBBHI", sn, 5, 2, 4, stroke_percent)
        return self.build_packet(code=CMD_DP_CONTROL_V4, data=dp_payload, is_login=False)

    def build_dp101_click(self, sn: int = 2) -> List[bytes]:
        """
        DP 101: Legacy click trigger (not present on all models).
        """
        dp_payload = bytes([0x00]) + struct.pack(">IBBHB", sn, 101, 1, 1, 1)
        return self.build_packet(code=CMD_DP_CONTROL_V4, data=dp_payload, is_login=False)

    def parse_notification(self, raw_buffer: bytearray) -> Optional[Tuple[int, int, bytes]]:
        """
        Parses an assembled notification packet.
        Returns (code, ack, data) or None if decryption fails.
        """
        if len(raw_buffer) < 17:
            return None
        security_flag = raw_buffer[0]
        iv = bytes(raw_buffer[1:17])
        encrypted = bytes(raw_buffer[17:])
        if len(encrypted) % 16 != 0:
            return None

        # Determine key candidates based on flag
        keys_to_try = []
        if security_flag == 4:
            keys_to_try.append(("login_key", self.login_key))
        elif security_flag == 5 and self.session_key:
            keys_to_try.append(("session_key", self.session_key))
        else:
            if self.session_key:
                keys_to_try.append(("session_key", self.session_key))
            keys_to_try.append(("login_key", self.login_key))

        for name, key in keys_to_try:
            try:
                decrypted = aes_cbc_decrypt(key, iv, encrypted)
                if len(decrypted) < 12:
                    continue
                seq, resp_to, code, length = struct.unpack(">IIHH", decrypted[:12])
                data_end = 12 + length
                if len(decrypted) < data_end:
                    continue
                data = decrypted[12:data_end]
                return code, resp_to, data
            except Exception:
                continue

        return None
