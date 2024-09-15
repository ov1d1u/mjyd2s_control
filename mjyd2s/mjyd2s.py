import asyncio
import secrets
import hashlib
import hmac
import logging
from Crypto.Cipher import AES
from bleak import BleakClient

from .mjyd2sconfiguration import MJYD2SConfiguration

LOGGER = logging.getLogger(__name__)

CHAR_10_UUID = "00000010-0000-1000-8000-00805f9b34fb"
CHAR_19_UUID = "00000019-0000-1000-8000-00805f9b34fb"

CHAR_TX_UUID = "00000101-0065-6C62-2E74-6F696D2E696D"
CHAR_RX_UUID = "00000102-0065-6C62-2E74-6F696D2E696D"

REPLY_TIMEOUT = 5.0


class MJYD2S:
    mi_token = None
    mi_random_key = secrets.token_bytes(16)
    mi_random_key_recv = None
    derived_key = None
    configuration = None

    _queue_in = asyncio.Queue()
    _msg_count = 0
    
    def __init__(self, device, mi_token):
        self.device = device
        self.mi_token = mi_token
    
    async def _notification_handler(self, sender, data):
        LOGGER.debug(f"<< {data.hex()}")
        self._queue_in.put_nowait(data)
    
    async def connect(self) -> bool:
        self.client = BleakClient(self.device)
        await self.client.connect()
        return await self.authenticate()
    
    async def authenticate(self) -> bool:
        if not self.client.is_connected:
            return False
        
        await self.client.start_notify(CHAR_19_UUID, self._notification_handler)
        await self.client.start_notify(CHAR_10_UUID, self._notification_handler)
        
        if not self.client.is_connected:
            return False

        await self._write(CHAR_10_UUID, bytes.fromhex("a4"))
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("0000040006f2"):
            raise Exception(f"Invalid response received. received {response.hex()}")
        
        await self._write(CHAR_19_UUID, bytes.fromhex("0000050006f2"))
        mtu_response = await self._get_response(decrypt=False)
        mtu_response[2] = mtu_response[2] + 1
        await self._write(CHAR_19_UUID, mtu_response)
        
        # For some reason we have to wait a bit here,
        # otherwise the device will no longer respond
        await asyncio.sleep(1)
        
        await self._write(CHAR_10_UUID, bytes.fromhex("24000000"))
        await self._write(CHAR_19_UUID, bytes.fromhex("0000000b0100"))
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("00000101"):
            if response != bytes.fromhex("e2000000"):
                raise Exception("Could not connect. Make sure another device is not already connected.")
            else:
                raise Exception(f"Invalid response received. received {response.hex()}")
            
        await self._write(CHAR_19_UUID, bytes.fromhex("0100") + self.mi_random_key)
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("00000100"):
            raise Exception(f"Invalid response received. received {response.hex()}")
        
        key_msg = await self._get_response(decrypt=False)
        self.mi_random_key_recv = key_msg[4:]
        
        self.derived_key = self._hkdf(
            bytes.fromhex(self.mi_token),
            64,
            self.mi_random_key + self.mi_random_key_recv,
            b"mible-login-info"
        )
        
        await self._write(CHAR_19_UUID, bytes.fromhex("00000300"))
        response = await self._get_response(decrypt=False)
        mi_device_info_recv = response[4:]
        
        expected_mi_device_info = hmac.new(
            self.derived_key[0:16],
            self.mi_random_key_recv + self.mi_random_key,
            hashlib.sha256
        ).digest()
        
        if mi_device_info_recv != expected_mi_device_info:
            raise Exception(f"Fatal error: device info mismatch. Received {mi_device_info_recv.hex()}, expected {expected_mi_device_info.hex()}")
        
        await self._write(CHAR_19_UUID, bytes.fromhex("00000300"))
        await self._write(CHAR_19_UUID, bytes.fromhex("0000000a0100"))
        
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("00000101"):
            raise Exception(f"Invalid response received. received {response.hex()}")
        
        mi_device_info_send = hmac.new(
            self.derived_key[16:32],
            self.mi_random_key + self.mi_random_key_recv,
            hashlib.sha256
        ).digest()
        await self._write(CHAR_19_UUID, bytes.fromhex("0100") + mi_device_info_send)
        
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("00000100"):
            raise Exception(f"Invalid response received. received {response.hex()}")
            
        response = await self._get_response(decrypt=False)
        if response != bytes.fromhex("21000000"):
            raise Exception(f"Invalid response received. received {response.hex()}")
            
        await self.client.stop_notify(CHAR_19_UUID)
        await self.client.stop_notify(CHAR_10_UUID)
        await self.client.start_notify(CHAR_RX_UUID, self._notification_handler)
        
        await self.get_configuration()
        
        return True
    
    async def get_configuration(self) -> MJYD2SConfiguration | None:
        self._ensure_connected()
        
        response = await self._send_message(bytes.fromhex("06010102030408"))
        self.configuration = MJYD2SConfiguration(response)
        return self.configuration
    
    async def turn_on(self, refresh_configuration: bool = True):
        self._ensure_connected()
        
        await self._send_message(bytes.fromhex("03020301"), wait_for_reply=True)
        if refresh_configuration:
            await self.get_configuration()
    
    async def turn_off(self, refresh_configuration: bool = True):
        self._ensure_connected()
        
        await self._send_message(bytes.fromhex("03020300"), wait_for_reply=True)
        if refresh_configuration:
            await self.get_configuration()
    
    async def set_brightness(self, brightness: int, refresh_configuration: bool = True):
        self._ensure_connected()
        
        await self._send_message(bytes.fromhex(f"030202{brightness:02x}"), wait_for_reply=True)
        if refresh_configuration:
            await self.get_configuration()
            
    async def set_duration(self, timeout: int, refresh_configuration: bool = True):
        self._ensure_connected()
        
        await self._send_message(bytes.fromhex(f"030204{timeout:02x}"), wait_for_reply=False)
        if refresh_configuration:
            await self.get_configuration()
            
    async def set_ambient(self, limit: int, refresh_configuration: bool = True):
        self._ensure_connected()
        
        await self._send_message(bytes.fromhex(f"030208{limit:02x}"), wait_for_reply=False)
        if refresh_configuration:
            await self.get_configuration()
    
    @property
    def is_authenticated(self):
        return self.mi_token is not None and \
            self.derived_key is not None and \
            self.mi_random_key_recv is not None and \
            self.mi_random_key is not None
    
    def _ensure_connected(self):
        if not self.client.is_connected:
            raise Exception("Not connected")
        
        if not self.is_authenticated:
            raise Exception("Not authenticated")
            
    async def _send_message(self, msg, wait_for_reply=True):
        hex_msg_count = self._msg_count.to_bytes(2, byteorder='little').hex()
        msg_bytes = bytes.fromhex(hex_msg_count) + self._encrypt_message(msg)
        self._msg_count += 1
        await self._write(CHAR_TX_UUID, msg_bytes)

        if not wait_for_reply:
            return

        return await self._get_response(expected_msg_count=self._msg_count)

    async def _wait_response(self, expected_msg_count):
        if expected_msg_count is not None:
            while True:
                in_msg = await self._queue_in.get()
                in_msg_count = int.from_bytes(in_msg[0:2], byteorder='little')

                if in_msg_count == expected_msg_count:
                    return in_msg
        else:
            return await self._queue_in.get()
        
    async def _get_response(self, expected_msg_count: int|None = None, decrypt: bool = True) -> bytes | None:
        try:
            response = await asyncio.wait_for(self._wait_response(expected_msg_count), timeout=REPLY_TIMEOUT)

            if decrypt:
                return self._decrypt_message(response)
            else:
                return response
        except asyncio.TimeoutError:
            return None
                    
    async def _write(self, charac, data):
        LOGGER.debug(f">> {data.hex()}")
        return await self.client.write_gatt_char(charac, data)
        
    def _hkdf_extract(self, salt, input_key, hash_func):
        return hmac.new(salt, input_key, hash_func).digest()

    def _hkdf_expand(self, prk, info, length, hash_func):
        block = b""
        output = b""
        counter = 1
        while len(output) < length:
            block = hmac.new(prk, block + info + bytes([counter]), hash_func).digest()
            output += block
            counter += 1
        return output[:length]

    def _hkdf(self, input_key, length, salt, info, hash_func=hashlib.sha256):
        prk = self._hkdf_extract(salt, input_key, hash_func)
        return self._hkdf_expand(prk, info, length, hash_func)

    def _encrypt_message(self, msg):
        LOGGER.debug(f"xx {msg.hex()}")
        nonce = self._compute_enc_nonce()
        cipher = AES.new(
            self.derived_key[16:32],
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=4
        )
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return ciphertext + tag
    
    def _decrypt_message(self, msg):
        nonce = self._compute_dec_nonce()
        cipher = AES.new(
            self.derived_key[0:16],
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=4
        )
        chipertext = msg[2:len(msg) - 4]
        tag = msg[len(msg) - 4:]
        return cipher.decrypt_and_verify(chipertext, tag)
        
    def _compute_enc_nonce(self):
        nonce = 12 * [0]
        nonce[:4] = self.derived_key[36:40]
        nonce[8: 10] = self._msg_count.to_bytes(2, byteorder='little')
        nonce[10:12] = [0, 0]
        return bytes(nonce)
    
    def _compute_dec_nonce(self):
        nonce = 12 * [0]
        nonce[:4] = self.derived_key[32:36]
        nonce[8:10] = self._msg_count.to_bytes(2, byteorder='little')
        nonce[10:12] = [0, 0]
        return bytes(nonce)
