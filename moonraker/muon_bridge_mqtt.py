# MUON, KAN-527 -- the smallest MQTT 3.1.1 client muon_bridge needs, on the
# standard library: CONNECT with a user name and password, one SUBSCRIBE,
# PUBLISH at QoS 0 or 1, keepalive. Written from the OASIS MQTT 3.1.1
# specification (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/), not from
# any client library. The TLS context comes from the caller.

from __future__ import annotations

import asyncio
import os
import ssl
import struct
from typing import Awaitable, Callable, Optional, Tuple

from .muon_bridge_common import BridgeError, Secret

CONNECT, CONNACK, PUBLISH, PUBACK = 1, 2, 3, 4
SUBSCRIBE, SUBACK, PINGREQ, PINGRESP, DISCONNECT = 8, 9, 12, 13, 14

#: Bambu's full status report runs to tens of kilobytes; anything far beyond
#: that is not a printer talking.
MAX_PACKET = 1 << 20

CONNACK_REASONS = {
    1: "the printer refused the MQTT protocol version",
    2: "the printer refused the client id",
    3: "the printer's MQTT server is unavailable",
    4: "the printer refused the access code",
    5: "the printer refused the access code",
}


def _string(value: bytes) -> bytes:
    return struct.pack("!H", len(value)) + value


def _remaining_length(length: int) -> bytes:
    out = bytearray()
    while True:
        byte, length = length % 128, length // 128
        out.append(byte | (0x80 if length else 0))
        if not length:
            return bytes(out)


def packet(kind: int, flags: int, body: bytes) -> bytes:
    return bytes([(kind << 4) | flags]) + _remaining_length(len(body)) + body


def connect_packet(client_id: str, username: str, password: Secret,
                   keepalive: int) -> bytearray:
    """CONNECT, as a bytearray the caller overwrites once it is written."""
    body = bytearray(_string(b"MQTT"))
    body += bytes([4, 0xC2])            # 3.1.1; user name, password, clean
    body += struct.pack("!H", keepalive)
    body += _string(client_id.encode())
    body += _string(username.encode())
    secret = password.reveal()
    body += struct.pack("!H", len(secret)) + secret
    head = bytes([CONNECT << 4]) + _remaining_length(len(body))
    out = bytearray(head) + body
    for index in range(len(body)):
        body[index] = 0
    return out


async def read_packet(reader: asyncio.StreamReader) -> Tuple[int, int, bytes]:
    first = (await reader.readexactly(1))[0]
    length, shift = 0, 0
    for _ in range(4):
        byte = (await reader.readexactly(1))[0]
        length |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    else:
        raise BridgeError("the printer sent a malformed MQTT packet", 502)
    if length > MAX_PACKET:
        raise BridgeError("the printer sent an oversized MQTT packet", 502)
    body = await reader.readexactly(length) if length else b""
    return first >> 4, first & 0x0F, body


MessageHandler = Callable[[str, bytes], None]


class MqttClient:
    def __init__(self, on_message: MessageHandler,
                 on_close: Callable[[str], Awaitable[None]],
                 keepalive: int = 30) -> None:
        self.on_message = on_message
        self.on_close = on_close
        self.keepalive = keepalive
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._ids = 0
        self._tasks: list = []
        self._closing = False

    def _next_id(self) -> int:
        self._ids = self._ids % 0xFFFF + 1
        return self._ids

    async def connect(self, host: str, port: int, context: ssl.SSLContext,
                      server_name: str, username: str, password: Secret,
                      timeout: float = 10.0) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=context, server_hostname=server_name),
                timeout)
        except ssl.SSLCertVerificationError as exc:
            raise BridgeError(
                "the printer's certificate did not verify against Bambu "
                f"Lab's CA for serial {server_name}: {exc.verify_message}",
                502) from None
        except (OSError, asyncio.TimeoutError) as exc:
            raise BridgeError(
                f"cannot reach the printer's MQTT server: {type(exc).__name__}",
                504) from None
        self.reader, self.writer = reader, writer
        hello = connect_packet(
            "muon-bridge-" + os.urandom(4).hex(), username, password,
            self.keepalive * 2)
        try:
            writer.write(bytes(hello))
        finally:
            for index in range(len(hello)):
                hello[index] = 0
        try:
            kind, _, body = await asyncio.wait_for(
                read_packet(reader), timeout)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            await self._abort()
            raise BridgeError("the printer closed MQTT before answering", 502) \
                from None
        if kind != CONNACK or len(body) != 2 or body[1] != 0:
            await self._abort()
            code = body[1] if kind == CONNACK and len(body) == 2 else -1
            raise BridgeError(
                CONNACK_REASONS.get(code, "the printer refused MQTT"),
                403 if code in (4, 5) else 502)

    async def subscribe(self, topic: str, timeout: float = 10.0) -> None:
        assert self.writer is not None and self.reader is not None
        packet_id = self._next_id()
        body = struct.pack("!H", packet_id) + _string(topic.encode()) + b"\x00"
        self.writer.write(packet(SUBSCRIBE, 2, body))
        while True:
            kind, _, body = await asyncio.wait_for(
                read_packet(self.reader), timeout)
            if kind == SUBACK:
                if len(body) < 3 or body[2] == 0x80:
                    raise BridgeError("the printer refused the subscription",
                                      502)
                break
            if kind == PUBLISH:
                self._handle_publish(0, body)
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._read_loop()),
                       loop.create_task(self._ping_loop())]

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> None:
        if self.writer is None or self.writer.is_closing():
            raise BridgeError("the printer is not connected", 503)
        body = _string(topic.encode())
        if qos:
            body += struct.pack("!H", self._next_id())
        self.writer.write(packet(PUBLISH, qos << 1, body + payload))

    def _handle_publish(self, flags: int, body: bytes) -> None:
        (size,) = struct.unpack_from("!H", body)
        topic = body[2:2 + size].decode("utf-8", "replace")
        offset = 2 + size
        qos = (flags >> 1) & 3
        if qos:
            packet_id = body[offset:offset + 2]
            offset += 2
            if self.writer is not None:
                self.writer.write(packet(PUBACK, 0, packet_id))
        self.on_message(topic, body[offset:])

    async def _read_loop(self) -> None:
        assert self.reader is not None
        reason = "the printer closed the connection"
        try:
            while True:
                kind, flags, body = await read_packet(self.reader)
                if kind == PUBLISH:
                    self._handle_publish(flags, body)
        except asyncio.CancelledError:
            return
        except BridgeError as exc:
            reason = str(exc)
        except (OSError, asyncio.IncompleteReadError, ValueError,
                struct.error):
            pass
        if not self._closing:
            await self.on_close(reason)

    async def _ping_loop(self) -> None:
        try:
            while self.writer is not None and not self.writer.is_closing():
                await asyncio.sleep(self.keepalive)
                self.writer.write(packet(PINGREQ, 0, b""))
        except (asyncio.CancelledError, OSError):
            return

    async def _abort(self) -> None:
        if self.writer is not None:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 2.0)
            except Exception:
                pass

    async def close(self) -> None:
        self._closing = True
        current = asyncio.current_task()
        for task in self._tasks:
            if task is not current:
                task.cancel()
        if self.writer is not None and not self.writer.is_closing():
            try:
                self.writer.write(packet(DISCONNECT, 0, b""))
            except Exception:
                pass
        await self._abort()
        self.writer = None
        self.reader = None
