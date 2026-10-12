# MUON, KAN-527 -- a Bambu Lab printer, driven over its LAN-mode services.
#
# Written from public protocol write-ups, not from anyone's client code:
#   OpenBambuAPI (Doridian/OpenBambuAPI, documentation under GFDL-1.3),
#   at commit cc383a2c96576a9f53391c879acfb8dca5c534e4:
#   * mqtt.md  -- MQTT on 8883, user "bblp", password = the LAN access code;
#                 topics device/{serial}/report and device/{serial}/request;
#                 pushing.pushall, print.stop/pause/resume, print.gcode_file,
#                 print.project_file and the push_status report fields.
#   * tls.md   -- every local service is TLS under the "BBL CA" roots; the
#                 certificate names the serial, so SNI = serial.
#   * ftp.md   -- implicit FTPS on 990, same user and access code; the data
#                 channel must resume the control channel's TLS session.
#   * video.md -- A1/P1 camera on 6000: an 80-byte auth packet, then frames
#                 of a 16-byte little-endian header and one JPEG.

from __future__ import annotations

import asyncio
import ftplib
import io
import json
import logging
import socket
import ssl
import struct
from typing import Any, Awaitable, Callable, Dict, Optional

from .muon_bridge_common import (
    BridgeError, Dialer, IPAddress, Secret, check_filename, direct
)
from .muon_bridge_mqtt import MqttClient

USER = "bblp"
MQTT_PORT = 8883
FTPS_PORT = 990
CAMERA_PORT = 6000
UPLOAD_EXTENSIONS = (".3mf", ".gcode")

#: The push_status fields a caller sees: the job, its progress and the
#: temperatures. Nothing that identifies the owner's account.
STATUS_FIELDS = (
    "gcode_state", "mc_percent", "mc_remaining_time", "layer_num",
    "total_layer_num", "subtask_name", "gcode_file", "print_error",
    "mc_print_error_code", "nozzle_temper", "nozzle_target_temper",
    "bed_temper", "bed_target_temper", "chamber_temper", "spd_lvl",
    "wifi_signal",
)

#: A serial is upper-case letters and digits (tls.md: it is the certificate's
#: common name). Anything else would not survive an MQTT topic or SNI.
_SERIAL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def check_serial(value: Any) -> str:
    if (
        not isinstance(value, str) or not 8 <= len(value) <= 32
        or not set(value) <= _SERIAL_CHARS
    ):
        raise BridgeError(
            "'serial' must be the printer's serial number (8-32 upper-case "
            "letters and digits)", 400)
    return value


def tls_context(ca_file: str) -> ssl.SSLContext:
    """Trust only Bambu's roots, and check the name against SNI (tls.md).
    The roots lack extensions that VERIFY_X509_STRICT (default on Python
    3.13) demands; that flag alone is relaxed. The chain and the name are
    still checked."""
    context = ssl.create_default_context(cafile=ca_file)
    context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _ImplicitFtps(ftplib.FTP_TLS):
    """Implicit FTPS (ftp.md): TLS from the first byte, SNI = serial, and the
    data channel resumes the control channel's session, which the printer
    requires."""

    def __init__(self, context: ssl.SSLContext, server_name: str) -> None:
        super().__init__(context=context, timeout=30.0)
        self.server_name = server_name

    def connect(self, host: str = "", port: int = 0,
                timeout: float = -999, source_address: Any = None) -> str:
        self.host, self.port = host, port
        raw = socket.create_connection((host, port), self.timeout)
        self.af = raw.family
        self.sock = self.context.wrap_socket(
            raw, server_hostname=self.server_name)
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome

    def ntransfercmd(self, cmd: str, rest: Any = None) -> Any:
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if getattr(self, "_prot_p", False):
            control = self.sock
            assert isinstance(control, ssl.SSLSocket)
            conn = self.context.wrap_socket(
                conn, server_hostname=self.server_name,
                session=control.session)
        return conn, size

    def makepasv(self) -> Any:
        # The control connection's peer, never the address in the reply
        # (the 227 answer could name any host).
        _, port = super().makepasv()
        return self.host, port


Notify = Callable[[Dict[str, Any]], None]
Closed = Callable[[str], Awaitable[None]]


class BambuPrinter:
    kind = "bambu"

    def __init__(self, ip: IPAddress, serial: str, access_code: Secret,
                 ca_file: str, notify: Notify, closed: Closed,
                 dialer: Dialer = direct) -> None:
        self.ip = ip
        self.serial = serial
        self.access_code = access_code
        self.ca_file = ca_file
        self.notify = notify
        self.closed = closed
        self.dialer = dialer
        self.report: Dict[str, Any] = {}
        self.sequence = 0
        self.mqtt: Optional[MqttClient] = None

    @property
    def report_topic(self) -> str:
        return f"device/{self.serial}/report"

    @property
    def request_topic(self) -> str:
        return f"device/{self.serial}/request"

    async def open(self) -> None:
        host, port = self.dialer(str(self.ip), MQTT_PORT)
        self.mqtt = MqttClient(self._on_message, self.closed)
        await self.mqtt.connect(host, port, tls_context(self.ca_file),
                                self.serial, USER, self.access_code)
        await self.mqtt.subscribe(self.report_topic)
        self._send("pushing", "pushall")

    def _on_message(self, topic: str, payload: bytes) -> None:
        if topic != self.report_topic:
            return
        try:
            message = json.loads(payload)
        except ValueError:
            return
        report = message.get("print") if isinstance(message, dict) else None
        if not isinstance(report, dict):
            return
        changed = {
            key: report[key] for key in STATUS_FIELDS
            if key in report and self.report.get(key) != report[key]
        }
        if report.get("result") == "fail" and report.get("command"):
            changed["last_error"] = {
                "command": str(report.get("command")),
                "reason": str(report.get("reason", ""))[:200],
            }
        if changed:
            self.report.update(changed)
            self.notify(changed)

    def status(self) -> Dict[str, Any]:
        return dict(self.report)

    def _send(self, group: str, command: str, **fields: Any) -> int:
        if self.mqtt is None:
            raise BridgeError("the printer is not connected", 503)
        self.sequence += 1
        body = {"sequence_id": str(self.sequence), "command": command}
        body.update(fields)
        self.mqtt.publish(
            self.request_topic, json.dumps({group: body}).encode())
        return self.sequence

    def pause(self) -> int:
        return self._send("print", "pause", param="")

    def resume(self) -> int:
        return self._send("print", "resume", param="")

    def stop(self) -> int:
        return self._send("print", "stop", param="")

    def start(self, filename: Any, options: Dict[str, Any]) -> int:
        check_filename(filename, UPLOAD_EXTENSIONS)
        if filename.lower().endswith(".gcode"):
            return self._send("print", "gcode_file", param=filename)
        plate = options.get("plate", 1)
        if not isinstance(plate, int) or not 1 <= plate <= 64:
            raise BridgeError("'plate' must be a plate number, 1-64", 400)
        flags = {
            name: bool(options.get(name, default)) for name, default in (
                ("timelapse", False), ("bed_levelling", True),
                ("flow_cali", False), ("vibration_cali", False),
                ("layer_inspect", False), ("use_ams", False),
            )
        }
        return self._send(
            "print", "project_file",
            param=f"Metadata/plate_{plate}.gcode",
            project_id="0", profile_id="0", task_id="0", subtask_id="0",
            subtask_name=filename.rsplit(".", 1)[0], file="",
            url=f"ftp:///{filename}", md5="", bed_type="auto",
            ams_mapping="", **flags)

    def _upload_blocking(self, filename: Any, data: bytes) -> None:
        host, port = self.dialer(str(self.ip), FTPS_PORT)
        ftp = _ImplicitFtps(tls_context(self.ca_file), self.serial)
        try:
            ftp.connect(host, port)
            ftp.login(USER, self.access_code.reveal_str())
            ftp.prot_p()
            ftp.storbinary(f"STOR {filename}", io.BytesIO(data))
        finally:
            try:
                ftp.quit()
            except Exception:
                ftp.close()

    async def upload(self, filename: Any, data: bytes) -> None:
        check_filename(filename, UPLOAD_EXTENSIONS)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, self._upload_blocking, filename, data)
        except ssl.SSLCertVerificationError as exc:
            raise BridgeError(
                "the printer's FTPS certificate did not verify against "
                f"Bambu Lab's CA: {exc.verify_message}", 502) from None
        except ftplib.error_perm as exc:
            code = str(exc)[:3]
            raise BridgeError(
                f"the printer refused the upload (FTP {code})",
                401 if code == "530" else 502) from None
        except (OSError, ftplib.Error, EOFError) as exc:
            raise BridgeError(
                f"the upload failed: {type(exc).__name__}", 502) from None

    async def snapshot(self, timeout: float = 10.0) -> bytes:
        """One JPEG from the A1/P1 camera (video.md); X1 printers have no
        port 6000 and answer 404 here."""
        host, port = self.dialer(str(self.ip), CAMERA_PORT)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                host, port, ssl=tls_context(self.ca_file),
                server_hostname=self.serial), timeout)
        except ssl.SSLCertVerificationError as exc:
            raise BridgeError(
                "the printer's camera certificate did not verify against "
                f"Bambu Lab's CA: {exc.verify_message}", 502) from None
        except (OSError, asyncio.TimeoutError):
            raise BridgeError("this printer has no camera stream on port "
                              f"{CAMERA_PORT}", 404) from None
        auth = bytearray(struct.pack("<IIII", 0x40, 0x3000, 0, 0))
        auth += USER.encode().ljust(32, b"\0")
        auth += self.access_code.reveal().ljust(32, b"\0")[:32]
        try:
            writer.write(bytes(auth))
            for index in range(len(auth)):
                auth[index] = 0
            header = await asyncio.wait_for(reader.readexactly(16), timeout)
            (size,) = struct.unpack_from("<I", header)
            if not 4 <= size <= 4 << 20:
                raise BridgeError("the camera sent a malformed frame", 502)
            frame = await asyncio.wait_for(reader.readexactly(size), timeout)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            raise BridgeError("the camera closed before sending a frame",
                              502) from None
        finally:
            writer.close()
        if frame[:2] != b"\xff\xd8" or frame[-2:] != b"\xff\xd9":
            raise BridgeError("the camera sent something that is not a JPEG",
                              502)
        return frame

    async def close(self) -> None:
        if self.mqtt is not None:
            mqtt, self.mqtt = self.mqtt, None
            try:
                await mqtt.close()
            except Exception:
                logging.exception("muon_bridge: closing MQTT")
        self.access_code.wipe()
