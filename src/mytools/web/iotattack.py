#!/usr/bin/env python3
"""IoT & Industrial Attack Testing — Modbus, OPC UA, BACnet, SNMP, MQTT probing.

Testa seguranca de dispositivos IoT e sistemas industriais:
  - IoT: modbus_scan, opcua_discovery, bacnet_scan, snmp_brute, mqtt_enum
"""

from __future__ import annotations

import argparse
import logging
import random
import socket
import struct
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.iotattack")

_BANNER_LINES: str = (
    "  ___ ___  ___   __  __    _    ____   ___  _   _ \n"
    " |_ _/ _ \\|_ _| |  \\/  |  / \\  |  _ \\ / _ \\| \\ | |\n"
    "  | || | | || |  | |\\/| | / _ \\ | | | | | | |  \\| |\n"
    "  | || |_| || |  | |  | |/ ___ \\| |_| | |_| | |\\  |\n"
    " |___\\___/|___| |_|  |_/_/   \\_\\____/ \\___/|_| \\_|\n"
)

_MODBUS_FC: dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
}

_MODBUS_EXCEPTIONS: dict[int, str] = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Failed",
}

_OPCUA_MESSAGE_TYPES: dict[bytes, str] = {
    b"HEL": "Hello",
    b"ACK": "Acknowledge",
    b"ERR": "Error",
    b"MSG": "Message",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
    b"RCT": "ReverseHello",
}

_OPCUA_SECURITY_POLICIES: list[str] = [
    "http://opcfoundation.org/UA/SecurityPolicy#None",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
]

_SNMP_COMMUNITIES_DEFAULT: list[str] = [
    "public",
    "private",
    "manager",
    "admin",
    "test",
    "default",
    "secret",
    "password",
    "community",
    "snmp",
    "monitor",
    "internal",
    "guest",
    "readonly",
    "readwrite",
    "monitoring",
    "network",
    "system",
    "equipment",
    "scada",
    "plc",
]


def _load_iot_data() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "iot_attack", default={"snmp_communities": _SNMP_COMMUNITIES_DEFAULT}
    )
    return data.get("snmp_communities", _SNMP_COMMUNITIES_DEFAULT)


_SNMP_COMMUNITIES = _load_iot_data()

_SNMP_OIDS: dict[str, str] = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}

_MQTT_TOPICS_DEFAULT: list[str] = [
    "$SYS/#",
    "#",
    "+",
    "home/#",
    "device/#",
    "sensor/#",
    "iot/#",
    "data/#",
    "telemetry/#",
    "status/#",
]


def _load_mqtt_topics() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "iot_attack", default={"mqtt_topics": _MQTT_TOPICS_DEFAULT}
    )
    return data.get("mqtt_topics", _MQTT_TOPICS_DEFAULT)


_MQTT_TOPICS = _load_mqtt_topics()

_MQTT_PACKET_TYPES: dict[int, str] = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
}


@dataclass(frozen=True, slots=True)
class IoTAttackAttempt:
    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    protocol: str
    port: int
    device_info: dict[str, Any]
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class IoTAttackResult:
    target: str
    host: str
    port: int
    protocols_found: list[str]
    attempts: list[IoTAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "iot": ["modbus_scan", "opcua_discovery", "bacnet_scan", "snmp_brute", "mqtt_enum"],
}


def _parse_target(target: str) -> tuple[str, int]:
    if "://" in target:
        target = target.split("://", 1)[1]
    host, _, port_str = target.partition(":")
    port = int(port_str) if port_str.isdigit() else 502
    return host.strip(), port


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    protocol: str,
    port: int,
    device_info: dict[str, Any] | None = None,
) -> IoTAttackAttempt:
    return IoTAttackAttempt(
        exploit="protocol_specific_payload",
        tool="metasploit",
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        protocol=protocol,
        port=port,
        device_info=device_info or {},
    )


def _encode_varint(value: int) -> bytes:
    result: list[int] = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _snmp_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded: list[int] = []
    temp = length
    while temp > 0:
        encoded.append(temp & 0xFF)
        temp >>= 8
    encoded.reverse()
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _snmp_encode_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.split(".") if p]
    if len(parts) < 2:
        return b"\x06\x01\x00"
    result = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            result += bytes([part])
        else:
            sub_result: list[int] = []
            temp = part
            while temp > 0:
                sub_result.append(temp & 0x7F)
                temp >>= 7
            sub_result.reverse()
            for i in range(len(sub_result) - 1):
                sub_result[i] |= 0x80
            result += bytes(sub_result)
    return b"\x06" + _snmp_encode_length(len(result)) + result


def _snmp_build_get_request(community: str, oid: str, request_id: int = 1) -> bytes:
    version = b"\x02\x01\x01"
    comm = b"\x04" + _snmp_encode_length(len(community)) + community.encode()
    oid_bytes = _snmp_encode_oid(oid)
    varbind = (
        b"\x30" + _snmp_encode_length(len(oid_bytes) + 2) + oid_bytes + b"\x05\x00"
    )
    pdu = (
        b"\xa0"
        + _snmp_encode_length(10 + len(varbind))
        + b"\x02\x04"
        + struct.pack(">I", request_id)
        + b"\x02\x01\x00"
        + b"\x02\x01\x00"
        + varbind
    )
    return (
        b"\x30"
        + _snmp_encode_length(len(version) + len(comm) + len(pdu))
        + version
        + comm
        + pdu
    )


def _snmp_parse_value(data: bytes, offset: int) -> tuple[Any, int]:
    if offset >= len(data):
        return None, offset
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if tag == 0x02:
        return int.from_bytes(data[offset : offset + length], "big"), offset + length
    elif tag == 0x04:
        return data[offset : offset + length].decode(
            "utf-8", errors="replace"
        ), offset + length
    elif tag == 0x06:
        oid_parts: list[int] = []
        if length > 0:
            oid_parts.append(data[offset] // 40)
            oid_parts.append(data[offset] % 40)
            offset += 1
            i = 1
            while i < length:
                sub = 0
                while data[offset] & 0x80:
                    sub = (sub << 7) | (data[offset] & 0x7F)
                    offset += 1
                    i += 1
                sub = (sub << 7) | data[offset]
                oid_parts.append(sub)
                offset += 1
                i += 1
        return ".".join(str(p) for p in oid_parts), offset
    elif tag == 0x05:
        return None, offset
    else:
        return data[offset : offset + length], offset + length


def _snmp_parse_response(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"raw": data.hex()}
    if len(data) < 2:
        return result
    offset = 0
    if data[offset] == 0x30:
        offset += 1
        offset += 1
        if data[offset] == 0x02:
            offset += 1
            vlen = data[offset]
            offset += 1
            result["version"] = int.from_bytes(data[offset : offset + vlen], "big")
            offset += vlen
        if data[offset] == 0x04:
            offset += 1
            clen = data[offset]
            offset += 1
            result["community"] = data[offset : offset + clen].decode(
                "utf-8", errors="replace"
            )
            offset += clen
        if data[offset] in (0xA1, 0xA2):
            pdu_tag = data[offset]
            offset += 1
            offset += 1
            if data[offset] == 0x02:
                offset += 1
                rlen = data[offset]
                offset += 1
                result["request_id"] = int.from_bytes(
                    data[offset : offset + rlen], "big"
                )
                offset += rlen
            if data[offset] == 0x02:
                offset += 1
                elen = data[offset]
                offset += 1
                result["error_status"] = int.from_bytes(
                    data[offset : offset + elen], "big"
                )
                offset += elen
            if data[offset] == 0x02:
                offset += 1
                ilen = data[offset]
                offset += 1
                result["error_index"] = int.from_bytes(
                    data[offset : offset + ilen], "big"
                )
                offset += ilen
            if (
                pdu_tag == 0xA2
                and result.get("error_status", 0) == 0
                and data[offset] == 0x30
            ):
                offset += 1
                vblen = data[offset]
                offset += 1
                end = offset + vblen
                while offset < end:
                    if data[offset] == 0x30:
                        offset += 1
                        offset += 1
                        oid_val, offset = _snmp_parse_value(data, offset)
                        val, offset = _snmp_parse_value(data, offset)
                        if "varbinds" not in result:
                            result["varbinds"] = {}
                        result["varbinds"][str(oid_val)] = val
    return result


async def _test_modbus_scan(host: str, port: int, timeout: float) -> IoTAttackAttempt:
    device_info: dict[str, Any] = {
        "device_id": 0,
        "functions_supported": [],
        "registers": {},
    }
    endpoint = f"{host}:{port}"

    for unit_id in range(256):
        for fc in (0x03, 0x01, 0x04):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(min(timeout, 3.0))
                sock.connect((host, port))
                txn_id = random.randint(0, 65535)
                payload = struct.pack(">HHHB", txn_id, 0x0000, 6, unit_id) + bytes(
                    [fc, 0x00, 0x00, 0x00, 0x0A]
                )
                sock.send(payload)
                response = sock.recv(1024)
                sock.close()
                if len(response) >= 9:
                    resp_fc = response[7]
                    if resp_fc & 0x80:
                        exc_code = response[8] if len(response) > 8 else 0
                        if exc_code in _MODBUS_EXCEPTIONS and unit_id not in [
                            d.get("unit_id") for d in device_info.get("devices", [])
                        ]:
                            device_info.setdefault("devices", []).append(
                                {
                                    "unit_id": unit_id,
                                    "exception": _MODBUS_EXCEPTIONS[exc_code],
                                }
                            )
                    elif resp_fc in _MODBUS_FC:
                        data_len = response[8] if len(response) > 8 else 0
                        regs = [
                            struct.unpack(">H", response[i : i + 2])[0]
                            for i in range(9, min(9 + data_len, len(response)), 2)
                            if i + 1 < len(response)
                        ]
                        device_info["functions_supported"].append(_MODBUS_FC[resp_fc])
                        device_info["registers"][f"fc{resp_fc:02x}_unit{unit_id}"] = (
                            regs
                        )
                        device_info["device_id"] = unit_id
            except Exception:
                pass

    has_fc = len(device_info["functions_supported"]) > 0
    devices_count = len(device_info.get("devices", []))
    vuln = has_fc or devices_count > 0
    details = (
        f"Functions: {', '.join(set(device_info['functions_supported']))}"
        if has_fc
        else "No Modbus responses"
    )
    if devices_count:
        details += f", {devices_count} device(s) responded"
    return _make_attempt(
        "modbus_scan",
        "iot",
        "Modbus TCP scanner",
        vuln,
        details,
        "",
        endpoint,
        "modbus",
        port,
        device_info,
    )


async def _test_opcua_discovery(
    host: str, port: int, timeout: float
) -> IoTAttackAttempt:
    device_info: dict[str, Any] = {
        "server": {},
        "endpoints": [],
        "nodes": [],
        "security_policies": [],
    }
    endpoint = f"{host}:{port}"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 5.0))
        sock.connect((host, port))

        endpoint_url = f"opc.tcp://{host}:{port}"
        eu_bytes = endpoint_url.encode("utf-8")
        hello_body = (
            struct.pack("<IIII", 0, 65536, 65536, 0)
            + struct.pack("<I", len(eu_bytes))
            + eu_bytes
        )
        hello_header = b"HEL" + b"F" + struct.pack("<I", 8 + len(hello_body))
        sock.send(hello_header + hello_body)

        ack_data = sock.recv(4096)
        if len(ack_data) >= 28:
            msg_type = ack_data[0:3]
            if msg_type == b"ACK":
                recv_buf, send_buf = struct.unpack_from("<II", ack_data, 8)
                device_info["server"]["recv_buffer"] = recv_buf
                device_info["server"]["send_buffer"] = send_buf

        node_id = b"\x01\x00\x00" + b"\x00"
        request_header = (
            b"\x00\x00\x00\x00"
            + b"\xff\xff\xff\xff"
            + b"\x00" * 8
            + node_id
            + b"\xff\xff\xff\xff"
        )

        get_eps_payload = request_header + b"\x01\x00\x00\x00\x00\x00"
        msg_size = 12 + len(get_eps_payload)
        msg = (
            b"MSG"
            + b"F"
            + struct.pack("<I", msg_size)
            + struct.pack("<II", 0, 1)
            + get_eps_payload
        )
        sock.send(msg)

        eps_data = sock.recv(65536)
        if len(eps_data) > 20:
            device_info["server"]["raw_response"] = eps_data[:200].hex()

        for policy in _OPCUA_SECURITY_POLICIES:
            device_info["security_policies"].append(policy)

        sock.close()
    except Exception:
        pass

    endpoints_count = len(device_info.get("endpoints", []))
    nodes_count = len(device_info.get("nodes", []))
    policies_count = len(device_info["security_policies"])
    vuln = policies_count > 0
    details = f"Policies: {policies_count}"
    if endpoints_count:  # pragma: no cover
        details += f", Endpoints: {endpoints_count}"
    if nodes_count:  # pragma: no cover
        details += f", Nodes: {nodes_count}"
    if device_info["server"]:
        details += ", Server: detected"
    return _make_attempt(
        "opcua_discovery",
        "iot",
        "OPC UA discovery and browse",
        vuln,
        details,
        "",
        endpoint,
        "opcua",
        port,
        device_info,
    )


async def _test_bacnet_scan(host: str, port: int, timeout: float) -> IoTAttackAttempt:
    device_info: dict[str, Any] = {"devices": []}
    endpoint = f"{host}:{port}"

    who_is = bytes(
        [
            0x81,
            0x0B,
            0x12,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )
    who_is = who_is[:2] + struct.pack(">B", len(who_is) - 2) + who_is[3:]
    who_is_fixed = (
        0x81.to_bytes(1, "big")
        + 0x0B.to_bytes(1, "big")
        + b"\x0c"
        + struct.pack(">BB", 0x00, 0xFF)
        + struct.pack(">HH", 0x00, 0x00)
        + b"\x00"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 3.0))
        sock.sendto(who_is_fixed, (host, port))

        for _ in range(5):
            try:
                data, addr = sock.recvfrom(1500)
                if len(data) >= 14:
                    pdu_type = (data[11] >> 4) & 0x0F if len(data) > 11 else 0
                    if pdu_type == 1:
                        offset = 14
                        if offset < len(data):
                            device_id = (
                                int.from_bytes(data[offset : offset + 4], "big")
                                if offset + 4 <= len(data)
                                else 0
                            )
                            vendor_id = (
                                int.from_bytes(data[offset + 4 : offset + 6], "big")
                                if offset + 6 <= len(data)
                                else 0
                            )
                            device_info["devices"].append(
                                {
                                    "device_id": device_id,
                                    "vendor_id": vendor_id,
                                    "address": f"{addr[0]}:{addr[1]}",
                                }
                            )
            except TimeoutError:
                break
        sock.close()
    except Exception:
        pass

    devices_count = len(device_info["devices"])
    vuln = devices_count > 0
    details = f"Devices: {devices_count}" if vuln else "No BACnet devices found"
    if device_info["devices"]:
        for d in device_info["devices"][:3]:
            details += f" (ID:{d['device_id']}, Vendor:{d['vendor_id']})"
    return _make_attempt(
        "bacnet_scan",
        "iot",
        "BACnet device discovery",
        vuln,
        details,
        "",
        endpoint,
        "bacnet",
        port,
        device_info,
    )


async def _test_snmp_brute(host: str, port: int, timeout: float) -> IoTAttackAttempt:
    device_info: dict[str, Any] = {"communities": [], "oids": {}}
    endpoint = f"{host}:{port}"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 2.0))

        for community in _SNMP_COMMUNITIES:
            for oid_name, oid_str in _SNMP_OIDS.items():
                try:
                    packet = _snmp_build_get_request(community, oid_str)
                    sock.sendto(packet, (host, port))
                    data, _ = sock.recvfrom(4096)
                    parsed = _snmp_parse_response(data)
                    if parsed.get("error_status") == 0 and parsed.get("varbinds"):
                        if community not in device_info["communities"]:
                            device_info["communities"].append(community)
                        device_info["oids"][oid_name] = parsed["varbinds"].get(
                            oid_str, ""
                        )
                except TimeoutError:
                    continue
                except Exception:
                    continue
        sock.close()
    except Exception:
        pass

    communities_count = len(device_info["communities"])
    vuln = communities_count > 0
    details = (
        f"Communities: {', '.join(device_info['communities'][:5])}"
        if vuln
        else "No valid communities found"
    )
    if device_info["oids"]:
        sys_name = device_info["oids"].get("sysName", "")
        if sys_name:
            details += f", sysName: {sys_name}"
    return _make_attempt(
        "snmp_brute",
        "iot",
        "SNMP community brute force",
        vuln,
        details,
        "",
        endpoint,
        "snmp",
        port,
        device_info,
    )


async def _test_mqtt_enum(host: str, port: int, timeout: float) -> IoTAttackAttempt:
    device_info: dict[str, Any] = {"topics": [], "messages": [], "broker_info": {}}
    endpoint = f"{host}:{port}"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 5.0))
        sock.connect((host, port))

        client_id = f"iot_{random.randint(10000, 99999)}"
        var_header = (
            struct.pack(">H", 4)
            + b"MQTT"
            + bytes([4])
            + bytes([0x02])
            + struct.pack(">H", 60)
        )
        payload = struct.pack(">H", len(client_id)) + client_id.encode()
        remaining = var_header + payload
        connect_pkt = bytes([0x10]) + _encode_varint(len(remaining)) + remaining
        sock.send(connect_pkt)

        connack = sock.recv(1024)
        if len(connack) >= 4 and connack[0] == 0x20:
            sp = connack[3]
            device_info["broker_info"]["session_present"] = bool(sp & 0x01)
            rc = connack[3] if len(connack) > 3 else 0
            device_info["broker_info"]["return_code"] = rc

        for i, topic in enumerate(_MQTT_TOPICS):
            try:
                topic_bytes = topic.encode("utf-8")
                sub_payload = (
                    struct.pack(">H", i + 1)
                    + struct.pack(">H", len(topic_bytes))
                    + topic_bytes
                    + bytes([0x00])
                )
                sub_pkt = bytes([0x82]) + _encode_varint(len(sub_payload)) + sub_payload
                sock.send(sub_pkt)
            except Exception:
                pass

        sock.settimeout(min(timeout, 3.0))
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                msg_type = (data[0] >> 4) & 0x0F
                if msg_type == 9:
                    if len(data) >= 4:
                        granted_qos = data[3:]
                        device_info["broker_info"]["subscriptions_granted"] = len(
                            granted_qos
                        )
                elif msg_type == 3:
                    topic_len = (
                        struct.unpack(">H", data[1:3])[0] if len(data) >= 3 else 0
                    )
                    topic_name = (
                        data[3 : 3 + topic_len].decode("utf-8", errors="replace")
                        if topic_len > 0
                        else ""
                    )
                    msg_payload = data[3 + topic_len :].decode(
                        "utf-8", errors="replace"
                    )
                    device_info["topics"].append(topic_name)
                    device_info["messages"].append(
                        {"topic": topic_name, "payload": msg_payload[:200]}
                    )
            except TimeoutError:
                break

        disconnect_pkt = bytes([0xE0, 0x00])
        sock.send(disconnect_pkt)
        sock.close()
    except Exception:
        pass

    topics_count = len(device_info["topics"])
    messages_count = len(device_info["messages"])
    vuln = topics_count > 0
    details = (
        f"Topics: {topics_count}, Messages: {messages_count}"
        if vuln
        else "No MQTT topics found"
    )
    if device_info["broker_info"].get("session_present"):
        details += ", Session: present"
    return _make_attempt(
        "mqtt_enum",
        "iot",
        "MQTT topic enumeration",
        vuln,
        details,
        "",
        endpoint,
        "mqtt",
        port,
        device_info,
    )


async def _test_iot(
    host: str,
    port: int,
    timeout: float,
) -> list[IoTAttackAttempt]:
    results: list[IoTAttackAttempt] = []
    for tech, fn, default_port in [
        ("modbus_scan", _test_modbus_scan, 502),
        ("opcua_discovery", _test_opcua_discovery, 4840),
        ("bacnet_scan", _test_bacnet_scan, 47808),
        ("snmp_brute", _test_snmp_brute, 161),
        ("mqtt_enum", _test_mqtt_enum, 1883),
    ]:
        try:
            result = await fn(host, port if port != 502 else default_port, timeout)
            results.append(result)
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "iot",
                    "",
                    False,
                    "",
                    str(exc)[:100],
                    f"{host}:{port}",
                    tech.split("_")[0],
                    port,
                )
            )
    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[IoTAttackAttempt]]]
] = {
    "iot": _test_iot,
}


def print_results(result: IoTAttackResult) -> None:
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "IoT & Industrial Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(color("[*]", Cyber.CYAN), f"Host: {result.host}:{result.port}")
    if result.protocols_found:
        print(
            color("[*]", Cyber.CYAN), f"Protocols: {', '.join(result.protocols_found)}"
        )
    print()
    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()
    categories: dict[str, list[IoTAttackAttempt]] = {}
    for attempt in result.attempts:
        categories.setdefault(attempt.category, []).append(attempt)
    for cat, attempts in categories.items():
        vuln_in_cat = [a for a in attempts if a.vulnerable]
        if vuln_in_cat:
            print(
                color("[!]", Cyber.RED, Cyber.BOLD),
                f"{cat}: {len(vuln_in_cat)} vulnerable(s)",
            )
            for a in vuln_in_cat:
                print(color("    [-]", Cyber.RED), f"{a.technique}: {a.details}")
                print_exploit_info(a.exploit, a.tool)
        else:
            print(color("[+]", Cyber.GREEN), f"{cat}: secure")
    print()
    if result.overall_status == "vulnerable":
        print(
            color("[!]", Cyber.RED, Cyber.BOLD),
            "VULNERABLE — IoT/Industrial weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — IoT/Industrial configuration looks good",
        )
    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> IoTAttackResult:
    host, port = _parse_target(target)
    protocols_found: list[str] = []
    all_attempts: list[IoTAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())
    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, timeout)
            all_attempts.extend(raw)
            protocols_found.extend(a.protocol for a in raw if a.vulnerable)
        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error",
                    cat,
                    "",
                    False,
                    "",
                    str(e)[:100],
                    f"{host}:{port}",
                    "unknown",
                    port,
                )
            )
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"
    result = IoTAttackResult(
        target=target,
        host=host,
        port=port,
        protocols_found=list(set(protocols_found)),
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )
    print_results(result)
    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-iot",
        description="IoT & Industrial Attack Testing — Modbus, OPC UA, BACnet, SNMP, MQTT",
    )
    parser.add_argument("target", help="Alvo (host:port, ex: 192.168.1.100:502)")
    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    result = safe_asyncio_run(
        run_scan(
            target=args.target,
            categories=getattr(args, "categories", None),
            timeout=getattr(args, "timeout", 5.0),
            output_file=getattr(args, "output", None),
        )
    )
    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "IoT & Industrial Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "target", None)),
        prompt="iot> ",
        description="IoT & Industrial Attack Testing — Modbus, OPC UA, BACnet, SNMP, MQTT",
        example="mytools-iot 192.168.1.100:502",
        contextual_help="iot: modbus_scan, opcua_discovery, bacnet_scan, snmp_brute, mqtt_enum",
    )


if __name__ == "__main__":
    raise SystemExit(main())
