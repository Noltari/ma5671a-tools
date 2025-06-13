"""Huawei MA5671a SFP EEPROM info."""

import base64
import binascii
from enum import IntEnum
import json
import logging
from math import log10
import optparse
import struct
import sys
from typing import Any, Final


class ExitCode(IntEnum):
    NO_ERROR = 0
    INPUT_FILE_NAME = 1
    EEPROM_LEN = 2


def bytes_to_i8(data: bytearray) -> int:
    return struct.unpack("b", data)[0]


def bytes_to_i16(data: bytearray) -> int:
    return struct.unpack(">h", data)[0]


def bytes_to_i32(data: bytearray) -> int:
    return struct.unpack(">i", data)[0]


def bytes_to_u8(data: bytearray) -> int:
    return struct.unpack("B", data)[0]


def bytes_to_u16(data: bytearray) -> int:
    return struct.unpack(">H", data)[0]


def bytes_to_u32(data: bytearray) -> int:
    return struct.unpack(">I", data)[0]


def i8_to_bytes(data: int) -> bytes:
    return struct.pack("b", data)


def i16_to_bytes(data: int) -> bytes:
    return struct.pack(">h", data)


def i32_to_bytes(data: int) -> bytes:
    return struct.pack(">i", data)


def u8_to_bytes(data: int) -> bytes:
    return struct.pack("B", data)


def u16_to_bytes(data: int) -> bytes:
    return struct.pack(">H", data)


def u32_to_bytes(data: int) -> bytes:
    return struct.pack(">I", data)


class StringType(IntEnum):
    NONE = 0
    SERIAL = 1
    MAC_ADDRESS = 2


def str_to_bytes(
    data_str: str | None, str_len: int, str_type: StringType = StringType.NONE
) -> bytearray:
    if data_str is None:
        return bytearray(str_len)

    if data_str.startswith("0x"):
        data_bytes = bytes.fromhex(data_str.lstrip("0x"))
    else:
        if str_type == StringType.MAC_ADDRESS:
            mac_addr = data_str.strip().replace(":", "")
            data_bytes = binascii.unhexlify(mac_addr)
        elif str_type == StringType.SERIAL:
            manufacturer = data_str[:4].encode()
            serial_number = binascii.unhexlify(data_str[4:])
            data_bytes = manufacturer + serial_number
        else:
            data_bytes = data_str.encode()

    data_len = len(data_bytes)

    if data_len < str_len:
        data_bytes = data_bytes + bytearray(str_len - data_len)
    if data_len > str_len:
        data_bytes = gpon_ploam[: str_len + 1]

    return data_bytes


B64_LINE_LEN: Final[int] = 60
B64_LINE_SEP: Final[str] = "@"
B64_LINE_SEP_BYTES: Final[bytearray] = bytearray([ord(B64_LINE_SEP)])
EEPROM_LEN: Final[int] = 640
GPON_EQUIPMENT_ID_LEN: Final[int] = 20
GPON_LOID_LEN: Final[int] = 24
GPON_LPWD_LEN: Final[int] = 17
GPON_MAC_LEN: Final[int] = 6
GPON_PLOAM_LEN: Final[int] = GPON_LOID_LEN
GPON_SERIAL_LEN: Final[int] = 8
GPON_VENDOR_ID_LEN: Final[int] = 4


EEPROM_MWATTS_CONV: Final[int] = 10000
EEPROM_MAMPS_CONV: Final[int] = 500
EEPROM_VOLTS_CONV: Final[int] = 10000


class GponAuth(IntEnum):
    LOID = 0x01
    PLOAM = 0x02


def eeprom_to_dbm(value: int) -> int:
    return int(round(10 * log10(value / EEPROM_MWATTS_CONV), 0))


def eeprom_to_hex(value: bytearray, prefix: bool = True) -> str:
    if prefix:
        hex_str = "0x"
    else:
        hex_str = ""
    for cur_byte in value:
        hex_str += "%02x" % cur_byte
    return hex_str


def eeprom_to_loid_ploam_switch(value: bytearray) -> str:
    if value[0] == GponAuth.LOID:
        return "LOID"
    elif value[0] == GponAuth.PLOAM:
        return "PLOAM"
    return eeprom_to_hex(value)


def eeprom_to_mac(value: bytearray) -> str:
    if len(value) != 6:
        return ""

    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
    )


def eeprom_to_mamps(value: int) -> float:
    return value / EEPROM_MAMPS_CONV


def eeprom_to_serial_number(value: bytearray) -> str:
    manufacturer = value[:4]
    serial_number = value[4:]

    if manufacturer.isalpha():
        manufacturer_str = manufacturer.decode()
    else:
        return eeprom_to_hex(value)

    return manufacturer_str + eeprom_to_hex(serial_number, False)


def eeprom_to_str(value: bytearray) -> str:
    if value.isalpha():
        return value.decode()

    offset = 0
    value_str = ""
    for cur_byte in value:
        cur_value = value[offset : offset + 1]
        if cur_value.isalpha():
            value_str += cur_value.decode()
        else:
            break
        offset += 1

    if offset > 0:
        value_str = value_str + " + " + eeprom_to_hex(value[offset:])
        return value_str

    return eeprom_to_hex(value)


def eeprom_to_u8(value: int) -> str:
    return "0x%02x" % value


def eeprom_to_u16(value: int) -> str:
    return "0x%04x" % value


def eeprom_to_u32(value: int) -> str:
    return "0x%08x" % value


def eeprom_to_volts(value: int) -> float:
    return value / EEPROM_VOLTS_CONV


class EEPROM0:
    """Huawei MA5671a EEPROM0 layout."""

    identifier: int
    # TODO
    reserved_1: bytearray
    reserved_2: bytearray

    def __init__(self) -> None:
        """Init EEPROM class."""
        self.default_values()

    def data(self) -> dict[str, Any]:
        """Get EEPROM data."""
        _data: dict[str, Any] = {
            "identifier": self.identifier,
            # TODO
            "reserved-1": eeprom_to_hex(self.reserved_1),
            "reserved-2": eeprom_to_hex(self.reserved_2),
        }
        return json.dumps(_data, indent=4)

    def default_values(self):
        """Set EEPROM default values."""
        self.identifier = 0x3
        # TODO
        self.reserved_1 = bytearray(128)
        self.reserved_2 = bytearray(384)

    def hex_import(self, hex: bytearray) -> None:
        self.identifier = bytes_to_u8(hex[0:1])
        # TODO
        self.reserved_1 = hex[128:256]
        self.reserved_2 = hex[256:640]

    def hex_export(self) -> bytearray:
        hex = bytearray()
        hex += u8_to_bytes(self.identifier)
        # TODO
        hex += self.reserved_1
        hex += self.reserved_2
        return hex

    def b64_encode(self, hex: bytearray = None) -> bytearray:
        if hex is None:
            hex = self.hex_export()

        b64 = base64.b64encode(hex)
        res = bytearray()
        res += B64_LINE_SEP_BYTES

        offset = 0
        for cur_byte in b64:
            if offset > 0 and offset % B64_LINE_LEN == 0:
                res += B64_LINE_SEP_BYTES

            res += bytearray([cur_byte])

            offset += 1

        res += B64_LINE_SEP_BYTES
        res += bytearray([ord("=")] * 4)
        res += B64_LINE_SEP_BYTES

        return res


class EEPROM1:
    """Huawei MA5671a EEPROM1 layout."""

    temp_high_alarm: int
    temp_low_alarm: int
    temp_high_warning: int
    temp_low_warning: int
    voltage_high_alarm: int
    voltage_low_alarm: int
    voltage_high_warning: int
    voltage_low_warning: int
    bias_high_alarm: int
    bias_low_alarm: int
    bias_high_warning: int
    bias_low_warning: int
    tx_power_high_alarm: int
    tx_power_low_alarm: int
    tx_power_high_warning: int
    tx_power_low_warning: int
    rx_power_high_alarm: int
    rx_power_low_alarm: int
    rx_power_high_warning: int
    rx_power_low_warning: int
    mac_address: bytearray
    reserved_1: bytearray
    rx_power_4_cal: int
    rx_power_3_cal: int
    rx_power_2_cal: int
    rx_power_1_cal: int
    rx_power_0_cal: int
    tx_bias_slope_cal: int
    tx_bias_offset_cal: int
    tx_power_slope_cal: int
    tx_power_offset_cal: int
    temperature_slope_cal: int
    temperature_offset_cal: int
    voltage_slope_cal: int
    voltage_offset_cal: int
    reserved_2: bytearray
    cc_dmi = int
    temperature_msb = int
    temperature_lsb = int
    vcc_msb = int
    vcc_lsb = int
    tx_bias_msb = int
    tx_bias_lsb = int
    tx_power_msb = int
    tx_power_lsb = int
    rx_power_msb = int
    rx_power_lsb = int
    optional_diagnostics = bytearray
    status_control = int
    reserved_3: bytearray
    alarm_flags: int
    tx_in_eq_control: int
    rx_out_emph_control: int
    warning_flags: int
    ext_status_control: int
    vendor_specific: bytearray
    table_select: int
    reserved_4: bytearray
    gpon_loid_ploam: bytearray
    gpon_lpwd: bytearray
    gpon_loid_ploam_switch: bytearray
    gpon_serial_number: bytearray
    reserved_5: bytearray
    vendor_control: bytearray
    unknown_vendor_specific: bytearray
    gpon_equipment_id: bytearray
    gpon_vendor_id: bytearray
    reserved_6: bytearray

    def __init__(self) -> None:
        """Init EEPROM class."""
        self.default_values()

    def data(self) -> dict[str, Any]:
        """Get EEPROM data."""
        _data: dict[str, Any] = {
            "temp-high-alarm": self.temp_high_alarm,
            "temp-low-alarm": self.temp_low_alarm,
            "temp-high-warning": self.temp_high_warning,
            "temp-low-warning": self.temp_low_warning,
            "voltage-high-alarm": eeprom_to_volts(self.voltage_high_alarm),
            "voltage-low-alarm": eeprom_to_volts(self.voltage_low_alarm),
            "voltage-high-warning": eeprom_to_volts(self.voltage_high_warning),
            "voltage-low-warning": eeprom_to_volts(self.voltage_low_warning),
            "bias-high-alarm": eeprom_to_mamps(self.bias_high_alarm),
            "bias-low-alarm": eeprom_to_mamps(self.bias_low_alarm),
            "bias-high-warning": eeprom_to_mamps(self.bias_high_warning),
            "bias-low-warning": eeprom_to_mamps(self.bias_low_warning),
            "tx-power-high-alarm": eeprom_to_dbm(self.tx_power_high_alarm),
            "tx-power-low-alarm": eeprom_to_dbm(self.tx_power_low_alarm),
            "tx-power-high-warning": eeprom_to_dbm(self.tx_power_high_warning),
            "tx-power-low-warning": eeprom_to_dbm(self.tx_power_low_warning),
            "rx-power-high-alarm": eeprom_to_dbm(self.rx_power_high_alarm),
            "rx-power-low-alarm": eeprom_to_dbm(self.rx_power_low_alarm),
            "rx-power-high-warning": eeprom_to_dbm(self.rx_power_high_warning),
            "rx-power-low-warning": eeprom_to_dbm(self.rx_power_low_warning),
            "mac-address": eeprom_to_mac(self.mac_address),
            "reserved-1": eeprom_to_hex(self.reserved_1),
            "rx-power-4-cal": eeprom_to_u32(self.rx_power_4_cal),
            "rx-power-3-cal": eeprom_to_u32(self.rx_power_3_cal),
            "rx-power-2-cal": eeprom_to_u32(self.rx_power_2_cal),
            "rx-power-1-cal": eeprom_to_u32(self.rx_power_1_cal),
            "rx-power-0-cal": eeprom_to_u32(self.rx_power_0_cal),
            "tx-bias-slope-cal": eeprom_to_u16(self.tx_bias_slope_cal),
            "tx-bias-offset-cal": eeprom_to_u16(self.tx_bias_offset_cal),
            "tx-power-slope-cal": eeprom_to_u16(self.tx_power_slope_cal),
            "tx-power-offset-cal": eeprom_to_u16(self.tx_power_offset_cal),
            "temperature-slope-cal": eeprom_to_u16(self.temperature_slope_cal),
            "temperature-offset-cal": eeprom_to_u16(self.temperature_offset_cal),
            "voltage-slope-cal": eeprom_to_u16(self.voltage_slope_cal),
            "voltage-offset-cal": eeprom_to_u16(self.voltage_offset_cal),
            "reserved-2": eeprom_to_hex(self.reserved_2),
            "cc-dmi": eeprom_to_u8(self.cc_dmi),
            "temperature-msb": eeprom_to_u8(self.temperature_msb),
            "temperature-lsb": eeprom_to_u8(self.temperature_lsb),
            "vcc-msb": eeprom_to_u8(self.vcc_msb),
            "vcc-lsb": eeprom_to_u8(self.vcc_lsb),
            "tx-bias-msb": eeprom_to_u8(self.tx_bias_msb),
            "tx-bias-lsb": eeprom_to_u8(self.tx_bias_lsb),
            "tx-power-msb": eeprom_to_u8(self.tx_power_msb),
            "tx-power-lsb": eeprom_to_u8(self.tx_power_lsb),
            "rx-power-msb": eeprom_to_u8(self.rx_power_msb),
            "rx-power-lsb": eeprom_to_u8(self.rx_power_lsb),
            "optional-diagnostics": eeprom_to_hex(self.optional_diagnostics),
            "status-control": eeprom_to_u8(self.status_control),
            "reserved-3": eeprom_to_hex(self.reserved_3),
            "alarm-flags": eeprom_to_u16(self.alarm_flags),
            "tx-input-equalization-level-control": eeprom_to_u8(self.tx_in_eq_control),
            "rx-output-emphasis-level-control": eeprom_to_u8(self.rx_out_emph_control),
            "warning-flags": eeprom_to_u16(self.warning_flags),
            "extended-status-control": eeprom_to_u16(self.ext_status_control),
            "vendor-select": eeprom_to_hex(self.vendor_specific),
            "table-select": eeprom_to_u8(self.table_select),
            "reserved-4": eeprom_to_hex(self.reserved_4),
            "gpon-loid-ploam": eeprom_to_str(self.gpon_loid_ploam),
            "gpon-lpwd": eeprom_to_str(self.gpon_lpwd),
            "gpon-loid-ploam-switch": eeprom_to_loid_ploam_switch(
                self.gpon_loid_ploam_switch
            ),
            "gpon-serial-number": eeprom_to_serial_number(self.gpon_serial_number),
            "reserved-5": eeprom_to_hex(self.reserved_5),
            "vendor-control": eeprom_to_hex(self.vendor_control),
            "unknown-vendor-specific": eeprom_to_hex(self.unknown_vendor_specific),
            "gpon-equipment-id": eeprom_to_str(self.gpon_equipment_id),
            "gpon-vendor-id": eeprom_to_str(self.gpon_vendor_id),
            "reserved-6": eeprom_to_hex(self.reserved_6),
        }
        return json.dumps(_data, indent=4)

    def default_values(self):
        """Set EEPROM default values."""
        self.temp_high_alarm = 95
        self.temp_low_alarm = -50
        self.temp_high_warning = 90
        self.temp_low_warning = -45
        self.voltage_high_alarm = 36000
        self.voltage_low_alarm = 30000
        self.voltage_high_warning = 35000
        self.voltage_low_warning = 31000
        self.bias_high_alarm = 45000
        self.bias_low_alarm = 0
        self.bias_high_warning = 35000
        self.bias_low_warning = 0
        self.tx_power_high_alarm = 39810
        self.tx_power_low_alarm = 8912
        self.tx_power_high_warning = 31622
        self.tx_power_low_warning = 11220
        self.rx_power_high_alarm = 2511
        self.rx_power_low_alarm = 13
        self.rx_power_high_warning = 1995
        self.rx_power_low_warning = 16
        self.mac_address = bytearray(GPON_MAC_LEN)
        self.reserved_1 = bytearray(10)
        self.rx_power_4_cal = 0
        self.rx_power_3_cal = 0
        self.rx_power_2_cal = 0
        self.rx_power_1_cal = 0x3F800000
        self.rx_power_0_cal = 0
        self.tx_bias_slope_cal = 0x0100
        self.tx_bias_offset_cal = 0
        self.tx_power_slope_cal = 0x0100
        self.tx_power_offset_cal = 0
        self.temperature_slope_cal = 0x0100
        self.temperature_offset_cal = 0
        self.voltage_slope_cal = 0x0100
        self.voltage_offset_cal = 0
        self.reserved_2 = bytearray(3)
        self.cc_dmi = 0
        self.temperature_msb = 0
        self.temperature_lsb = 0
        self.vcc_msb = 0
        self.vcc_lsb = 0
        self.tx_bias_msb = 0
        self.tx_bias_lsb = 0
        self.tx_power_msb = 0
        self.tx_power_lsb = 0
        self.rx_power_msb = 0
        self.rx_power_lsb = 0
        self.optional_diagnostics = bytearray([0xFF] * 4)
        self.status_control = 0
        self.reserved_3 = bytearray(1)
        self.alarm_flags = 0
        self.tx_in_eq_control = 0xFF
        self.rx_out_emph_control = 0xFF
        self.warning_flags = 0
        self.ext_status_control = 0
        self.vendor_specific = bytearray([0x70]) + bytearray(6)
        self.table_select = 0
        self.reserved_4 = bytearray([0xFF] * 63)
        self.gpon_loid_ploam = bytearray(GPON_LOID_LEN)
        self.gpon_lpwd = bytearray(GPON_LPWD_LEN)
        self.gpon_loid_ploam_switch = bytearray(1)
        self.gpon_serial_number = bytearray(GPON_SERIAL_LEN)
        self.reserved_5 = bytearray([0xFF] * 7)
        self.vendor_control = bytearray([0xFF] * 8)
        self.unknown_vendor_specific = bytearray(256)
        self.gpon_equipment_id = bytearray(GPON_EQUIPMENT_ID_LEN)
        self.gpon_vendor_id = bytearray(GPON_VENDOR_ID_LEN)
        self.reserved_6 = bytearray(104)

    def hex_import(self, hex: bytearray) -> None:
        self.temp_high_alarm = bytes_to_i8(hex[0:1])
        self.temp_low_alarm = bytes_to_i8(hex[2:3])
        self.temp_high_warning = bytes_to_i8(hex[4:5])
        self.temp_low_warning = bytes_to_i8(hex[6:7])
        self.voltage_high_alarm = bytes_to_u16(hex[8:10])
        self.voltage_low_alarm = bytes_to_u16(hex[10:12])
        self.voltage_high_warning = bytes_to_u16(hex[12:14])
        self.voltage_low_warning = bytes_to_u16(hex[14:16])
        self.bias_high_alarm = bytes_to_u16(hex[16:18])
        self.bias_low_alarm = bytes_to_u16(hex[18:20])
        self.bias_high_warning = bytes_to_u16(hex[20:22])
        self.bias_low_warning = bytes_to_u16(hex[22:24])
        self.tx_power_high_alarm = bytes_to_u16(hex[24:26])
        self.tx_power_low_alarm = bytes_to_u16(hex[26:28])
        self.tx_power_high_warning = bytes_to_u16(hex[28:30])
        self.tx_power_low_warning = bytes_to_u16(hex[30:32])
        self.rx_power_high_alarm = bytes_to_u16(hex[32:34])
        self.rx_power_low_alarm = bytes_to_u16(hex[34:36])
        self.rx_power_high_warning = bytes_to_u16(hex[36:38])
        self.rx_power_low_warning = bytes_to_u16(hex[38:40])
        self.mac_address = hex[40:46]
        self.reserved_1 = hex[46:56]
        self.rx_power_4_cal = bytes_to_u32(hex[56:60])
        self.rx_power_3_cal = bytes_to_u32(hex[60:64])
        self.rx_power_2_cal = bytes_to_u32(hex[64:68])
        self.rx_power_1_cal = bytes_to_u32(hex[68:72])
        self.rx_power_0_cal = bytes_to_u32(hex[72:76])
        self.tx_bias_slope_cal = bytes_to_u16(hex[76:78])
        self.tx_bias_offset_cal = bytes_to_u16(hex[78:80])
        self.tx_power_slope_cal = bytes_to_u16(hex[80:82])
        self.tx_power_offset_cal = bytes_to_u16(hex[82:84])
        self.temperature_slope_cal = bytes_to_u16(hex[84:86])
        self.temperature_offset_cal = bytes_to_u16(hex[86:88])
        self.voltage_slope_cal = bytes_to_u16(hex[88:90])
        self.voltage_offset_cal = bytes_to_u16(hex[90:92])
        self.reserved_2 = hex[92:95]
        self.cc_dmi = bytes_to_u8(hex[95:96])
        self.temperature_msb = bytes_to_u8(hex[96:97])
        self.temperature_lsb = bytes_to_u8(hex[97:98])
        self.vcc_msb = bytes_to_u8(hex[98:99])
        self.vcc_lsb = bytes_to_u8(hex[99:100])
        self.tx_bias_msb = bytes_to_u8(hex[100:101])
        self.tx_bias_lsb = bytes_to_u8(hex[101:102])
        self.tx_power_msb = bytes_to_u8(hex[102:103])
        self.tx_power_lsb = bytes_to_u8(hex[103:104])
        self.rx_power_msb = bytes_to_u8(hex[104:105])
        self.rx_power_lsb = bytes_to_u8(hex[105:106])
        self.optional_diagnostics = hex[106:110]
        self.status_control = bytes_to_u8(hex[110:111])
        self.reserved_3 = hex[111:112]
        self.alarm_flags = bytes_to_u16(hex[112:114])
        self.tx_in_eq_control = bytes_to_u8(hex[114:115])
        self.rx_out_emph_control = bytes_to_u8(hex[115:116])
        self.warning_flags = bytes_to_u16(hex[116:118])
        self.ext_status_control = bytes_to_u16(hex[118:120])
        self.vendor_specific = hex[120:127]
        self.table_select = bytes_to_u8(hex[127:128])
        self.reserved_4 = hex[128:191]
        self.gpon_loid_ploam = hex[191:215]
        self.gpon_lpwd = hex[215:232]
        self.gpon_loid_ploam_switch = hex[232:233]
        self.gpon_serial_number = hex[233:241]
        self.reserved_5 = hex[241:248]
        self.vendor_control = hex[248:256]
        self.unknown_vendor_specific = hex[256:512]
        self.gpon_equipment_id = hex[512:532]
        self.gpon_vendor_id = hex[532:536]
        self.reserved_6 = hex[536:640]

    def hex_export(self) -> bytearray:
        hex = bytearray()
        hex += i8_to_bytes(self.temp_high_alarm) + b"\x00"
        hex += i8_to_bytes(self.temp_low_alarm) + b"\x00"
        hex += i8_to_bytes(self.temp_high_warning) + b"\x00"
        hex += i8_to_bytes(self.temp_low_warning) + b"\x00"
        hex += u16_to_bytes(self.voltage_high_alarm)
        hex += u16_to_bytes(self.voltage_low_alarm)
        hex += u16_to_bytes(self.voltage_high_warning)
        hex += u16_to_bytes(self.voltage_low_warning)
        hex += u16_to_bytes(self.bias_high_alarm)
        hex += u16_to_bytes(self.bias_low_alarm)
        hex += u16_to_bytes(self.bias_high_warning)
        hex += u16_to_bytes(self.bias_low_warning)
        hex += u16_to_bytes(self.tx_power_high_alarm)
        hex += u16_to_bytes(self.tx_power_low_alarm)
        hex += u16_to_bytes(self.tx_power_high_warning)
        hex += u16_to_bytes(self.tx_power_low_warning)
        hex += u16_to_bytes(self.rx_power_high_alarm)
        hex += u16_to_bytes(self.rx_power_low_alarm)
        hex += u16_to_bytes(self.rx_power_high_warning)
        hex += u16_to_bytes(self.rx_power_low_warning)
        hex += self.mac_address
        hex += self.reserved_1
        hex += u32_to_bytes(self.rx_power_4_cal)
        hex += u32_to_bytes(self.rx_power_3_cal)
        hex += u32_to_bytes(self.rx_power_2_cal)
        hex += u32_to_bytes(self.rx_power_1_cal)
        hex += u32_to_bytes(self.rx_power_0_cal)
        hex += u16_to_bytes(self.tx_bias_slope_cal)
        hex += u16_to_bytes(self.tx_bias_offset_cal)
        hex += u16_to_bytes(self.tx_power_slope_cal)
        hex += u16_to_bytes(self.tx_power_offset_cal)
        hex += u16_to_bytes(self.temperature_slope_cal)
        hex += u16_to_bytes(self.temperature_offset_cal)
        hex += u16_to_bytes(self.voltage_slope_cal)
        hex += u16_to_bytes(self.voltage_offset_cal)
        hex += self.reserved_2
        hex += u8_to_bytes(self.cc_dmi)
        hex += u8_to_bytes(self.temperature_msb)
        hex += u8_to_bytes(self.temperature_lsb)
        hex += u8_to_bytes(self.vcc_msb)
        hex += u8_to_bytes(self.vcc_lsb)
        hex += u8_to_bytes(self.tx_bias_msb)
        hex += u8_to_bytes(self.tx_bias_lsb)
        hex += u8_to_bytes(self.tx_power_msb)
        hex += u8_to_bytes(self.tx_power_lsb)
        hex += u8_to_bytes(self.rx_power_msb)
        hex += u8_to_bytes(self.rx_power_lsb)
        hex += self.optional_diagnostics
        hex += u8_to_bytes(self.status_control)
        hex += self.reserved_3
        hex += u16_to_bytes(self.alarm_flags)
        hex += u8_to_bytes(self.tx_in_eq_control)
        hex += u8_to_bytes(self.rx_out_emph_control)
        hex += u16_to_bytes(self.warning_flags)
        hex += u16_to_bytes(self.ext_status_control)
        hex += self.vendor_specific
        hex += u8_to_bytes(self.table_select)
        hex += self.reserved_4
        hex += self.gpon_loid_ploam
        hex += self.gpon_lpwd
        hex += self.gpon_loid_ploam_switch
        hex += self.gpon_serial_number
        hex += self.reserved_5
        hex += self.vendor_control
        hex += self.unknown_vendor_specific
        hex += self.gpon_equipment_id
        hex += self.gpon_vendor_id
        hex += self.reserved_6
        return hex

    def b64_encode(self, hex: bytearray = None) -> bytearray:
        if hex is None:
            hex = self.hex_export()

        b64 = base64.b64encode(hex)
        res = bytearray()
        res += B64_LINE_SEP_BYTES

        offset = 0
        for cur_byte in b64:
            if offset > 0 and offset % B64_LINE_LEN == 0:
                res += B64_LINE_SEP_BYTES

            res += bytearray([cur_byte])

            offset += 1

        res += B64_LINE_SEP_BYTES
        res += bytearray([ord("=")] * 4)
        res += B64_LINE_SEP_BYTES

        return res

    def set_gpon_equipment_id(self, gpon_equipment_id_str: str) -> None:
        gpon_equipment_id = str_to_bytes(gpon_equipment_id_str, GPON_EQUIPMENT_ID_LEN)

        self.gpon_equipment_id = gpon_equipment_id

    def set_gpon_loid(self, gpon_loid_str: str, gpon_lpwd_str: str | None) -> None:
        gpon_loid = str_to_bytes(gpon_loid_str, GPON_LOID_LEN)
        gpon_lpwd = str_to_bytes(gpon_lpwd_str, GPON_LPWD_LEN)

        self.gpon_loid_ploam = gpon_ploam
        self.gpon_lpwd = bytearray(GPON_LPWD_LEN)
        self.gpon_loid_ploam_switch = bytearray([GponAuth.PLOAM])

    def set_gpon_ploam(self, gpon_ploam_str: str) -> None:
        gpon_ploam = str_to_bytes(gpon_ploam_str, GPON_PLOAM_LEN)

        self.gpon_loid_ploam = gpon_ploam
        self.gpon_lpwd = bytearray(GPON_LPWD_LEN)
        self.gpon_loid_ploam_switch = bytearray([GponAuth.PLOAM])

    def set_gpon_serial(self, gpon_serial_str: str) -> None:
        gpon_serial = str_to_bytes(gpon_serial_str, GPON_SERIAL_LEN, StringType.SERIAL)

        self.gpon_serial_number = gpon_serial

    def set_gpon_vendor_id(self, gpon_vendor_id_str: str) -> None:
        gpon_vendor_id = str_to_bytes(gpon_vendor_id_str, GPON_VENDOR_ID_LEN)

        self.gpon_vendor_id = gpon_vendor_id

    def set_mac_address(self, mac_addr_str: str) -> None:
        mac_addr = str_to_bytes(mac_addr_str, GPON_MAC_LEN, StringType.MAC_ADDRESS)

        self.mac_address = mac_addr


EEPROM: EEPROM0 | EEPROM1 | None = None
EEPROM_INPUT_STR: str | None = None
OPT_ARGS: list[str]
OPT_OPTS: optparse.Values


_LOGGER = logging.getLogger(__name__)


def sfp_eeprom_dump(eeprom_hint: str) -> None:
    """Huawei MA5671a dump."""
    _LOGGER.warning("")
    _LOGGER.warning("*** EEPROM (%s) ***", eeprom_hint)
    _LOGGER.warning(EEPROM.data())


def sfp_eeprom_input() -> None:
    """SFP EEPROM input."""
    global EEPROM_INPUT_STR

    input_raw = None

    if OPT_OPTS.input is None:
        _LOGGER.error("Missing --input file name.")
        sys.exit(ExitCode.INPUT_FILE_NAME)

    input_opt = str(OPT_OPTS.input).strip()
    if input_opt.startswith(B64_LINE_SEP):
        input_raw = input_opt
    else:
        input_fn = input_opt
        with open(input_fn, "r") as input_fd:
            input_raw = input_fd.read()

    input_raw = input_raw.strip()
    input_offset = input_raw.find("@")
    if input_offset > 0:
        input_raw = input_raw[input_offset:]

    EEPROM_INPUT_STR = input_raw
    _LOGGER.warning("*** Input ***")
    _LOGGER.warning(input_raw)

    input_lines = input_raw.split("@")

    input_bytes = bytearray()
    input_hex = bytearray()
    for line_b64 in input_lines:
        line_bytes = base64.b64decode(line_b64)
        if len(line_bytes) > 0:
            input_bytes += line_bytes

            line_hex = binascii.hexlify(line_bytes)
            input_hex += line_hex

    _LOGGER.debug("*** Hex ***")
    _LOGGER.debug(input_hex)
    _LOGGER.debug("***")

    bytes_len = len(input_bytes)
    if bytes_len != EEPROM_LEN:
        _LOGGER.error("Invalid EEPROM length=%d", bytes_len)
        sys.exit(ExitCode.EEPROM_LEN)

    EEPROM.hex_import(input_bytes)

    sfp_eeprom_dump("input")


def sfp_eeprom_output() -> None:
    """SFP EEPROM output."""
    hex_export = EEPROM.hex_export()

    _LOGGER.debug("*** Hex ***")
    _LOGGER.debug("bytes=%d", len(hex_export))
    _LOGGER.debug(eeprom_to_hex(hex_export))
    _LOGGER.debug("***")

    b64_export = EEPROM.b64_encode(hex_export)
    b64_str = b64_export.decode()
    if b64_str == EEPROM_INPUT_STR:
        return

    sfp_eeprom_dump("output")

    b64_str = "begin-base64 644 sfp_a2_info " + b64_str

    _LOGGER.warning("")
    _LOGGER.warning("*** Output ***")
    _LOGGER.warning(b64_str)

    output_fn = OPT_OPTS.output
    if output_fn is not None:
        with open(output_fn, "w") as output_fd:
            output_fd.write(b64_str)


def sfp_eeprom_update() -> None:
    """SFP EEPROM update."""

    if OPT_OPTS.gpon_equipment_id is not None:
        EEPROM.set_gpon_equipment_id(OPT_OPTS.gpon_equipment_id)

    if OPT_OPTS.gpon_ploam is not None:
        EEPROM.set_gpon_ploam(OPT_OPTS.gpon_ploam)
    elif OPT_OPTS.gpon_loid is not None:
        EEPROM.set_gpon_loid(OPT_OPTS.gpon_loid, OPT_OPTS.gpon_lpwd)

    if OPT_OPTS.gpon_serial is not None:
        EEPROM.set_gpon_serial(OPT_OPTS.gpon_serial)

    if OPT_OPTS.gpon_vendor_id is not None:
        EEPROM.set_gpon_vendor_id(OPT_OPTS.gpon_vendor_id)

    if OPT_OPTS.mac_address is not None:
        EEPROM.set_mac_address(OPT_OPTS.mac_address)


def main() -> None:
    """Entry function."""
    global EEPROM, OPT_OPTS, OPT_ARGS

    parser = optparse.OptionParser()

    parser.add_option("-e", "--eeprom", default=1)
    parser.add_option("-i", "--input")
    parser.add_option("-o", "--output")

    parser.add_option("--gpon-equipment-id")
    parser.add_option("--gpon-loid")
    parser.add_option("--gpon-lpwd")
    parser.add_option("--gpon-ploam")
    parser.add_option("--gpon-serial")
    parser.add_option("--gpon-vendor-id")
    parser.add_option("--mac-address")

    OPT_OPTS, OPT_ARGS = parser.parse_args()

    if OPT_OPTS.eeprom == 1:
        EEPROM = EEPROM1()
    else:
        EEPROM = EEPROM0()

    sfp_eeprom_input()
    sfp_eeprom_update()
    sfp_eeprom_output()


if __name__ == "__main__":
    main()
