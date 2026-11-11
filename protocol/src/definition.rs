//
//  definition.rs
//  leeway-protocol-mtr01
//
//  文件职责：提供不包含 AES-CMAC 密钥的完整 MTR01 声明式协议定义。
//

use serde_json::{Value, json};

/// 返回 MTR01 V1.5 的完整协议结构。
#[allow(
    clippy::too_many_lines,
    reason = "固定协议定义需要完整列出全部 A/B/C/D 消息"
)]
pub(crate) fn protocol_definition() -> Value {
    json!({
        "schemaVersion": 1,
        "definitionKind": "native",
        "protocolId": "mtr01-protocol",
        "protocolVersion": "1.5",
        "name": "MTR01 Metering Protocol",
        "framing": {
            "kind": "fixedHeaderLengthPrefixed",
            "headerHex": "54435a51",
            "headerAscii": "TCZQ",
            "commandBytes": 2,
            "lengthBytes": 1,
            "lengthIncludesPayload": true,
            "checksum": {
                "kind": "aesCmac",
                "bytes": 16,
                "coverage": "beforeChecksum",
                "placement": "append",
                "keySource": "outOfBand"
            },
            "maxPayloadBytes": 255,
            "maxFrameBytes": 278
        },
        "bleProfile": {
            "id": "mtr01",
            "name": "MTR01",
            "serviceUuid": "0000AAA0-0000-1000-8000-00805F9B34FB",
            "advertisementUuid": "AAA0",
            "rxUuid": "0000AAA2-0000-1000-8000-00805F9B34FB",
            "txUuid": "0000AAA1-0000-1000-8000-00805F9B34FB",
            "notificationChunkBytes": 244
        },
        "messages": [
            {
                "id": "aSubscribe",
                "command": "A#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"01": "subscribe"}
                }
            },
            {
                "id": "aUnsubscribe",
                "command": "A#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"02": "unsubscribe"}
                }
            },
            {
                "id": "aOnce",
                "command": "A#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"03": "readOnce"}
                }
            },
            {
                "id": "aData",
                "command": "A@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 88,
                    "endianness": "little",
                    "fields": [
                        {"name": "cellVoltage10mV", "type": "u16[32]", "offsetBytes": 0, "unit": "10mV"},
                        {"name": "temperatureDeciCelsius", "type": "u16[4]", "offsetBytes": 64, "unit": "0.1C"},
                        {"name": "mosTemperatureDeciCelsius", "type": "u16", "offsetBytes": 72, "unit": "0.1C"},
                        {"name": "stateOfChargePercent", "type": "u8", "offsetBytes": 74, "unit": "percent"},
                        {"name": "totalVoltage10mV", "type": "u16", "offsetBytes": 75, "unit": "10mV"},
                        {"name": "currentCentiamps", "type": "i16", "offsetBytes": 77, "unit": "0.01A"},
                        {"name": "powerWatts", "type": "i16", "offsetBytes": 79, "unit": "W"},
                        {"name": "dischargeState", "type": "u8", "offsetBytes": 81},
                        {"name": "chargeState", "type": "u8", "offsetBytes": 82},
                        {"name": "cycleCount", "type": "u16", "offsetBytes": 83},
                        {"name": "ratedCapacity10mAh", "type": "u16", "offsetBytes": 85, "unit": "10mAh"},
                        {"name": "dataSource", "type": "u8", "offsetBytes": 87, "values": {
                            "01": "localEstimate",
                            "02": "bmsTwin"
                        }}
                    ]
                }
            },
            {
                "id": "bGetInfo",
                "command": "B#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"00": "getDeviceInfo"}
                }
            },
            {
                "id": "bBasicConfig",
                "command": "B#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 13,
                    "fields": [
                        {"name": "cmd", "type": "u8", "offsetBytes": 0, "constantHex": "01"},
                        {"name": "bmsType", "type": "u8", "offsetBytes": 1, "values": {
                            "01": "atnDash",
                            "02": "atnAt",
                            "03": "jbd",
                            "04": "jk",
                            "05": "yy"
                        }},
                        {"name": "batteryType", "type": "u8", "offsetBytes": 2, "values": {
                            "01": "ternaryLithium",
                            "02": "lithiumIronPhosphate",
                            "03": "leadAcid"
                        }},
                        {"name": "baudRate", "type": "u24be", "offsetBytes": 3},
                        {"name": "vehicleProtocol", "type": "ascii[2]", "offsetBytes": 6, "values": {
                            "RS": "rs485",
                            "1W": "oneWire"
                        }},
                        {"name": "vehicleBrand", "type": "ascii[5]", "offsetBytes": 8, "padding": "leftWithDelimiter"}
                    ]
                }
            },
            {
                "id": "bRuntimeConfig",
                "command": "B#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 48,
                    "endianness": "little",
                    "fields": [
                        {"name": "cmd", "type": "u8", "offsetBytes": 0, "constantHex": "02"},
                        {"name": "ratedCapacity10mAh", "type": "u16", "offsetBytes": 1, "unit": "10mAh"},
                        {"name": "cellCount", "type": "u8", "offsetBytes": 3},
                        {"name": "consumptionWhPer100km", "type": "u16", "offsetBytes": 4, "unit": "Wh/100km"},
                        {"name": "ocvRaw", "type": "bytes[42]", "offsetBytes": 6, "unit": "1mV", "unconfiguredHex": "ef"}
                    ]
                }
            },
            {
                "id": "bIdentityConfig",
                "command": "B#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "delimitedAscii",
                    "delimiterHex": "ef",
                    "fields": [
                        {"name": "cmd", "encoding": "ascii", "constantHex": "03"},
                        {"name": "serialNumber", "encoding": "ascii", "minBytes": 12, "maxBytes": 32},
                        {"name": "nationalCode", "encoding": "ascii", "minBytes": 0}
                    ]
                }
            },
            {
                "id": "bCalibrationControl",
                "command": "B#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {
                        "0401": "voltageCalibration",
                        "0402": "currentCalibration",
                        "0403": "deviceRestart"
                    }
                }
            },
            {
                "id": "bDeviceInfo",
                "command": "B@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 54,
                    "fields": [
                        {"name": "cmd", "type": "u8", "offsetBytes": 0, "constantHex": "00"},
                        {"name": "deviceName", "type": "ascii[10]", "offsetBytes": 1, "padding": "leftWithDelimiter"},
                        {"name": "serialNumber", "type": "ascii[32]", "offsetBytes": 11, "padding": "leftWithDelimiter"},
                        {"name": "softwareVersion", "type": "ascii[6]", "offsetBytes": 43, "padding": "leftWithDelimiter"},
                        {"name": "hardwareVersion", "type": "ascii[5]", "offsetBytes": 49, "padding": "leftWithDelimiter"}
                    ]
                }
            },
            {
                "id": "bBasicConfigFeedback",
                "command": "B@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {
                        "0100": "ok",
                        "0101": "brandProtocolMismatch",
                        "0102": "baudRateBrandMismatch"
                    }
                }
            },
            {
                "id": "bRuntimeConfigFeedback",
                "command": "B@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {
                        "0200": "ok",
                        "0201": "ocvNotConfigured",
                        "0202": "ocvCurveInvalidApplied"
                    }
                }
            },
            {
                "id": "bIdentityConfigFeedback",
                "command": "B@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {"0300": "ok"}
                }
            },
            {
                "id": "cScanRequest",
                "command": "C#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"01": "scanRequest"}
                }
            },
            {
                "id": "cConnectControl",
                "command": "C#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 9,
                    "fields": [
                        {"name": "cmd", "type": "u8", "offsetBytes": 0, "constantHex": "02"},
                        {"name": "control", "type": "u8", "offsetBytes": 1, "values": {
                            "01": "connectOnce",
                            "02": "bindAndAutoConnect"
                        }},
                        {"name": "addressType", "type": "u8", "offsetBytes": 2},
                        {"name": "address", "type": "bytes[6]", "offsetBytes": 3}
                    ]
                }
            },
            {
                "id": "cDisconnectAndUnbind",
                "command": "C#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 9,
                    "values": {"0203efefefefefefefef": "disconnectAndUnbind"}
                }
            },
            {
                "id": "cConnectionFeedback",
                "command": "C@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {
                        "0101": "connected",
                        "0102": "connectionFailed"
                    }
                }
            },
            {
                "id": "cScanList",
                "command": "C@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 219,
                    "fields": [
                        {"name": "cmd", "type": "u8", "offsetBytes": 0, "constantHex": "02"},
                        {"name": "result", "type": "u8", "offsetBytes": 1, "constantHex": "01"},
                        {"name": "scanSlots", "type": "scanSlot[7]", "offsetBytes": 2, "slotBytes": 31, "slotLayout": {
                            "delimiter": {"offsetBytes": 0, "constantHex": "ef"},
                            "name": {"offsetBytes": 1, "type": "ascii[22]", "padding": "leftWithDelimiter"},
                            "addressType": {"offsetBytes": 23, "type": "u8"},
                            "address": {"offsetBytes": 24, "type": "bytes[6]"},
                            "rssi": {"offsetBytes": 30, "type": "i8"}
                        }}
                    ]
                }
            },
            {
                "id": "cScanError",
                "command": "C@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {"0202": "scanError"}
                }
            },
            {
                "id": "dUnbound",
                "command": "D#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 1,
                    "values": {"01": "unbound"}
                }
            },
            {
                "id": "dBound",
                "command": "D#",
                "direction": "centralToDevice",
                "payload": {
                    "kind": "fixedLayout",
                    "lengthBytes": 18,
                    "fields": [
                        {"name": "status", "type": "u8", "offsetBytes": 0, "values": {"02": "bound", "03": "bindingConfiguration"}},
                        {"name": "delimiter", "type": "u8", "offsetBytes": 1, "constantHex": "ef"},
                        {"name": "bindingCode", "type": "bytes[16]", "offsetBytes": 2}
                    ]
                }
            },
            {
                "id": "dResponse",
                "command": "D@",
                "direction": "deviceToCentral",
                "payload": {
                    "kind": "fixedBytes",
                    "lengthBytes": 2,
                    "values": {
                        "0001": "confirmIdentity",
                        "0101": "bindingRecorded",
                        "0201": "rejectedIdentity"
                    }
                }
            }
        ],
        "testVectors": []
    })
}
