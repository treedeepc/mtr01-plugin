// 文件职责：验证 MTR01 官方插件配置、golden、流和错误边界。

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use leeway_mtr01_plugin::Mtr01PluginHandler;
use leeway_protocol_core::{ProtocolAdapter, ProtocolValue, ProtocolValues};
use leeway_protocol_mtr01::{
    MTR01_MESSAGE_A_DATA, MTR01_MESSAGE_A_SUBSCRIBE, MTR01_MESSAGE_B_BASIC_CONFIG,
    MTR01_MESSAGE_B_BASIC_FEEDBACK, MTR01_MESSAGE_B_DEVICE_INFO, MTR01_MESSAGE_B_GET_INFO,
    MTR01_MESSAGE_B_IDENTITY_CONFIG, MTR01_MESSAGE_B_IDENTITY_FEEDBACK,
    MTR01_MESSAGE_B_RUNTIME_CONFIG, MTR01_MESSAGE_B_RUNTIME_FEEDBACK,
    MTR01_MESSAGE_C_CONNECT_CONTROL, MTR01_MESSAGE_C_CONNECTION_FEEDBACK,
    MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND, MTR01_MESSAGE_C_SCAN_ERROR, MTR01_MESSAGE_C_SCAN_LIST,
    MTR01_MESSAGE_C_SCAN_REQUEST, Mtr01ARequest, Mtr01Adapter, Mtr01BasicConfig, Mtr01BatteryType,
    Mtr01BmsType, Mtr01CResponse, Mtr01Codec, Mtr01Command, Mtr01DeviceInfoV15,
    Mtr01IdentityConfig, Mtr01RuntimeConfig, Mtr01ScanList, Mtr01ScanSlot,
};
use leeway_protocol_plugin_abi::{PluginAbiStatus, ProtocolPluginHandler};
use leeway_protocol_plugin_contracts::{
    PluginConfigurationInput, PluginHostRequest, PluginHostResponse, PluginWireErrorCode,
    PluginWireValue,
};
use serde_json::{Value, json};

const BUNDLE_MANIFEST: &str = include_str!("../../bundle/Contents/Resources/plugin.json");
const BUNDLE_PROTOCOL: &str = include_str!("../../bundle/Contents/Resources/protocol.json");
const BUNDLE_SCENARIO: &str = include_str!("../../bundle/Contents/Resources/scenario.json");
const BUNDLE_CONFIGURATION: &str =
    include_str!("../../bundle/Contents/Resources/configuration.json");

const TEST_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const REPORT_HEX: &str = "40014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0157002885ffc0ff01004101d0070100";

fn bytes_value(bytes: &[u8]) -> PluginWireValue {
    PluginWireValue::Bytes {
        base64: STANDARD.encode(bytes),
    }
}
fn create(handler: &Mtr01PluginHandler, key: [u8; 16]) -> u64 {
    let response = handler
        .handle(&PluginHostRequest::Create {
            id: 1,
            abi_version: 1,
            config: PluginConfigurationInput::from_values(BTreeMap::from([(
                "cmacKey".into(),
                bytes_value(key.as_slice()),
            )])),
        })
        .expect("create response");
    success_result(response)["handle"].as_u64().expect("handle")
}

fn success_result(response: PluginHostResponse) -> Value {
    assert!(response.ok, "unexpected failure: {response:?}");
    response.result.expect("result")
}

fn failure_code(response: PluginHostResponse) -> PluginWireErrorCode {
    assert!(!response.ok);
    response.error.expect("error").code
}

fn encode(handler: &Mtr01PluginHandler, handle: u64, message_id: &str, payload: &[u8]) -> Vec<u8> {
    let response = handler
        .handle(&PluginHostRequest::Encode {
            id: 2,
            abi_version: 1,
            handle,
            message_id: message_id.into(),
            values: BTreeMap::from([("payload".into(), bytes_value(payload))]),
        })
        .expect("encode response");
    let result = success_result(response);
    let frame = result["frameBase64"].as_str().expect("frame");
    STANDARD.decode(frame).expect("frame base64")
}

fn decode(handler: &Mtr01PluginHandler, handle: u64, frame: &[u8]) -> (String, Vec<u8>) {
    let response = handler
        .handle(&PluginHostRequest::Decode {
            id: 3,
            abi_version: 1,
            handle,
            frame_base64: STANDARD.encode(frame),
        })
        .expect("decode response");
    let result = success_result(response);
    let message_id = result["messageId"].as_str().expect("message id").to_owned();
    let payload = result["values"]["payload"]["base64"]
        .as_str()
        .expect("payload")
        .to_owned();
    (
        message_id,
        STANDARD.decode(payload).expect("payload base64"),
    )
}

#[test]
fn creates_instance_requires_16_byte_key_and_redacts_debug() {
    let handler = Mtr01PluginHandler::new();
    let missing = handler
        .handle(&PluginHostRequest::Create {
            id: 1,
            abi_version: 1,
            config: PluginConfigurationInput::empty(),
        })
        .expect("response");
    assert_eq!(
        failure_code(missing),
        PluginWireErrorCode::ConfigurationRequired
    );
    let invalid = handler
        .handle(&PluginHostRequest::Create {
            id: 2,
            abi_version: 1,
            config: PluginConfigurationInput::from_values(BTreeMap::from([(
                "cmacKey".into(),
                bytes_value(&[0; 15]),
            )])),
        })
        .expect("response");
    assert_eq!(
        failure_code(invalid),
        PluginWireErrorCode::ConfigurationInvalid
    );

    let handle = create(&handler, TEST_KEY);
    assert!(handle > 0);
    let debug = format!("{handler:?}");
    assert!(!debug.contains(&hex::encode(TEST_KEY)));
    assert!(!debug.contains("2b7e151628aed2a6"));
}

#[test]
fn encodes_and_decodes_a_request_and_a_data_like_static_adapter() {
    let handler = Mtr01PluginHandler::new();
    let handle = create(&handler, TEST_KEY);
    let adapter = Mtr01Adapter::new(TEST_KEY);
    let subscribe_payload = Mtr01ARequest::Subscribe.to_payload();
    let static_request = adapter
        .encode(
            MTR01_MESSAGE_A_SUBSCRIBE,
            &ProtocolValues::from([(
                "payload".into(),
                ProtocolValue::Bytes(subscribe_payload.to_vec()),
            )]),
        )
        .expect("static request");
    let plugin_request = encode(
        &handler,
        handle,
        MTR01_MESSAGE_A_SUBSCRIBE,
        &subscribe_payload,
    );
    assert_eq!(plugin_request, static_request);
    assert_eq!(
        hex::encode(&plugin_request),
        "54435a51412301017a3af721601594eb5fd36a1a7b4a22c0"
    );
    assert_eq!(
        decode(&handler, handle, &plugin_request),
        (MTR01_MESSAGE_A_SUBSCRIBE.into(), subscribe_payload.to_vec())
    );

    let report = hex::decode(REPORT_HEX).expect("report");
    let static_data = adapter
        .encode(
            MTR01_MESSAGE_A_DATA,
            &ProtocolValues::from([("payload".into(), ProtocolValue::Bytes(report.clone()))]),
        )
        .expect("static data");
    let plugin_data = encode(&handler, handle, MTR01_MESSAGE_A_DATA, &report);
    assert_eq!(plugin_data, static_data);
    assert_eq!(
        decode(&handler, handle, &plugin_data),
        (MTR01_MESSAGE_A_DATA.into(), report)
    );
}

#[test]
fn stream_reassembles_split_mtr01_frames() {
    let handler = Mtr01PluginHandler::new();
    let handle = create(&handler, TEST_KEY);
    let adapter = Mtr01Adapter::new(TEST_KEY);
    let report = hex::decode(REPORT_HEX).expect("report");
    let frame = adapter
        .encode(
            MTR01_MESSAGE_A_DATA,
            &ProtocolValues::from([("payload".into(), ProtocolValue::Bytes(report))]),
        )
        .expect("frame");
    let stream_handle = success_result(
        handler
            .handle(&PluginHostRequest::StreamCreate {
                id: 4,
                abi_version: 1,
                handle,
            })
            .expect("stream create"),
    )["streamHandle"]
        .as_u64()
        .expect("stream handle");

    let first = handler
        .handle(&PluginHostRequest::StreamPush {
            id: 5,
            abi_version: 1,
            stream_handle,
            bytes_base64: STANDARD.encode(&frame[..17]),
        })
        .expect("first push");
    assert!(
        success_result(first)["framesBase64"]
            .as_array()
            .expect("frames")
            .is_empty()
    );
    let second = handler
        .handle(&PluginHostRequest::StreamPush {
            id: 6,
            abi_version: 1,
            stream_handle,
            bytes_base64: STANDARD.encode(&frame[17..]),
        })
        .expect("second push");
    assert_eq!(
        success_result(second)["framesBase64"],
        json!([STANDARD.encode(&frame)])
    );
    handler
        .handle(&PluginHostRequest::StreamDestroy {
            id: 7,
            abi_version: 1,
            stream_handle,
        })
        .expect("stream destroy");
}

#[test]
fn v151_b_and_c_messages_match_shared_adapter() {
    let handler = Mtr01PluginHandler::new();
    let handle = create(&handler, TEST_KEY);
    let adapter = Mtr01Adapter::new(TEST_KEY);
    let scan_list = Mtr01CResponse::ScanList(Mtr01ScanList {
        slots: std::array::from_fn(|_| Mtr01ScanSlot::Empty),
    })
    .to_payload()
    .expect("scan list");
    let requests = [
        (MTR01_MESSAGE_B_GET_INFO, vec![0x00]),
        (
            MTR01_MESSAGE_B_BASIC_CONFIG,
            Mtr01BasicConfig {
                bms_type: Mtr01BmsType::Jbd,
                battery_type: Mtr01BatteryType::TernaryLithium,
                baud_rate: 115_200,
                vehicle_protocol: "RS".into(),
                vehicle_brand: "NIU".into(),
            }
            .to_payload()
            .expect("basic config"),
        ),
        (
            MTR01_MESSAGE_B_RUNTIME_CONFIG,
            Mtr01RuntimeConfig {
                rated_capacity_10mah: 2_000,
                cell_count: 16,
                consumption_wh_per_100km: 2_500,
                ocv_raw: [0xEF; 42],
            }
            .to_payload(),
        ),
        (
            MTR01_MESSAGE_B_IDENTITY_CONFIG,
            Mtr01IdentityConfig {
                serial_number: "BMS202611050001".into(),
                national_code: "GB-001".into(),
            }
            .to_payload()
            .expect("identity"),
        ),
        (MTR01_MESSAGE_C_SCAN_REQUEST, vec![0x01]),
        (
            MTR01_MESSAGE_C_CONNECT_CONTROL,
            vec![0x02, 0x01, 0x01, 1, 2, 3, 4, 5, 6],
        ),
        (
            MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND,
            vec![0x02, 0x03, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF],
        ),
        (MTR01_MESSAGE_C_SCAN_ERROR, vec![0x01, 0x02]),
        (MTR01_MESSAGE_C_SCAN_LIST, scan_list),
    ];
    for (message_id, payload) in requests {
        let plugin_frame = encode(&handler, handle, message_id, &payload);
        let static_frame = adapter
            .encode(
                message_id,
                &ProtocolValues::from([("payload".into(), ProtocolValue::Bytes(payload.clone()))]),
            )
            .expect("static frame");
        assert_eq!(plugin_frame, static_frame);
        assert_eq!(
            decode(&handler, handle, &plugin_frame),
            (message_id.into(), payload)
        );
    }

    let responses = [
        (
            MTR01_MESSAGE_B_DEVICE_INFO,
            Mtr01DeviceInfoV15 {
                device_name: "MTR01SIM".into(),
                serial_number: "BMS202611050001".into(),
                software_version: "1.5.1".into(),
                hardware_version: "1".into(),
                basic_config: Mtr01BasicConfig {
                    bms_type: Mtr01BmsType::Jbd,
                    battery_type: Mtr01BatteryType::TernaryLithium,
                    baud_rate: 115_200,
                    vehicle_protocol: "RS".into(),
                    vehicle_brand: "NIU".into(),
                },
                runtime_config: Mtr01RuntimeConfig {
                    rated_capacity_10mah: 2_000,
                    cell_count: 16,
                    consumption_wh_per_100km: 2_500,
                    ocv_raw: [0xEF; 42],
                },
            }
            .to_payload()
            .expect("device info"),
        ),
        (MTR01_MESSAGE_B_BASIC_FEEDBACK, vec![0x01, 0x02]),
        (MTR01_MESSAGE_B_RUNTIME_FEEDBACK, vec![0x02, 0x02]),
        (MTR01_MESSAGE_B_IDENTITY_FEEDBACK, vec![0x03, 0x00]),
        (MTR01_MESSAGE_C_CONNECTION_FEEDBACK, vec![0x02, 0x01]),
    ];
    for (message_id, payload) in responses {
        let plugin_frame = encode(&handler, handle, message_id, &payload);
        assert_eq!(
            decode(&handler, handle, &plugin_frame),
            (message_id.into(), payload)
        );
    }
}

#[test]
fn v151_rejects_mismatched_message_payloads_recoverably() {
    let handler = Mtr01PluginHandler::new();
    let handle = create(&handler, TEST_KEY);
    let response = handler
        .handle(&PluginHostRequest::Encode {
            id: 20,
            abi_version: 1,
            handle,
            message_id: MTR01_MESSAGE_C_SCAN_ERROR.into(),
            values: BTreeMap::from([("payload".into(), bytes_value(&[0x02, 0x01]))]),
        })
        .expect("encode response");
    assert_eq!(
        failure_code(response),
        PluginWireErrorCode::InvalidFieldValue
    );
    let disconnect = handler
        .handle(&PluginHostRequest::Encode {
            id: 21,
            abi_version: 1,
            handle,
            message_id: MTR01_MESSAGE_C_CONNECT_CONTROL.into(),
            values: BTreeMap::from([(
                "payload".into(),
                bytes_value(&[0x02, 0x03, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF]),
            )]),
        })
        .expect("disconnect routing response");
    assert_eq!(
        failure_code(disconnect),
        PluginWireErrorCode::InvalidFieldValue
    );

    let adapter = Mtr01Adapter::new(TEST_KEY);
    let frame = adapter.encode(
        MTR01_MESSAGE_A_DATA,
        &ProtocolValues::from([(
            "payload".into(),
            ProtocolValue::Bytes(
                hex::decode(REPORT_HEX)
                    .expect("report")
                    .into_iter()
                    .take(88)
                    .collect(),
            ),
        )]),
    );
    assert!(frame.is_err());
}

#[test]
fn wrong_key_and_tampering_return_recoverable_checksum_errors() {
    let handler = Mtr01PluginHandler::new();
    let handle = create(&handler, TEST_KEY);
    let wrong = Mtr01Codec::new([0; 16])
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::Subscribe.to_payload(),
        )
        .expect("wrong-key frame");
    let wrong_response = handler
        .handle(&PluginHostRequest::Decode {
            id: 8,
            abi_version: 1,
            handle,
            frame_base64: STANDARD.encode(wrong),
        })
        .expect("wrong key response");
    assert_eq!(
        failure_code(wrong_response),
        PluginWireErrorCode::ChecksumMismatch
    );

    let mut tampered = Mtr01Codec::new(TEST_KEY)
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::Subscribe.to_payload(),
        )
        .expect("valid frame");
    tampered[7] ^= 1;
    let tampered_response = handler
        .handle(&PluginHostRequest::Decode {
            id: 9,
            abi_version: 1,
            handle,
            frame_base64: STANDARD.encode(tampered),
        })
        .expect("tampered response");
    assert_eq!(
        failure_code(tampered_response),
        PluginWireErrorCode::ChecksumMismatch
    );
}

#[test]
fn rejects_wrong_abi_and_unknown_handle_as_recoverable_errors() {
    let handler = Mtr01PluginHandler::new();
    assert_eq!(
        handler
            .handle(&PluginHostRequest::Describe {
                id: 1,
                abi_version: 2,
            })
            .expect_err("ABI mismatch"),
        PluginAbiStatus::AbiMismatch
    );
    let response = handler
        .handle(&PluginHostRequest::Encode {
            id: 2,
            abi_version: 1,
            handle: 999,
            message_id: MTR01_MESSAGE_A_SUBSCRIBE.into(),
            values: BTreeMap::from([(
                "payload".into(),
                bytes_value(&Mtr01ARequest::Subscribe.to_payload()),
            )]),
        })
        .expect("unknown handle response");
    assert_eq!(failure_code(response), PluginWireErrorCode::InvalidRequest);
}

#[test]
fn example_bundle_metadata_matches_runtime_contract() {
    let manifest: Value = serde_json::from_str(BUNDLE_MANIFEST).expect("manifest JSON");
    assert_eq!(manifest["pluginId"], "com.leeway.mtr01");
    assert_eq!(manifest["abiVersion"], 1);
    assert_eq!(manifest["protocolId"], "mtr01-protocol");
    assert_eq!(manifest["protocolVersion"], "1.5.1");

    let protocol: Value = serde_json::from_str(BUNDLE_PROTOCOL).expect("protocol JSON");
    assert_eq!(protocol, Mtr01Adapter::new([0; 16]).definition());
    let device_info = protocol["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|message| message["id"] == "bDeviceInfo")
        .expect("bDeviceInfo");
    assert_eq!(device_info["payload"]["endianness"], "little");
    assert_eq!(protocol["bleProfile"]["id"], "mtr01");
    assert_eq!(protocol["bleProfile"]["name"], "MTR01");
    assert_eq!(protocol["bleProfile"]["advertisementUuid"], "AAA0");
    assert_eq!(protocol["bleProfile"]["notificationChunkBytes"], 244);

    let scenario: Value = serde_json::from_str(BUNDLE_SCENARIO).expect("scenario JSON");
    assert_eq!(scenario["scenarioId"], "mtr01-sim");
    assert_eq!(scenario["name"], "MTR01 Simulator");
    assert_eq!(scenario["protocolId"], "mtr01-protocol");
    assert_eq!(scenario["protocolVersion"], "1.5.1");
    for (variable, expected_bytes) in [("report", 89), ("deviceInfo", 113), ("scanList", 212)] {
        let bytes = hex::decode(
            scenario["initialState"][variable]["hex"]
                .as_str()
                .expect("scenario bytes"),
        )
        .expect("scenario hex");
        assert_eq!(bytes.len(), expected_bytes, "{variable}");
    }
    let editable_fields = scenario["editableFields"]["fields"]
        .as_array()
        .expect("editable fields");
    assert_eq!(editable_fields.len(), 26);
    for field_id in [
        "stateOfChargePercent",
        "mosTemperatureDeciCelsius",
        "totalVoltage10mV",
        "currentCentiamps",
        "powerWatts",
        "cycleCount",
    ] {
        let field = editable_fields
            .iter()
            .find(|field| field["id"] == field_id)
            .unwrap_or_else(|| panic!("missing editable field {field_id}"));
        assert_eq!(field["target"]["messageId"], "aData");
        assert_eq!(field["target"]["variable"], "report");
        assert!(field["label"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(
            field["localizedLabels"]["zh-Hans"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert!(field["unit"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(
            field["localizedUnits"]["zh-Hans"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }
    for field_id in [
        "deviceName",
        "serialNumber",
        "softwareVersion",
        "hardwareVersion",
        "bmsType",
        "batteryType",
        "baudRate",
        "vehicleProtocol",
        "vehicleBrand",
        "deviceRatedCapacity10mAh",
        "cellCount",
        "consumptionWhPer100km",
        "ocvRaw",
        "cellVoltages10mV",
        "temperaturesDeciCelsius",
        "dischargeState",
        "chargeState",
        "ratedCapacity10mAh",
        "dataSource",
        "faultCode",
    ] {
        assert!(
            editable_fields
                .iter()
                .any(|field| field["id"] == field_id),
            "missing complete field {field_id}"
        );
    }
    let collections = scenario["editableCollections"]["collections"]
        .as_array()
        .expect("editable collections");
    assert_eq!(collections.len(), 1);
    let bms_devices = &collections[0];
    assert_eq!(bms_devices["id"], "bmsDevices");
    assert_eq!(bms_devices["target"]["messageId"], "cScanList");
    assert_eq!(bms_devices["target"]["fieldId"], "scanSlots");
    assert_eq!(
        bms_devices["columns"]
            .as_array()
            .expect("collection columns")
            .len(),
        4
    );
    assert_eq!(
        bms_devices["itemPolicy"]["emptyItemHex"]
            .as_str()
            .expect("empty item")
            .len()
            / 2,
        30
    );
    let functions = scenario["deviceFunctions"]["functions"]
        .as_array()
        .expect("device functions");
    for function_id in [
        "configureBms",
        "connectOnceBms",
        "bindAndConnectBms",
        "disconnectBms",
    ] {
        assert!(
            functions
                .iter()
                .any(|function| function["id"] == function_id),
            "missing device function {function_id}"
        );
    }

    let configuration: Value =
        serde_json::from_str(BUNDLE_CONFIGURATION).expect("configuration JSON");
    assert_eq!(configuration["schemaVersion"], 1);
    assert_eq!(configuration["fields"][0]["id"], "cmacKey");
    assert_eq!(configuration["fields"][0]["type"], "secretBytes");
    assert_eq!(configuration["fields"][0]["encoding"], "hex");
    assert_eq!(configuration["fields"][0]["length"], 16);
    assert_eq!(configuration["fields"][0]["required"], true);
    assert_eq!(configuration["fields"][0]["label"], "AES-CMAC key");
    assert_eq!(
        configuration["fields"][0]["localizedLabels"]["zh-Hans"],
        "AES-CMAC 密钥"
    );
}
