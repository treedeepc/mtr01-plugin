//
//  mtr01_tests.rs
//  leeway-protocol-mtr01 / tests
//
//  文件职责：验证 MTR01 V1.5.1 帧、流式分片和 A/B/C/D 业务载荷黄金行为。
//

use leeway_protocol_core::AesCmacKey;
use leeway_protocol_core::checksum::aes_cmac;
use leeway_protocol_core::{ProtocolAdapter, ProtocolValue, ProtocolValues};
use leeway_protocol_mtr01::{
    MTR01_MAX_FRAME_BYTES, MTR01_MESSAGE_A_DATA, MTR01_MESSAGE_B_BASIC_CONFIG,
    MTR01_MESSAGE_B_BASIC_FEEDBACK, MTR01_MESSAGE_B_DEVICE_INFO, MTR01_MESSAGE_B_GET_INFO,
    MTR01_MESSAGE_B_IDENTITY_CONFIG, MTR01_MESSAGE_B_IDENTITY_FEEDBACK,
    MTR01_MESSAGE_B_RUNTIME_CONFIG, MTR01_MESSAGE_B_RUNTIME_FEEDBACK,
    MTR01_MESSAGE_C_CONNECT_CONTROL, MTR01_MESSAGE_C_CONNECTION_FEEDBACK,
    MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND, MTR01_MESSAGE_C_SCAN_ERROR, MTR01_MESSAGE_C_SCAN_LIST,
    MTR01_MESSAGE_C_SCAN_REQUEST, MTR01_NOTIFICATION_BYTES, Mtr01AData, Mtr01ARequest,
    Mtr01Adapter, Mtr01BFeedback, Mtr01BRequest, Mtr01BResponse, Mtr01BasicConfig,
    Mtr01BatteryType, Mtr01BindingRequest, Mtr01BindingResponse, Mtr01BmsType, Mtr01CRequest,
    Mtr01CResponse, Mtr01CalibrationControl, Mtr01Codec, Mtr01Command, Mtr01ConnectControl,
    Mtr01ConnectionFeedback, Mtr01DeviceInfoV15, Mtr01Error, Mtr01IdentityConfig,
    Mtr01RuntimeConfig, Mtr01ScanList, Mtr01ScanSlot, Mtr01StreamDecoder,
};

const TEST_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

const REPORT_HEX: &str = "40014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0157002885ffc0ff01004101d0070100";
const REPORT_FRAME_HEX: &str = "54435a5141405940014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0157002885ffc0ff01004101d0070100e0a6915cfd5c960f13b09b2c376488e3";

fn adapter_values(payload: &[u8]) -> ProtocolValues {
    ProtocolValues::from([("payload".into(), ProtocolValue::Bytes(payload.to_vec()))])
}

/// 验证固定 A# 帧黄金字节与 V1.4 保持一致。
#[test]
fn encodes_golden_a_request_frame() {
    let authenticated = hex::decode("54435a5141230101").expect("hex");
    assert_eq!(
        hex::encode(
            aes_cmac(&AesCmacKey::new(TEST_KEY), &authenticated)
                .expect("AES-CMAC key is fixed width"),
        ),
        "7a3af721601594eb5fd36a1a7b4a22c0"
    );
    let frame = Mtr01Codec::new(TEST_KEY)
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::Subscribe.to_payload(),
        )
        .expect("encode");
    assert_eq!(
        hex::encode(&frame),
        "54435a51412301017a3af721601594eb5fd36a1a7b4a22c0"
    );
    let decoded = Mtr01Codec::new(TEST_KEY).decode(&frame).expect("decode");
    assert_eq!(decoded.command, Mtr01Command::ARequest);
    assert_eq!(
        Mtr01ARequest::from_payload(&decoded.payload).expect("payload"),
        Mtr01ARequest::Subscribe
    );
}

/// 验证 V1.5.1 A@ 89 字节黄金帧及数据来源和故障码字段。
#[test]
fn encodes_golden_v151_realtime_data_frame() {
    let payload = hex::decode(REPORT_HEX).expect("report");
    let report = Mtr01AData::from_payload(&payload).expect("decode payload");
    assert_eq!(payload.len(), 89);
    assert_eq!(report.state_of_charge_percent, 87);
    assert_eq!(report.data_source, 0x01);
    assert_eq!(report.fault_code, 0x00);
    assert_eq!(report.to_payload(), payload);

    let frame = Mtr01Codec::new(TEST_KEY)
        .encode(Mtr01Command::AResponse, &payload)
        .expect("encode frame");
    assert_eq!(hex::encode(frame), REPORT_FRAME_HEX);

    let adapter = Mtr01Adapter::new(TEST_KEY);
    let decoded = adapter
        .decode(&hex::decode(REPORT_FRAME_HEX).expect("golden frame"))
        .expect("adapter decode");
    assert_eq!(decoded.message_id, MTR01_MESSAGE_A_DATA);
    assert_eq!(decoded.values, adapter_values(&payload));
}

/// 验证错误数据来源、故障码和旧 88 字节报文被拒绝。
#[test]
fn rejects_old_or_invalid_realtime_data_payloads() {
    let mut payload = hex::decode(REPORT_HEX).expect("report");
    payload.pop();
    assert_eq!(
        Mtr01AData::from_payload(&payload),
        Err(Mtr01Error::InvalidPayloadLength)
    );

    let mut payload = hex::decode(REPORT_HEX).expect("report");
    payload[87] = 0x03;
    assert_eq!(
        Mtr01AData::from_payload(&payload),
        Err(Mtr01Error::UnsupportedValue)
    );

    let mut payload = hex::decode(REPORT_HEX).expect("report");
    payload[88] = 0x03;
    assert_eq!(
        Mtr01AData::from_payload(&payload),
        Err(Mtr01Error::UnsupportedValue)
    );
}

/// 验证错误密钥和篡改帧不能通过认证。
#[test]
fn rejects_wrong_key_and_tampering() {
    let frame = Mtr01Codec::new(TEST_KEY)
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::ReadOnce.to_payload(),
        )
        .expect("encode");
    assert!(Mtr01Codec::new([0; 16]).decode(&frame).is_err());

    let mut tampered = frame;
    tampered[7] ^= 1;
    assert!(Mtr01Codec::new(TEST_KEY).decode(&tampered).is_err());
}

/// 验证 BLE 写入边界可以和完整帧边界不同。
#[test]
fn stream_decoder_reassembles_split_and_multiple_frames() {
    let codec = Mtr01Codec::new(TEST_KEY);
    let first = codec
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::Subscribe.to_payload(),
        )
        .expect("first");
    let second = codec
        .encode(
            Mtr01Command::ARequest,
            &Mtr01ARequest::Unsubscribe.to_payload(),
        )
        .expect("second");
    let mut decoder = Mtr01StreamDecoder::new();
    assert!(decoder.push(&first[..6]).expect("partial").is_empty());
    let mut combined = first[6..].to_vec();
    combined.extend_from_slice(&second[..5]);
    assert_eq!(decoder.push(&combined).expect("first complete").len(), 1);
    assert_eq!(
        decoder.push(&second[5..]).expect("second complete").len(),
        1
    );
}

/// 验证 A@ 89 字节字段按协议布局往返。
#[test]
fn round_trips_realtime_data_payload() {
    let data = Mtr01AData {
        cell_voltage_10mv: std::array::from_fn(|index| {
            3_000 + u16::try_from(index).expect("array index fits u16")
        }),
        temperature_deci_celsius: [250, 251, 252, 253],
        mos_temperature_deci_celsius: 318,
        state_of_charge_percent: 87,
        total_voltage_10mv: 5_200,
        current_centiamps: -123,
        power_watts: -64,
        discharge_state: 1,
        charge_state: 0,
        cycle_count: 321,
        rated_capacity_10mah: 2_000,
        data_source: 0x02,
        fault_code: 0x01,
    };
    let payload = data.to_payload();
    assert_eq!(payload.len(), Mtr01AData::PAYLOAD_BYTES);
    assert_eq!(payload[87], 0x02);
    assert_eq!(payload[88], 0x01);
    assert_eq!(Mtr01AData::from_payload(&payload).expect("decode"), data);
}

/// 验证 B# cmd 00 到 04 的固定布局、枚举和错误边界。
#[test]
fn round_trips_v151_b_requests() {
    assert_eq!(
        Mtr01BRequest::from_payload(&[0x00]).expect("get info"),
        Mtr01BRequest::GetInfo
    );
    assert_eq!(
        Mtr01BRequest::GetInfo.to_payload().expect("encode"),
        vec![0x00]
    );

    let basic = Mtr01BasicConfig {
        bms_type: Mtr01BmsType::Jbd,
        battery_type: Mtr01BatteryType::TernaryLithium,
        baud_rate: 115_200,
        vehicle_protocol: "RS".into(),
        vehicle_brand: "NIU".into(),
    };
    let payload = basic.to_payload().expect("basic");
    assert_eq!(
        payload,
        vec![
            0x01, 0x03, 0x01, 0x01, 0xC2, 0x00, b'R', b'S', 0xEF, 0xEF, b'N', b'I', b'U',
        ]
    );
    assert_eq!(Mtr01BasicConfig::from_payload(&payload), Ok(basic));
    assert!(Mtr01BasicConfig::from_payload(&[0x01; 12]).is_err());
    let mut invalid_ascii = payload;
    invalid_ascii[10] = 0x80;
    assert_eq!(
        Mtr01BasicConfig::from_payload(&invalid_ascii),
        Err(Mtr01Error::InvalidAscii)
    );

    let runtime = Mtr01RuntimeConfig {
        rated_capacity_10mah: 2_000,
        cell_count: 16,
        consumption_wh_per_100km: 2_500,
        ocv_raw: [0xEF; 42],
    };
    let payload = runtime.to_payload();
    assert_eq!(payload.len(), 48);
    assert_eq!(Mtr01RuntimeConfig::from_payload(&payload), Ok(runtime));

    let identity = Mtr01IdentityConfig {
        serial_number: "BMS202611050001".into(),
        national_code: "GB-001".into(),
    };
    let payload = identity.to_payload().expect("identity");
    assert_eq!(payload[0], 0x03);
    assert_eq!(payload[1], 0xEF);
    assert_eq!(Mtr01IdentityConfig::from_payload(&payload), Ok(identity));

    let calibration = Mtr01BRequest::Calibration(Mtr01CalibrationControl::Restart);
    assert_eq!(calibration.to_payload().expect("calibration"), [0x04, 0x03]);
    assert_eq!(
        Mtr01BRequest::from_payload(&[0x04, 0x03]).expect("decode calibration"),
        calibration
    );
    assert_eq!(
        Mtr01BRequest::from_payload(&[0x04, 0x04]),
        Err(Mtr01Error::UnsupportedValue)
    );
    assert_eq!(
        Mtr01BRequest::from_payload(&[0x05]),
        Err(Mtr01Error::UnsupportedCommand)
    );
}

/// 验证 B@ 设备信息和三类反馈码。
#[test]
fn round_trips_v151_b_responses() {
    let basic_config = Mtr01BasicConfig {
        bms_type: Mtr01BmsType::AtnDash,
        battery_type: Mtr01BatteryType::LithiumIronPhosphate,
        baud_rate: 115_200,
        vehicle_protocol: "RS".into(),
        vehicle_brand: "NIU".into(),
    };
    let runtime_config = Mtr01RuntimeConfig {
        rated_capacity_10mah: 2_000,
        cell_count: 16,
        consumption_wh_per_100km: 2_500,
        ocv_raw: [0xEF; 42],
    };
    let info = Mtr01DeviceInfoV15 {
        device_name: "MTR01BLE".into(),
        serial_number: "BMS202611050001".into(),
        software_version: "1.5.1".into(),
        hardware_version: "HW-1".into(),
        basic_config,
        runtime_config,
    };
    let payload = info.to_payload().expect("device info");
    assert_eq!(payload.len(), 113);
    assert_eq!(payload[54], 0x01);
    assert_eq!(payload[55], 0x02);
    assert_eq!(&payload[56..59], &[0x01, 0xC2, 0x00]);
    assert_eq!(&payload[59..61], b"RS");
    assert_eq!(&payload[66..68], &[0xD0, 0x07]);
    assert_eq!(payload[68], 16);
    assert_eq!(&payload[69..71], &[0xC4, 0x09]);
    assert!(payload[71..113].iter().all(|byte| *byte == 0xEF));
    assert_eq!(
        Mtr01BResponse::from_payload(&payload).expect("decode"),
        Mtr01BResponse::DeviceInfo(info)
    );

    for (command, codes) in [
        (0x01, &[0x00, 0x01, 0x02][..]),
        (0x02, &[0x00, 0x01, 0x02][..]),
        (0x03, &[0x00][..]),
    ] {
        for code in codes {
            let feedback = Mtr01BFeedback::new(command, *code).expect("valid feedback");
            assert_eq!(
                Mtr01BResponse::from_payload(&feedback.to_payload().expect("payload"))
                    .expect("decode"),
                Mtr01BResponse::Feedback(feedback)
            );
        }
    }
    assert_eq!(
        Mtr01BFeedback::new(0x03, 0x01),
        Err(Mtr01Error::UnsupportedValue)
    );
}

/// 验证 C# 扫描、连接控制和断开解绑填充。
#[test]
fn round_trips_v151_c_requests() {
    assert_eq!(
        Mtr01CRequest::from_payload(&[0x01]).expect("scan"),
        Mtr01CRequest::Scan
    );
    assert_eq!(Mtr01CRequest::Scan.to_payload().expect("encode"), [0x01]);

    let connect = Mtr01ConnectControl {
        control: 0x02,
        address_type: 0x01,
        address: [1, 2, 3, 4, 5, 6],
    };
    let payload = connect.to_payload().expect("connect");
    assert_eq!(payload.len(), 9);
    assert_eq!(
        Mtr01CRequest::from_payload(&payload).expect("decode"),
        Mtr01CRequest::Connect(connect)
    );

    let disconnected = Mtr01ConnectControl {
        control: 0x03,
        address_type: 0,
        address: [0; 6],
    }
    .to_payload()
    .expect("disconnect");
    assert_eq!(
        disconnected,
        [0x02, 0x03, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF]
    );
    assert_eq!(
        Mtr01CRequest::from_payload(&disconnected).expect("decode"),
        Mtr01CRequest::Connect(Mtr01ConnectControl {
            control: 0x03,
            address_type: 0xEF,
            address: [0xEF; 6],
        })
    );

    let mut invalid = disconnected;
    invalid[8] = 0;
    assert_eq!(
        Mtr01CRequest::from_payload(&invalid),
        Err(Mtr01Error::InvalidDelimiter)
    );
}

/// 验证 C@ cmd 映射、扫描错误和 212 字节扫描列表。
#[test]
fn round_trips_v151_c_responses() {
    let connected = Mtr01CResponse::Connection(Mtr01ConnectionFeedback::Success)
        .to_payload()
        .expect("connected");
    assert_eq!(connected, [0x02, 0x01]);
    assert_eq!(
        Mtr01CResponse::from_payload(&connected).expect("decode"),
        Mtr01CResponse::Connection(Mtr01ConnectionFeedback::Success)
    );
    assert_eq!(
        Mtr01CResponse::ScanError.to_payload().expect("scan error"),
        [0x01, 0x02]
    );

    let slots = std::array::from_fn(|index| match index {
        0 => Mtr01ScanSlot::Device {
            name: "MTR01".into(),
            address_type: 0x01,
            address: [1, 2, 3, 4, 5, 6],
            rssi: -40,
        },
        1 => Mtr01ScanSlot::Device {
            name: "MTR02".into(),
            address_type: 0x01,
            address: [7, 8, 9, 10, 11, 12],
            rssi: -52,
        },
        _ => Mtr01ScanSlot::Empty,
    });
    let list = Mtr01ScanList { slots };
    let payload = list.to_payload().expect("scan list");
    assert_eq!(payload.len(), 212);
    assert_eq!(payload[..2], [0x01, 0x01]);
    let first_slot = &payload[2..32];
    assert!(first_slot[..17].iter().all(|byte| *byte == 0xEF));
    assert_eq!(&first_slot[17..22], b"MTR01");
    assert_eq!(first_slot[22], 0x01);
    assert_eq!(&first_slot[23..29], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(first_slot[29], 0xD8);
    assert!(payload[62..].iter().all(|byte| *byte == 0xEF));
    assert_eq!(Mtr01ScanList::from_payload(&payload), Ok(list));
}

/// 验证 adapter 将扫描成功和扫描错误映射为独立稳定消息 ID。
#[test]
fn adapter_maps_v151_message_ids_and_validates_routing() {
    let adapter = Mtr01Adapter::new(TEST_KEY);
    let scan_list = Mtr01CResponse::ScanList(Mtr01ScanList {
        slots: std::array::from_fn(|_| Mtr01ScanSlot::Empty),
    })
    .to_payload()
    .expect("scan list");
    for (message_id, payload) in [
        (MTR01_MESSAGE_B_GET_INFO, vec![0x00]),
        (
            MTR01_MESSAGE_B_BASIC_CONFIG,
            Mtr01BasicConfig {
                bms_type: Mtr01BmsType::AtnDash,
                battery_type: Mtr01BatteryType::LithiumIronPhosphate,
                baud_rate: 9_600,
                vehicle_protocol: "1W".into(),
                vehicle_brand: "YY".into(),
            }
            .to_payload()
            .expect("basic"),
        ),
        (
            MTR01_MESSAGE_B_RUNTIME_CONFIG,
            Mtr01RuntimeConfig {
                rated_capacity_10mah: 1_000,
                cell_count: 4,
                consumption_wh_per_100km: 1_200,
                ocv_raw: [0xEF; 42],
            }
            .to_payload(),
        ),
        (
            MTR01_MESSAGE_B_IDENTITY_CONFIG,
            Mtr01IdentityConfig {
                serial_number: "BMS202611050001".into(),
                national_code: String::new(),
            }
            .to_payload()
            .expect("identity"),
        ),
        (MTR01_MESSAGE_B_BASIC_FEEDBACK, vec![0x01, 0x02]),
        (MTR01_MESSAGE_B_RUNTIME_FEEDBACK, vec![0x02, 0x00]),
        (MTR01_MESSAGE_B_IDENTITY_FEEDBACK, vec![0x03, 0x00]),
        (
            MTR01_MESSAGE_B_DEVICE_INFO,
            Mtr01DeviceInfoV15 {
                device_name: "MTR01".into(),
                serial_number: "BMS202611050001".into(),
                software_version: "1.5.1".into(),
                hardware_version: "1".into(),
                basic_config: Mtr01BasicConfig {
                    bms_type: Mtr01BmsType::AtnDash,
                    battery_type: Mtr01BatteryType::LithiumIronPhosphate,
                    baud_rate: 9_600,
                    vehicle_protocol: "1W".into(),
                    vehicle_brand: "YY".into(),
                },
                runtime_config: Mtr01RuntimeConfig {
                    rated_capacity_10mah: 1_000,
                    cell_count: 4,
                    consumption_wh_per_100km: 1_200,
                    ocv_raw: [0xEF; 42],
                },
            }
            .to_payload()
            .expect("device info"),
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
        (MTR01_MESSAGE_C_SCAN_LIST, scan_list),
        (MTR01_MESSAGE_C_SCAN_ERROR, vec![0x01, 0x02]),
        (MTR01_MESSAGE_C_CONNECTION_FEEDBACK, vec![0x02, 0x02]),
    ] {
        let frame = adapter
            .encode(message_id, &adapter_values(&payload))
            .expect("adapter encode");
        let decoded = adapter.decode(&frame).expect("adapter decode");
        assert_eq!(decoded.message_id, message_id);
    }

    assert!(
        adapter
            .encode(MTR01_MESSAGE_C_SCAN_ERROR, &adapter_values(&[0x02, 0x01]))
            .is_err()
    );
    assert!(
        adapter
            .encode(
                MTR01_MESSAGE_C_CONNECT_CONTROL,
                &adapter_values(&[0x02, 0x03, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF]),
            )
            .is_err()
    );
}

/// 验证 D# 和 D@ 固定载荷保持 V1.4 语义。
#[test]
fn round_trips_binding_payloads() {
    let unbound = Mtr01BindingRequest::Unbound;
    assert_eq!(
        Mtr01BindingRequest::from_payload(&unbound.to_payload().expect("unbound")).expect("decode"),
        unbound
    );
    let bound = Mtr01BindingRequest::Bound {
        status: 0x02,
        code: [7; 16],
    };
    assert_eq!(
        Mtr01BindingRequest::from_payload(&bound.to_payload().expect("bound")).expect("decode"),
        bound
    );
    assert_eq!(
        Mtr01BindingResponse::from_payload(&Mtr01BindingResponse::ConfirmIdentity.to_payload())
            .expect("response"),
        Mtr01BindingResponse::ConfirmIdentity
    );
}

/// 验证公开限额与文档中的 MTU 声明一致。
#[test]
fn exposes_protocol_limits() {
    assert_eq!(MTR01_MAX_FRAME_BYTES, 278);
    assert_eq!(MTR01_NOTIFICATION_BYTES, 244);
}

/// 验证协议定义和适配器版本已整体切换为 V1.5.1。
#[test]
fn adapter_declares_complete_v151_definition() {
    let adapter = Mtr01Adapter::new(TEST_KEY);
    assert_eq!(adapter.protocol_id(), "mtr01-protocol");
    assert_eq!(adapter.protocol_version(), "1.5.1");
    let definition = adapter.definition();
    assert_eq!(definition["protocolVersion"], "1.5.1");
    assert_eq!(
        definition["messages"].as_array().expect("messages").len(),
        22
    );
    assert!(adapter.has_message(MTR01_MESSAGE_C_SCAN_ERROR));
    assert!(adapter.has_message(MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND));
    assert!(!adapter.has_message("bSync"));
    assert!(!adapter.has_message("B$"));
}

/// 验证 MTR01 适配器可接入模拟器通用协议接口。
#[test]
fn adapter_encodes_messages_and_reassembles_stream_frames() {
    let adapter = Mtr01Adapter::new(TEST_KEY);
    let values = adapter_values(&Mtr01ARequest::Subscribe.to_payload());
    let frame = adapter.encode("aSubscribe", &values).expect("encode");
    let decoded_frame = adapter.decode(&frame).expect("decode");
    assert_eq!(decoded_frame.message_id, "aSubscribe");
    assert_eq!(decoded_frame.values, values);

    let mut decoder = adapter.stream_decoder().expect("decoder");
    assert!(decoder.push(&frame[..5]).expect("partial").is_empty());
    assert_eq!(decoder.push(&frame[5..]).expect("complete"), vec![frame]);
}
