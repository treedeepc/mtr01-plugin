//
//  framing_error_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证固定长度、checksum mismatch 和 framing 错误。
//

use std::collections::BTreeMap;

use leeway_protocol_contracts::ProtocolDiagnosticCode;
use leeway_protocol_core::{ProtocolCompiler, ProtocolValue};

/// 验证固定长度 framing。
#[test]
fn fixed_length_round_trip_and_length_error() {
    let document = r#"{
      "schemaVersion":1,
      "protocolId":"fixed",
      "protocolVersion":"1.0.0",
      "name":"Fixed",
      "framing":{"kind":"fixedLength","lengthBytes":2},
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint16","endianness":"big"}]
      }],
      "testVectors":[]
    }"#;
    let protocol = ProtocolCompiler::compile(document).expect("compile");
    let values = BTreeMap::from([("value".into(), ProtocolValue::Unsigned(0x0102))]);

    let frame = protocol.encode("value", &values).expect("encode");
    assert_eq!(frame, vec![1, 2]);
    assert!(protocol.decode(&[1]).is_err());
}

/// 验证 checksum mismatch 和损坏长度前缀。
#[test]
fn rejects_checksum_and_malformed_frame() {
    let document = r#"{
      "schemaVersion":1,
      "protocolId":"crc",
      "protocolVersion":"1.0.0",
      "name":"CRC",
      "framing":{"kind":"raw","maxFrameBytes":16},
      "checksum":{"kind":"crc16Modbus","coverage":"beforeChecksum","placement":"append"},
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint8"}]
      }],
      "testVectors":[]
    }"#;
    let protocol = ProtocolCompiler::compile(document).expect("compile");
    let mut frame = protocol
        .encode(
            "value",
            &BTreeMap::from([("value".into(), ProtocolValue::Unsigned(7))]),
        )
        .expect("encode");
    frame[0] ^= 1;
    assert_eq!(
        protocol.decode(&frame).expect_err("checksum").code,
        ProtocolDiagnosticCode::ChecksumMismatch
    );

    let prefixed_document = r#"{
      "schemaVersion":1,
      "protocolId":"prefixed",
      "protocolVersion":"1.0.0",
      "name":"Prefixed",
      "framing":{
        "kind":"lengthPrefixed",
        "maxFrameBytes":16,
        "lengthPrefix":{
          "bytes":2,
          "endianness":"big",
          "includesPrefix":false,
          "includesChecksum":false
        }
      },
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint8"}]
      }],
      "testVectors":[]
    }"#;
    let prefixed = ProtocolCompiler::compile(prefixed_document).expect("compile");
    assert_eq!(
        prefixed.decode(&[0, 2, 1]).expect_err("length").code,
        ProtocolDiagnosticCode::MalformedFrame
    );
}

/// 验证 AES-CMAC 必须通过带外密钥启用并拒绝篡改帧。
#[test]
fn aes_cmac_requires_key_and_rejects_tampering() {
    let document = r#"{
      "schemaVersion":1,
      "protocolId":"cmac",
      "protocolVersion":"1.0.0",
      "name":"CMAC",
      "framing":{"kind":"raw","maxFrameBytes":32},
      "checksum":{"kind":"aesCmac","coverage":"beforeChecksum","placement":"append"},
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint8"}]
      }],
      "testVectors":[]
    }"#;
    assert_eq!(
        ProtocolCompiler::compile(document).expect_err("missing key")[0].code,
        ProtocolDiagnosticCode::MissingChecksumKey
    );

    let protocol = ProtocolCompiler::compile_with_aes_cmac_key(
        document,
        Some([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
    )
    .expect("compile");
    let mut frame = protocol
        .encode(
            "value",
            &BTreeMap::from([("value".into(), ProtocolValue::Unsigned(7))]),
        )
        .expect("encode");
    assert_eq!(
        protocol.decode(&frame).expect("decode").values["value"],
        ProtocolValue::Unsigned(7)
    );
    frame[0] ^= 1;
    assert_eq!(
        protocol.decode(&frame).expect_err("checksum").code,
        ProtocolDiagnosticCode::ChecksumMismatch
    );
}
