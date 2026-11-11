//
//  codec_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证编码、解码、framing 和错误路径。
//

mod common;

use std::collections::BTreeMap;

use leeway_protocol_contracts::ProtocolDiagnosticCode;
use leeway_protocol_core::{ProtocolCompiler, ProtocolValue};

/// 创建 readSensor 字段值。
fn values() -> BTreeMap<String, ProtocolValue> {
    BTreeMap::from([
        ("address".into(), ProtocolValue::Unsigned(1)),
        ("command".into(), ProtocolValue::Unsigned(3)),
        ("register".into(), ProtocolValue::Unsigned(10)),
    ])
}

/// 验证 raw 协议编码与无损解码。
#[test]
fn encodes_and_decodes_supported_values() {
    let protocol = common::compile_raw("[]");
    let frame = protocol.encode("readSensor", &values()).expect("encode");

    assert_eq!(frame, vec![1, 3, 0, 10]);
    let decoded = protocol.decode(&frame).expect("decode");
    assert_eq!(decoded.message_id, "readSensor");
    assert_eq!(decoded.values, values());
    assert_eq!(decoded.raw_bytes, frame);
}

/// 验证未知消息和缺失字段失败。
#[test]
fn rejects_unknown_message_and_missing_values() {
    let protocol = common::compile_raw("[]");
    assert_eq!(
        protocol
            .encode("unknown", &values())
            .expect_err("unknown")
            .code,
        ProtocolDiagnosticCode::UnknownMessage
    );
    assert_eq!(
        protocol
            .encode("readSensor", &BTreeMap::new())
            .expect_err("missing")
            .code,
        ProtocolDiagnosticCode::InvalidFieldValue
    );
}

/// 验证无法匹配的消息失败。
#[test]
fn rejects_unknown_message_match() {
    let protocol = common::compile_raw("[]");
    assert_eq!(
        protocol.decode(&[1, 4, 0, 10]).expect_err("unknown").code,
        ProtocolDiagnosticCode::UnknownMessage
    );
}

/// 验证截断和尾随字段不会被静默接受。
#[test]
fn rejects_truncated_or_trailing_payload() {
    let protocol = common::compile_raw("[]");
    assert_eq!(
        protocol.decode(&[1, 3, 0]).expect_err("truncated").code,
        ProtocolDiagnosticCode::MalformedFrame
    );
    assert_eq!(
        protocol
            .decode(&[1, 3, 0, 10, 0])
            .expect_err("trailing")
            .code,
        ProtocolDiagnosticCode::MalformedFrame
    );
}

/// 验证 delimiter framing 和长度前缀 framing。
#[test]
fn supports_delimiter_and_length_prefix_framing() {
    let delimiter_document = r#"{
      "schemaVersion":1,
      "protocolId":"line",
      "protocolVersion":"1.0.0",
      "name":"Line",
      "framing":{"kind":"delimiter","delimiterHex":"0A","maxFrameBytes":8},
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint8"}]
      }],
      "testVectors":[]
    }"#;
    let delimiter = ProtocolCompiler::compile(delimiter_document).expect("delimiter");
    let frame = delimiter
        .encode(
            "value",
            &BTreeMap::from([("value".into(), ProtocolValue::Unsigned(7))]),
        )
        .expect("encode");
    assert_eq!(frame, vec![7, 10]);
    assert_eq!(
        delimiter.decode(&frame).expect("decode").values["value"],
        ProtocolValue::Unsigned(7)
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
        "fields":[{"name":"value","type":"uint16","endianness":"big"}]
      }],
      "testVectors":[]
    }"#;
    let prefixed = ProtocolCompiler::compile(prefixed_document).expect("prefixed");
    let frame = prefixed
        .encode(
            "value",
            &BTreeMap::from([("value".into(), ProtocolValue::Unsigned(0x0102))]),
        )
        .expect("encode");
    assert_eq!(frame, vec![0, 2, 1, 2]);
}
