//
//  type_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证 V1 全部字段类型、端序和无损往返。
//

use std::collections::BTreeMap;

use leeway_protocol_core::{ProtocolCompiler, ProtocolValue};

/// 验证全部 V1 字段类型。
#[test]
fn round_trips_supported_field_types() {
    let document = r#"{
      "schemaVersion":1,
      "protocolId":"types",
      "protocolVersion":"1.0.0",
      "name":"Types",
      "framing":{"kind":"raw","maxFrameBytes":256},
      "messages":[{
        "id":"allTypes",
        "match":[],
        "fields":[
          {"name":"u8","type":"uint8"},
          {"name":"u16be","type":"uint16","endianness":"big"},
          {"name":"u16le","type":"uint16","endianness":"little"},
          {"name":"i16be","type":"int16","endianness":"big"},
          {"name":"u24le","type":"uint24","endianness":"little"},
          {"name":"i24be","type":"int24","endianness":"big"},
          {"name":"u32be","type":"uint32","endianness":"big"},
          {"name":"i32le","type":"int32","endianness":"little"},
          {"name":"u64le","type":"uint64","endianness":"little"},
          {"name":"i64be","type":"int64","endianness":"big"},
          {"name":"float32","type":"float32","endianness":"big"},
          {"name":"float64","type":"float64","endianness":"little"},
          {"name":"enabled","type":"bool8"},
          {"name":"raw","type":"bytesFixed","length":2},
          {"name":"ascii","type":"asciiFixed","length":2},
          {"name":"utf8","type":"utf8Fixed","length":2},
          {"name":"mode8","type":"enum8","enumValues":{"idle":1,"active":2}},
          {"name":"mode16","type":"enum16","endianness":"little","enumValues":{"low":1,"high":258}}
        ]
      }],
      "testVectors":[]
    }"#;
    let protocol = ProtocolCompiler::compile(document).expect("compile");
    let values = BTreeMap::from([
        ("u8".into(), ProtocolValue::Unsigned(255)),
        ("u16be".into(), ProtocolValue::Unsigned(0x1234)),
        ("u16le".into(), ProtocolValue::Unsigned(0x1234)),
        ("i16be".into(), ProtocolValue::Signed(-2)),
        ("u24le".into(), ProtocolValue::Unsigned(0x0012_3456)),
        ("i24be".into(), ProtocolValue::Signed(-3)),
        ("u32be".into(), ProtocolValue::Unsigned(0x1234_5678)),
        ("i32le".into(), ProtocolValue::Signed(-4)),
        (
            "u64le".into(),
            ProtocolValue::Unsigned(0x1234_5678_9ABC_DEF0),
        ),
        ("i64be".into(), ProtocolValue::Signed(-5)),
        ("float32".into(), ProtocolValue::Float(1.5)),
        ("float64".into(), ProtocolValue::Float(-2.25)),
        ("enabled".into(), ProtocolValue::Bool(true)),
        ("raw".into(), ProtocolValue::Bytes(vec![0xAA, 0xBB])),
        ("ascii".into(), ProtocolValue::Text("OK".into())),
        ("utf8".into(), ProtocolValue::Text("é".into())),
        ("mode8".into(), ProtocolValue::Enum("active".into())),
        ("mode16".into(), ProtocolValue::Enum("high".into())),
    ]);

    let frame = protocol.encode("allTypes", &values).expect("encode");
    let decoded = protocol.decode(&frame).expect("decode");
    assert_eq!(decoded.values, values);
}

/// 验证字段值类型和范围错误。
#[test]
fn rejects_invalid_typed_values() {
    let document = r#"{
      "schemaVersion":1,
      "protocolId":"types",
      "protocolVersion":"1.0.0",
      "name":"Types",
      "framing":{"kind":"raw","maxFrameBytes":16},
      "messages":[{
        "id":"value",
        "match":[],
        "fields":[{"name":"value","type":"uint16","endianness":"big"}]
      }],
      "testVectors":[]
    }"#;
    let protocol = ProtocolCompiler::compile(document).expect("compile");
    for value in [
        ProtocolValue::Unsigned(65_536),
        ProtocolValue::Signed(-1),
        ProtocolValue::Bool(true),
    ] {
        assert!(
            protocol
                .encode("value", &BTreeMap::from([("value".into(), value)]))
                .is_err()
        );
    }
}
