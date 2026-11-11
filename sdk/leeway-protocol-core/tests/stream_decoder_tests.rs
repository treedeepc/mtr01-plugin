use std::collections::BTreeMap;

use leeway_protocol_contracts::ProtocolDiagnosticCode;
use leeway_protocol_core::{ProtocolCompiler, ProtocolValue};

fn sensor_protocol() -> leeway_protocol_core::CompiledProtocol {
    let source = include_str!("fixtures/protocol-v1-sensor.json");
    ProtocolCompiler::compile(source).expect("sensor protocol")
}

fn request_values() -> BTreeMap<String, ProtocolValue> {
    BTreeMap::from([
        ("address".into(), ProtocolValue::Unsigned(1)),
        ("command".into(), ProtocolValue::Unsigned(3)),
        ("register".into(), ProtocolValue::Unsigned(10)),
    ])
}

#[test]
fn reassembles_split_length_prefixed_frames() {
    let protocol = sensor_protocol();
    let mut decoder = protocol.stream_decoder().expect("decoder");
    let frame = protocol
        .encode("readSensor", &request_values())
        .expect("frame");

    assert!(decoder.push(&frame[..3]).expect("prefix").is_empty());
    assert_eq!(decoder.push(&frame[3..]).expect("rest"), vec![frame]);
}

#[test]
fn extracts_multiple_frames_from_one_push() {
    let protocol = sensor_protocol();
    let mut decoder = protocol.stream_decoder().expect("decoder");
    let frame = protocol
        .encode("readSensor", &request_values())
        .expect("frame");
    let mut input = frame.clone();
    input.extend_from_slice(&frame);

    assert_eq!(
        decoder.push(&input).expect("frames"),
        vec![frame.clone(), frame]
    );
}

#[test]
fn supports_delimiter_and_fixed_length_streams() {
    let delimiter = ProtocolCompiler::compile(
        r#"{
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
        }"#,
    )
    .expect("delimiter");
    let mut decoder = delimiter.stream_decoder().expect("delimiter decoder");
    assert!(decoder.push(&[7]).expect("partial delimiter").is_empty());
    assert_eq!(decoder.push(&[10]).expect("delimiter"), vec![vec![7, 10]]);

    let fixed = ProtocolCompiler::compile(
        r#"{
          "schemaVersion":1,
          "protocolId":"fixed",
          "protocolVersion":"1.0.0",
          "name":"Fixed",
          "framing":{"kind":"fixedLength","lengthBytes":1},
          "messages":[{
            "id":"value",
            "match":[],
            "fields":[{"name":"value","type":"uint8"}]
          }],
          "testVectors":[]
        }"#,
    )
    .expect("fixed");
    let mut decoder = fixed.stream_decoder().expect("fixed decoder");
    assert_eq!(
        decoder.push(&[1, 2]).expect("fixed frames"),
        vec![vec![1], vec![2]]
    );
}

#[test]
fn rejects_oversize_prefix_raw_framing_and_oversize_input() {
    let protocol = sensor_protocol();
    let mut decoder = protocol.stream_decoder().expect("decoder");
    assert_eq!(
        decoder
            .push(&[0x01, 0x00])
            .expect_err("oversize prefix")
            .code,
        ProtocolDiagnosticCode::FrameTooLarge
    );

    let raw = ProtocolCompiler::compile(
        r#"{
          "schemaVersion":1,
          "protocolId":"raw",
          "protocolVersion":"1.0.0",
          "name":"Raw",
          "framing":{"kind":"raw","maxFrameBytes":8},
          "messages":[{
            "id":"value",
            "match":[],
            "fields":[{"name":"value","type":"uint8"}]
          }],
          "testVectors":[]
        }"#,
    )
    .expect("raw");
    assert_eq!(
        raw.stream_decoder().expect_err("raw rejection").code,
        ProtocolDiagnosticCode::InvalidFrameConfiguration
    );

    let mut decoder = protocol.stream_decoder().expect("decoder");
    assert_eq!(
        decoder
            .push(&vec![0; 65_537])
            .expect_err("input limit")
            .code,
        ProtocolDiagnosticCode::FrameTooLarge
    );
}
