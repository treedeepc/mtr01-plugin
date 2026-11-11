//
//  document_tests.rs
//  leeway-protocol-contracts / tests
//
//  文件职责：验证协议文档拒绝未知字段和未支持类型。
//

use leeway_protocol_contracts::ProtocolDocument;

/// 验证文档对象拒绝未声明字段。
#[test]
fn rejects_unknown_document_fields() {
    let json = r#"{
      "schemaVersion": 1,
      "protocolId": "example",
      "protocolVersion": "1.0.0",
      "name": "Example",
      "framing": {"kind":"raw","maxFrameBytes":64},
      "messages": [],
      "testVectors": [],
      "unknown": true
    }"#;

    assert!(serde_json::from_str::<ProtocolDocument>(json).is_err());
}

/// 验证字段类型枚举之外的值被拒绝。
#[test]
fn rejects_unlisted_field_type() {
    let json = r#"{
      "schemaVersion": 1,
      "protocolId": "example",
      "protocolVersion": "1.0.0",
      "name": "Example",
      "framing": {"kind":"raw","maxFrameBytes":64},
      "messages": [{
        "id":"example",
        "match":[],
        "fields":[{"name":"value","type":"uint128"}]
      }],
      "testVectors": []
    }"#;

    assert!(serde_json::from_str::<ProtocolDocument>(json).is_err());
}
