//
//  compiler_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证 Protocol DSL 的结构与跨引用语义校验。
//

use leeway_protocol_contracts::ProtocolDiagnosticCode;
use leeway_protocol_core::ProtocolCompiler;

/// 创建基础协议文档 JSON。
fn document_with(messages: &str) -> String {
    format!(
        r#"{{
          "schemaVersion": 1,
          "protocolId": "example",
          "protocolVersion": "1.0.0",
          "name": "Example",
          "framing": {{"kind":"raw","maxFrameBytes":64}},
          "messages": {messages},
          "testVectors": []
        }}"#
    )
}

/// 验证重复消息 ID 被拒绝。
#[test]
fn rejects_duplicate_message_ids() {
    let document = document_with(
        r#"[
          {"id":"duplicate","match":[],"fields":[{"name":"a","type":"uint8"}]},
          {"id":"duplicate","match":[{"field":"a","operator":"equals","value":2}],"fields":[{"name":"a","type":"uint8"}]}
        ]"#,
    );

    let diagnostics = ProtocolCompiler::compile(&document).expect_err("duplicate");
    assert!(
        diagnostics
            .iter()
            .any(|item| { item.code == ProtocolDiagnosticCode::DuplicateMessageId })
    );
}

/// 验证匹配条件不能引用不存在的字段。
#[test]
fn rejects_match_on_unknown_field() {
    let document = document_with(
        r#"[{
          "id":"message",
          "match":[{"field":"missing","operator":"equals","value":1}],
          "fields":[{"name":"known","type":"uint8"}]
        }]"#,
    );

    let diagnostics = ProtocolCompiler::compile(&document).expect_err("unknown field");
    assert!(
        diagnostics
            .iter()
            .any(|item| { item.code == ProtocolDiagnosticCode::InvalidMatchCondition })
    );
}

/// 验证多字节字段缺少端序被拒绝。
#[test]
fn rejects_missing_endianness() {
    let document = document_with(
        r#"[{
          "id":"message",
          "match":[],
          "fields":[{"name":"value","type":"uint16"}]
        }]"#,
    );

    let diagnostics = ProtocolCompiler::compile(&document).expect_err("endianness");
    assert!(
        diagnostics
            .iter()
            .any(|item| { item.code == ProtocolDiagnosticCode::InvalidFieldValue })
    );
}

/// 验证合法文档可以编译且基本信息稳定。
#[test]
fn compiles_valid_document() {
    let document = document_with(
        r#"[{
          "id":"message",
          "match":[{"field":"command","operator":"equals","value":3}],
          "fields":[
            {"name":"address","type":"uint8"},
            {"name":"command","type":"uint8"},
            {"name":"register","type":"uint16","endianness":"big"}
          ]
        }]"#,
    );

    let protocol = ProtocolCompiler::compile(&document).expect("compile");
    assert_eq!(protocol.protocol_id(), "example");
    assert_eq!(protocol.protocol_version(), "1.0.0");
    assert_eq!(protocol.message_count(), 1);
}
