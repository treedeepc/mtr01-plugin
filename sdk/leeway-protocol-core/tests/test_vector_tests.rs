//
//  test_vector_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证黄金测试向量成功和失败诊断。
//

mod common;

use leeway_protocol_contracts::ProtocolDiagnosticCode;

/// 验证正确测试向量执行成功。
#[test]
fn runs_matching_test_vector() {
    let vectors = r#"[{
      "name":"read-register",
      "messageId":"readSensor",
      "values":{"address":1,"command":3,"register":10},
      "encodedHex":"0103000A"
    }]"#;
    let protocol = common::compile_raw(vectors);

    protocol.run_test_vectors().expect("test vectors");
}

/// 验证错误期望字节返回测试向量诊断。
#[test]
fn reports_wrong_expected_bytes() {
    let vectors = r#"[{
      "name":"wrong",
      "messageId":"readSensor",
      "values":{"address":1,"command":3,"register":10},
      "encodedHex":"0103000B"
    }]"#;
    let protocol = common::compile_raw(vectors);
    let diagnostics = protocol.run_test_vectors().expect_err("mismatch");

    assert!(
        diagnostics
            .iter()
            .any(|item| { item.code == ProtocolDiagnosticCode::TestVectorFailed })
    );
}
