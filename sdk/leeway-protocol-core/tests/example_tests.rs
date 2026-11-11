//
//  example_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证发布示例协议可编译并执行黄金测试向量。
//

use leeway_protocol_core::ProtocolCompiler;

/// 验证共享示例协议完整通过。
#[test]
fn sensor_example_compiles_and_passes_vectors() {
    let document = include_str!("fixtures/protocol-v1-sensor.json");
    let protocol = ProtocolCompiler::compile(document).expect("compile example");

    assert_eq!(protocol.test_vector_count(), 1);
    protocol.run_test_vectors().expect("example vectors");
}
