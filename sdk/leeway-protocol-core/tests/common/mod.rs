//
//  mod.rs
//  leeway-protocol-core / tests support
//
//  文件职责：提供协议编译与编解码测试共用的合法文档。
//

use leeway_protocol_core::{CompiledProtocol, ProtocolCompiler};

/// 返回基础 raw 协议 JSON。
pub fn raw_protocol(test_vectors: &str) -> String {
    format!(
        r#"{{
          "schemaVersion": 1,
          "protocolId": "example",
          "protocolVersion": "1.0.0",
          "name": "Example",
          "framing": {{"kind":"raw","maxFrameBytes":64}},
          "messages": [{{
            "id":"readSensor",
            "match":[{{"field":"command","operator":"equals","value":3}}],
            "fields":[
              {{"name":"address","type":"uint8"}},
              {{"name":"command","type":"uint8"}},
              {{"name":"register","type":"uint16","endianness":"big"}}
            ]
          }}],
          "testVectors": {test_vectors}
        }}"#
    )
}

/// 编译基础 raw 协议。
pub fn compile_raw(test_vectors: &str) -> CompiledProtocol {
    ProtocolCompiler::compile(&raw_protocol(test_vectors)).expect("compile protocol")
}
