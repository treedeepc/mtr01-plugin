//
//  adapter.rs
//  leeway-protocol-core / adapter
//
//  文件职责：定义模拟器可组合的通用协议编解码接口。
//

use std::fmt;

use leeway_protocol_contracts::ProtocolDiagnostic;
use serde_json::Value;

use crate::{DecodedFrame, ProtocolStreamDecoder, ProtocolValues};

/// 可与模拟器引擎组合的协议适配器。
pub trait ProtocolAdapter: fmt::Debug + Send + Sync {
    /// 返回稳定协议 ID。
    fn protocol_id(&self) -> &str;

    /// 返回协议版本。
    fn protocol_version(&self) -> &str;

    /// 返回可供查询的完整声明式协议定义。
    fn definition(&self) -> Value;

    /// 判断是否声明指定消息。
    fn has_message(&self, message_id: &str) -> bool;

    /// 编码完整协议帧。
    ///
    /// # Errors
    ///
    /// 消息、字段值、校验或 framing 无法生成时返回稳定诊断。
    fn encode(
        &self,
        message_id: &str,
        values: &ProtocolValues,
    ) -> Result<Vec<u8>, ProtocolDiagnostic>;

    /// 解码并认证完整协议帧。
    ///
    /// # Errors
    ///
    /// framing、校验、字段或消息匹配失败时返回稳定诊断。
    fn decode(&self, frame: &[u8]) -> Result<DecodedFrame, ProtocolDiagnostic>;

    /// 创建有界流式分帧器。
    ///
    /// # Errors
    ///
    /// 协议 framing 无法划分字节流时返回稳定诊断。
    fn stream_decoder(&self) -> Result<Box<dyn ProtocolStreamAdapter>, ProtocolDiagnostic>;
}

/// 可跨传输读取重组协议帧的流式接口。
pub trait ProtocolStreamAdapter: Send {
    /// 推入一段字节并返回已经完整的帧。
    ///
    /// # Errors
    ///
    /// 输入超限、帧损坏或 framing 配置不合法时返回稳定诊断。
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProtocolDiagnostic>;
}

impl ProtocolAdapter for crate::CompiledProtocol {
    fn protocol_id(&self) -> &str {
        self.protocol_id()
    }

    fn protocol_version(&self) -> &str {
        self.protocol_version()
    }

    fn definition(&self) -> Value {
        serde_json::to_value(self.definition()).unwrap_or(Value::Null)
    }

    fn has_message(&self, message_id: &str) -> bool {
        self.has_message(message_id)
    }

    fn encode(
        &self,
        message_id: &str,
        values: &ProtocolValues,
    ) -> Result<Vec<u8>, ProtocolDiagnostic> {
        self.encode(message_id, values)
    }

    fn decode(&self, frame: &[u8]) -> Result<DecodedFrame, ProtocolDiagnostic> {
        self.decode(frame)
    }

    fn stream_decoder(&self) -> Result<Box<dyn ProtocolStreamAdapter>, ProtocolDiagnostic> {
        Ok(Box::new(self.stream_decoder()?))
    }
}

impl ProtocolStreamAdapter for ProtocolStreamDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProtocolDiagnostic> {
        self.push(bytes)
    }
}
