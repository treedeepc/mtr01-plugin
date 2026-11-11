//
//  diagnostic.rs
//  leeway-protocol-contracts / diagnostic
//
//  文件职责：定义不含原始载荷的协议编译和编解码诊断。
//

use std::fmt;

use serde::{Deserialize, Serialize};

/// 协议稳定诊断码。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolDiagnosticCode {
    /// 文档不是合法 JSON 或 Schema。
    MalformedDocument,
    /// 文档超过字节上限。
    DocumentTooLarge,
    /// Schema 版本不受支持。
    UnsupportedSchemaVersion,
    /// requiredFeatures 中包含未知能力。
    UnknownFeature,
    /// 协议标识不合法。
    InvalidProtocolId,
    /// 协议版本或名称不合法。
    InvalidMetadata,
    /// 消息数量超过上限。
    TooManyMessages,
    /// 字段数量超过上限。
    TooManyFields,
    /// 测试向量数量超过上限。
    TooManyTestVectors,
    /// 字段定义不完整或组合不合法。
    InvalidFieldDefinition,
    /// framing 配置不合法。
    InvalidFrameConfiguration,
    /// checksum 配置不合法。
    InvalidChecksum,
    /// AES-CMAC 配置缺少 16 字节密钥。
    MissingChecksumKey,
    /// AES-CMAC 密钥长度不合法。
    InvalidChecksumKey,
    /// 消息 ID 重复。
    DuplicateMessageId,
    /// 消息匹配条件不合法。
    InvalidMatchCondition,
    /// 多条消息匹配条件无法区分。
    AmbiguousMessageMatch,
    /// 消息中没有目标字段。
    UnknownField,
    /// 字段定义或输入值不合法。
    InvalidFieldValue,
    /// 帧超过上限。
    FrameTooLarge,
    /// 校验失败。
    ChecksumMismatch,
    /// 没有匹配消息。
    UnknownMessage,
    /// 帧结构损坏或不完整。
    MalformedFrame,
    /// 测试向量失败。
    TestVectorFailed,
    /// 测试向量名称重复。
    DuplicateTestVectorName,
}

/// 协议编译或编解码失败诊断。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolDiagnostic {
    /// 稳定机器错误码。
    pub code: ProtocolDiagnosticCode,
    /// 指向文档或字段的稳定逻辑路径，不包含原始输入。
    pub path: String,
    /// 安全说明。
    pub message: String,
}

impl ProtocolDiagnostic {
    /// 创建安全协议诊断。
    #[must_use]
    pub fn new(
        code: ProtocolDiagnosticCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolDiagnostic {
    /// 输出不含原始载荷的诊断。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.message, self.path)
    }
}

impl std::error::Error for ProtocolDiagnostic {}
