//
//  ir.rs
//  leeway-protocol-core / compiler
//
//  文件职责：定义通过语义校验后的不可变协议执行模型。
//

use std::collections::BTreeMap;

use leeway_protocol_contracts::{
    Endianness, ProtocolChecksumKind, ProtocolDocument, ProtocolFraming, ProtocolMatchOperator,
};
use serde_json::Value;

use crate::checksum::AesCmacKey;

/// 编译后的完整协议。
#[derive(Debug)]
pub struct CompiledProtocol {
    /// 稳定协议 ID。
    pub(crate) protocol_id: String,
    /// 用户维护的协议版本。
    pub(crate) protocol_version: String,
    /// 通过校验的完整协议文档。
    pub(crate) definition: ProtocolDocument,
    /// 安全显示名称。
    pub(crate) name: String,
    /// 规范化 framing。
    pub(crate) framing: ProtocolFraming,
    /// 校验算法。
    pub(crate) checksum: ProtocolChecksumKind,
    /// 通过带外参数注入的 AES-CMAC 密钥。
    pub(crate) checksum_key: Option<AesCmacKey>,
    /// 编译后的消息。
    pub(crate) messages: Vec<CompiledMessage>,
    /// 编译后的测试向量。
    pub(crate) test_vectors: Vec<CompiledTestVector>,
}

impl CompiledProtocol {
    /// 返回稳定协议 ID。
    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// 返回用户维护的协议版本。
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// 返回通过校验的完整协议文档。
    #[must_use]
    pub fn definition(&self) -> &ProtocolDocument {
        &self.definition
    }

    /// 返回安全显示名称。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 返回消息数量。
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// 返回测试向量数量。
    #[must_use]
    pub fn test_vector_count(&self) -> usize {
        self.test_vectors.len()
    }

    /// 判断协议是否声明指定消息。
    #[must_use]
    pub fn has_message(&self, message_id: &str) -> bool {
        self.messages.iter().any(|message| message.id == message_id)
    }
}

/// 编译后的消息。
#[derive(Debug)]
pub(crate) struct CompiledMessage {
    /// 稳定消息 ID。
    pub(crate) id: String,
    /// 解码匹配条件。
    pub(crate) matches: Vec<CompiledMatch>,
    /// 字段与固定布局。
    pub(crate) fields: Vec<CompiledField>,
}

/// 编译后的消息匹配条件。
#[derive(Debug)]
pub(crate) struct CompiledMatch {
    /// 被匹配字段。
    pub(crate) field_name: String,
    /// 操作符。
    pub(crate) operator: ProtocolMatchOperator,
    /// 匹配参数。
    pub(crate) value: Value,
}

/// 编译后的字段。
#[derive(Debug)]
pub(crate) struct CompiledField {
    /// 消息内唯一字段名。
    pub(crate) name: String,
    /// 从消息 payload 起点计算的固定偏移。
    pub(crate) offset_bytes: usize,
    /// 字段类型与宽度。
    pub(crate) kind: CompiledFieldKind,
}

/// 编译后的字段类型。
#[derive(Debug)]
pub(crate) enum CompiledFieldKind {
    /// 无符号整数。
    Unsigned {
        /// 字节宽度。
        width: usize,
        /// 多字节端序。
        endianness: Endianness,
    },
    /// 有符号整数。
    Signed {
        /// 字节宽度。
        width: usize,
        /// 多字节端序。
        endianness: Endianness,
    },
    /// 布尔值。
    Bool,
    /// IEEE 浮点数。
    Float {
        /// 字节宽度。
        width: usize,
        /// 端序。
        endianness: Endianness,
    },
    /// 固定原始字节。
    Bytes {
        /// 固定长度。
        length: usize,
    },
    /// 固定 ASCII 文本。
    Ascii {
        /// 固定长度。
        length: usize,
    },
    /// 固定 UTF-8 文本。
    Utf8 {
        /// 固定长度。
        length: usize,
    },
    /// 无符号枚举。
    Enum {
        /// 字节宽度。
        width: usize,
        /// enum16 端序；enum8 为 None。
        endianness: Option<Endianness>,
        /// 名称到数值映射。
        values: BTreeMap<String, u64>,
    },
}

impl CompiledFieldKind {
    /// 返回字段固定字节宽度。
    pub(crate) const fn width(&self) -> usize {
        match self {
            Self::Unsigned { width, .. }
            | Self::Signed { width, .. }
            | Self::Float { width, .. }
            | Self::Enum { width, .. } => *width,
            Self::Bool => 1,
            Self::Bytes { length } | Self::Ascii { length } | Self::Utf8 { length } => *length,
        }
    }
}

/// 编译后的测试向量。
#[derive(Debug)]
pub(crate) struct CompiledTestVector {
    /// 协议内唯一名称。
    pub(crate) name: String,
    /// 目标消息 ID。
    pub(crate) message_id: String,
    /// 编码输入字段值。
    pub(crate) values: BTreeMap<String, Value>,
    /// 已解析的预期完整帧。
    pub(crate) expected_bytes: Vec<u8>,
}
