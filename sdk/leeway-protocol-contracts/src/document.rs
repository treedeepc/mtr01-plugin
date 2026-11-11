//
//  document.rs
//  leeway-protocol-contracts / document
//
//  文件职责：定义版本化 Protocol DSL 的可反序列化 JSON 结构。
//

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 当前 Protocol DSL Schema 版本。
pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;

/// 单个协议 JSON 最大字节数。
pub const MAX_PROTOCOL_BYTES: usize = 1024 * 1024;

/// 单个协议最大消息数。
pub const MAX_PROTOCOL_MESSAGES: usize = 256;

/// 单消息最大字段数。
pub const MAX_PROTOCOL_FIELDS_PER_MESSAGE: usize = 128;

/// 单协议最大测试向量数。
pub const MAX_PROTOCOL_TEST_VECTORS: usize = 1024;

/// 协议文档根对象。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolDocument {
    /// 文档结构版本。
    pub schema_version: u32,
    /// 稳定协议标识。
    pub protocol_id: String,
    /// 用户维护的协议版本。
    pub protocol_version: String,
    /// 安全显示名称。
    pub name: String,
    /// 可选安全说明。
    #[serde(default)]
    pub description: Option<String>,
    /// 本文件要求编译器支持的显式 Features。
    #[serde(default)]
    pub required_features: Vec<String>,
    /// 帧边界规则。
    pub framing: ProtocolFraming,
    /// 校验和；省略时使用 `none`。
    #[serde(default)]
    pub checksum: ProtocolChecksum,
    /// 可识别的消息定义。
    pub messages: Vec<ProtocolMessage>,
    /// 编译后自动执行的向量。
    #[serde(default)]
    pub test_vectors: Vec<ProtocolTestVector>,
}

/// 支持的帧边界规则。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProtocolFraming {
    /// 上层传输提供完整帧。
    Raw {
        /// 单帧最大字节数。
        max_frame_bytes: usize,
    },
    /// 使用固定分隔符划帧。
    Delimiter {
        /// 十六进制分隔符。
        delimiter_hex: String,
        /// 分隔符之前帧主体的最大字节数。
        max_frame_bytes: usize,
    },
    /// 固定长度帧。
    FixedLength {
        /// 完整帧字节数。
        length_bytes: usize,
    },
    /// 帧首包含长度字段。
    LengthPrefixed {
        /// 包含前缀后的最大帧字节数。
        max_frame_bytes: usize,
        /// 长度字段规则。
        length_prefix: LengthPrefix,
    },
}

/// 长度前缀语义。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LengthPrefix {
    /// 长度字段字节数，只允许 1、2、4。
    pub bytes: usize,
    /// 长度字段端序。
    pub endianness: Endianness,
    /// 长度值是否包含长度字段自身。
    pub includes_prefix: bool,
    /// 长度值是否包含尾部 checksum。
    pub includes_checksum: bool,
}

/// 多字节字段端序。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// 高位字节在前。
    Big,
    /// 低位字节在前。
    Little,
}

/// 校验和配置。
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolChecksum {
    /// 固定校验算法。
    #[serde(default)]
    pub kind: ProtocolChecksumKind,
    /// 校验覆盖范围。
    #[serde(default)]
    pub coverage: ChecksumCoverage,
    /// 校验值位置。
    #[serde(default)]
    pub placement: ChecksumPlacement,
}

/// 支持的固定校验算法。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolChecksumKind {
    /// 不附加校验和。
    #[default]
    None,
    /// 8 位累加和。
    Sum8,
    /// 8 位异或。
    Xor8,
    /// Modbus CRC16。
    Crc16Modbus,
    /// CCITT-FALSE CRC16。
    Crc16CcittFalse,
    /// ISO-HDLC CRC32。
    Crc32IsoHdlc,
    /// AES-CMAC（NIST AES-128）。
    AesCmac,
}

/// 校验覆盖范围。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChecksumCoverage {
    /// 覆盖 checksum 之前的全部字节。
    #[default]
    BeforeChecksum,
}

/// 校验值位置。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChecksumPlacement {
    /// 追加到帧尾。
    #[default]
    Append,
}

/// 单条消息定义。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolMessage {
    /// 稳定消息 ID。
    pub id: String,
    /// 解码消息匹配条件。
    #[serde(default, rename = "match")]
    pub match_conditions: Vec<ProtocolMatch>,
    /// 按声明顺序布局的字段。
    pub fields: Vec<ProtocolField>,
}

/// 单字段定义。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolField {
    /// 消息内唯一字段名。
    pub name: String,
    /// 固定字段类型。
    #[serde(rename = "type")]
    pub field_type: ProtocolFieldType,
    /// 多字节类型端序。
    #[serde(default)]
    pub endianness: Option<Endianness>,
    /// 固定 bytes/text 长度。
    #[serde(default)]
    pub length: Option<usize>,
    /// enum 名称到无符号值映射。
    #[serde(default)]
    pub enum_values: BTreeMap<String, u64>,
}

/// 支持的固定字段类型。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProtocolFieldType {
    /// 8 位无符号整数。
    #[serde(rename = "uint8")]
    Uint8,
    /// 16 位无符号整数。
    #[serde(rename = "uint16")]
    Uint16,
    /// 24 位无符号整数。
    #[serde(rename = "uint24")]
    Uint24,
    /// 32 位无符号整数。
    #[serde(rename = "uint32")]
    Uint32,
    /// 64 位无符号整数。
    #[serde(rename = "uint64")]
    Uint64,
    /// 8 位有符号整数。
    #[serde(rename = "int8")]
    Int8,
    /// 16 位有符号整数。
    #[serde(rename = "int16")]
    Int16,
    /// 24 位有符号整数。
    #[serde(rename = "int24")]
    Int24,
    /// 32 位有符号整数。
    #[serde(rename = "int32")]
    Int32,
    /// 64 位有符号整数。
    #[serde(rename = "int64")]
    Int64,
    /// 单字节布尔值。
    #[serde(rename = "bool8")]
    Bool8,
    /// 32 位 IEEE 浮点。
    #[serde(rename = "float32")]
    Float32,
    /// 64 位 IEEE 浮点。
    #[serde(rename = "float64")]
    Float64,
    /// 固定长度原始字节。
    #[serde(rename = "bytesFixed")]
    BytesFixed,
    /// 固定长度 ASCII。
    #[serde(rename = "asciiFixed")]
    AsciiFixed,
    /// 固定长度 UTF-8。
    #[serde(rename = "utf8Fixed")]
    Utf8Fixed,
    /// 8 位枚举。
    #[serde(rename = "enum8")]
    Enum8,
    /// 16 位枚举。
    #[serde(rename = "enum16")]
    Enum16,
}

/// 解码消息匹配条件。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolMatch {
    /// 被匹配字段名。
    pub field: String,
    /// 匹配操作符。
    pub operator: ProtocolMatchOperator,
    /// 操作符参数。
    pub value: Value,
}

/// 支持的匹配操作符。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolMatchOperator {
    /// 等于指定值。
    Equals,
    /// 不等于指定值。
    NotEquals,
    /// 属于指定数组。
    In,
    /// 位于无符号闭区间 `[min, max]`。
    UnsignedRange,
}

/// 黄金测试向量。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtocolTestVector {
    /// 协议内唯一向量名称。
    pub name: String,
    /// 编码目标消息 ID。
    pub message_id: String,
    /// 编码输入字段值。
    pub values: BTreeMap<String, Value>,
    /// 预期十六进制完整帧。
    pub encoded_hex: String,
}
