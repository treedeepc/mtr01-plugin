//
//  value.rs
//  leeway-protocol-core / codec
//
//  文件职责：定义协议字段与测试向量使用的有限类型值。
//

use std::collections::BTreeMap;

/// 单个协议字段值。
#[derive(Clone, Debug, PartialEq)]
pub enum ProtocolValue {
    /// 无符号整数和 enum 数值。
    Unsigned(u64),
    /// 有符号整数。
    Signed(i64),
    /// 布尔值。
    Bool(bool),
    /// IEEE 浮点值。
    Float(f64),
    /// 原始字节。
    Bytes(Vec<u8>),
    /// ASCII 或 UTF-8 文本。
    Text(String),
    /// 使用枚举名称表达的值。
    Enum(String),
}

/// 按字段名排序的协议值集合。
pub type ProtocolValues = BTreeMap<String, ProtocolValue>;
