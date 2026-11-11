//! 新版 Leeway 的版本化协议 JSON 契约。
//!
//! 本 crate 只定义可反序列化文档、能力枚举和诊断，不执行编译或字节编解码。

#![forbid(unsafe_code)]

mod diagnostic;
mod document;

pub use diagnostic::{ProtocolDiagnostic, ProtocolDiagnosticCode};
pub use document::{
    ChecksumCoverage, ChecksumPlacement, Endianness, LengthPrefix, MAX_PROTOCOL_BYTES,
    MAX_PROTOCOL_FIELDS_PER_MESSAGE, MAX_PROTOCOL_MESSAGES, MAX_PROTOCOL_TEST_VECTORS,
    PROTOCOL_SCHEMA_VERSION, ProtocolChecksum, ProtocolChecksumKind, ProtocolDocument,
    ProtocolField, ProtocolFieldType, ProtocolFraming, ProtocolMatch, ProtocolMatchOperator,
    ProtocolMessage, ProtocolTestVector,
};
