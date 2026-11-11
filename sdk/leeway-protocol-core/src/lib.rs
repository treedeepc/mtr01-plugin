//! 新版 Leeway 的 Protocol DSL 编译器与编解码核心。
//!
//! 本 crate 不执行传输、状态机、文件、Runtime 或 AI I/O。

#![forbid(unsafe_code)]

mod adapter;
pub mod checksum;
mod codec;
mod compiler;
mod framing;
mod ir;
mod stream_decoder;
mod value;

pub use adapter::{ProtocolAdapter, ProtocolStreamAdapter};
pub use checksum::AesCmacKey;
pub use codec::DecodedFrame;
pub use compiler::ProtocolCompiler;
pub use ir::CompiledProtocol;
pub use stream_decoder::{MAX_STREAM_INPUT_BYTES, ProtocolStreamDecoder};
pub use value::{ProtocolValue, ProtocolValues};
