//!
//! leeway-protocol-plugin-abi
//!
//! 文件职责：定义官方协议插件的最小 C ABI 和 fixture 共用处理器契约。
//!

#![deny(unsafe_code)]

mod handler;

#[allow(unsafe_code)]
pub mod ffi;

pub use handler::{ProtocolPluginHandler, execute_handler};

/// 当前插件 ABI 主版本。
pub const PLUGIN_ABI_VERSION: u32 = 1;
/// 单次请求最大字节数。
pub const MAX_PLUGIN_REQUEST_BYTES: usize = 1024 * 1024;
/// 单次响应最大字节数。
pub const MAX_PLUGIN_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// 插件 C ABI 状态码。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum PluginAbiStatus {
    /// 已生成合法 JSON 响应。
    Success = 0,
    /// 宿主 ABI 版本不匹配。
    AbiMismatch = 1,
    /// 输出容量不足。
    OutputTooSmall = 2,
    /// 指针、长度或 JSON 请求不合法。
    InvalidRequest = 3,
    /// 插件无法生成合法响应。
    PluginError = 4,
}

/// 插件返回给宿主的唯一调用函数指针。
pub type LeewayProtocolPluginCallV1 = unsafe extern "C" fn(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32;
