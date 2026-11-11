//!
//! `ffi.rs`
//! leeway-protocol-plugin-abi / ffi
//!
//! 文件职责：隔离插件 C ABI 指针和输出缓冲区边界。
//!

use std::ptr;

use crate::{
    LeewayProtocolPluginCallV1, MAX_PLUGIN_OUTPUT_BYTES, MAX_PLUGIN_REQUEST_BYTES, PluginAbiStatus,
    ProtocolPluginHandler, execute_handler,
};

/// 校验 ABI 并在成功时写入调用函数指针。
///
/// # Safety
///
/// `out_call` 非空时必须指向宿主可写的一个函数指针槽。
pub unsafe fn write_entry(
    host_abi_version: u32,
    out_call: *mut Option<LeewayProtocolPluginCallV1>,
    call: LeewayProtocolPluginCallV1,
) -> i32 {
    if host_abi_version != crate::PLUGIN_ABI_VERSION {
        return PluginAbiStatus::AbiMismatch as i32;
    }
    if out_call.is_null() {
        return PluginAbiStatus::InvalidRequest as i32;
    }
    // SAFETY: 调用方保证非空输出槽可写，且只在 ABI 校验成功后写入。
    unsafe {
        out_call.write(Some(call));
    }
    PluginAbiStatus::Success as i32
}

/// 在宿主提供的缓冲区中执行插件处理器。
///
/// # Safety
///
/// 非空请求指针必须可读 `request_len` 字节；输出指针在容量大于零时必须可写。
pub unsafe fn invoke_handler<H: ProtocolPluginHandler + ?Sized>(
    handler: &H,
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if request_ptr.is_null()
        || output_len.is_null()
        || request_len > MAX_PLUGIN_REQUEST_BYTES
        || output_capacity > MAX_PLUGIN_OUTPUT_BYTES
        || (output_capacity > 0 && output_ptr.is_null())
    {
        return PluginAbiStatus::InvalidRequest as i32;
    }
    // SAFETY: 指针和长度已按宿主 ABI 上限完成校验。
    let request = unsafe { std::slice::from_raw_parts(request_ptr, request_len) };
    let response = match execute_handler(handler, request) {
        Ok(response) => response,
        Err(status) => return status as i32,
    };
    // SAFETY: 输出长度指针已经验证非空。
    unsafe {
        output_len.write(response.len());
    }
    if response.len() > output_capacity {
        return PluginAbiStatus::OutputTooSmall as i32;
    }
    if !response.is_empty() {
        // SAFETY: 容量已覆盖响应长度，且输出指针非空。
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(), output_ptr, response.len());
        }
    }
    PluginAbiStatus::Success as i32
}
