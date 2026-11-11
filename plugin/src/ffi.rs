// 文件职责：导出 MTR01 官方插件唯一 C ABI 入口。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

use leeway_protocol_plugin_abi::{
    LeewayProtocolPluginCallV1, PluginAbiStatus,
    ffi::{invoke_handler, write_entry},
};

use crate::Mtr01PluginHandler;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn leeway_protocol_plugin_entry_v1(
    host_abi_version: u32,
    out_call: *mut Option<LeewayProtocolPluginCallV1>,
) -> i32 {
    // SAFETY: ABI 和输出槽由安全辅助函数校验，call 指针指向进程内静态函数。
    unsafe { write_entry(host_abi_version, out_call, mtr01_call) }
}

unsafe extern "C" fn mtr01_call(
    request_ptr: *const u8,
    request_len: usize,
    output_ptr: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: 指针和长度来自宿主，并由 ABI 辅助层再次做边界校验。
        unsafe {
            invoke_handler(
                handler(),
                request_ptr,
                request_len,
                output_ptr,
                output_capacity,
                output_len,
            )
        }
    })) {
        Ok(status) => status,
        Err(_) => PluginAbiStatus::PluginError as i32,
    }
}

fn handler() -> &'static Mtr01PluginHandler {
    static HANDLER: OnceLock<Mtr01PluginHandler> = OnceLock::new();
    HANDLER.get_or_init(Mtr01PluginHandler::new)
}
