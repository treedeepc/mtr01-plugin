//!
//! `handler.rs`
//! leeway-protocol-plugin-abi / handler
//!
//! 文件职责：在安全 Rust 中解析请求、调用插件业务并校验响应。
//!

use leeway_protocol_plugin_contracts::{PluginHostRequest, PluginHostResponse};

use crate::{MAX_PLUGIN_REQUEST_BYTES, PluginAbiStatus};

/// 插件业务处理器。
pub trait ProtocolPluginHandler: Send + Sync {
    /// 处理一个已认证的宿主请求。
    ///
    /// # Errors
    ///
    /// 仅 ABI 边界无法表达的状态返回 `PluginError`；可恢复协议错误必须返回
    /// `{ok:false}` 响应。
    fn handle(&self, request: &PluginHostRequest) -> Result<PluginHostResponse, PluginAbiStatus>;
}

/// 解析并执行一个宿主请求，返回经过校验的 JSON 响应。
///
/// # Errors
///
/// 请求超限或非法返回 `InvalidRequest`；处理器或响应结构失败返回 `PluginError`。
pub fn execute_handler<H: ProtocolPluginHandler + ?Sized>(
    handler: &H,
    request: &[u8],
) -> Result<Vec<u8>, PluginAbiStatus> {
    if request.is_empty() || request.len() > MAX_PLUGIN_REQUEST_BYTES {
        return Err(PluginAbiStatus::InvalidRequest);
    }
    let request: PluginHostRequest =
        serde_json::from_slice(request).map_err(|_| PluginAbiStatus::InvalidRequest)?;
    let response = handler.handle(&request)?;
    response
        .validate_for(&request)
        .map_err(|_| PluginAbiStatus::PluginError)?;
    serde_json::to_vec(&response).map_err(|_| PluginAbiStatus::PluginError)
}
