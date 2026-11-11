//!
//! `error.rs`
//! leeway-protocol-plugin-contracts / error
//!
//! 文件职责：定义插件契约内部的安全校验错误。
//!

use thiserror::Error;

/// 插件清单、配置或宿主 wire 校验错误。
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PluginContractError {
    /// 插件清单结构或语义不合法。
    #[error("Protocol plugin manifest is invalid.")]
    InvalidManifest,
    /// 插件配置 Schema 或输入值不合法。
    #[error("Protocol plugin configuration is invalid.")]
    InvalidConfiguration,
    /// 宿主响应结构与 `ok` 或 `id` 不匹配。
    #[error("Protocol plugin host response is invalid.")]
    InvalidResponse,
    /// 插件协议能力描述不合法。
    #[error("Protocol plugin descriptor is invalid.")]
    InvalidProtocolDescriptor,
}
