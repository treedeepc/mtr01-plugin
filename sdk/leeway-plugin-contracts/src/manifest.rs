//!
//! `manifest.rs`
//! leeway-protocol-plugin-contracts / manifest
//!
//! 文件职责：定义严格版本化的官方协议插件清单。
//!

use serde::{Deserialize, Serialize};

/// 官方协议插件清单。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginManifest {
    /// 清单 Schema 版本。
    pub schema_version: u32,
    /// 稳定插件 ID。
    pub plugin_id: String,
    /// 用户可见插件名称。
    pub name: String,
    /// 插件版本。
    pub version: String,
    /// 发布者名称。
    pub publisher: String,
    /// 插件 ABI 主版本。
    pub abi_version: u32,
    /// 稳定协议 ID。
    pub protocol_id: String,
    /// 协议版本。
    pub protocol_version: String,
    /// Bundle 内 dylib 相对路径。
    pub library: String,
    /// Bundle 内协议定义相对路径。
    pub protocol_file: String,
    /// Bundle 内默认场景相对路径。
    pub scenario_file: String,
    /// Bundle 内配置模型相对路径。
    pub configuration_file: String,
    /// 支持的 CPU 架构。
    pub architectures: Vec<String>,
    /// Bundle 固定文件摘要。
    pub files: PluginFileHashes,
}

/// 插件 Bundle 固定文件摘要。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginFileHashes {
    /// dylib SHA-256。
    pub library_sha256: String,
    /// 协议定义 SHA-256。
    pub protocol_sha256: String,
    /// 默认场景 SHA-256。
    pub scenario_sha256: String,
    /// 配置模型 SHA-256。
    pub configuration_sha256: String,
}
