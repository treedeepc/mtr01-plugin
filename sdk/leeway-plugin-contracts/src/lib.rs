//!
//! leeway-protocol-plugin-contracts
//!
//! 文件职责：定义官方协议插件清单、配置和宿主 wire 契约。
//!

#![forbid(unsafe_code)]

mod configuration;
mod descriptor;
mod error;
mod manifest;
mod wire;

pub use configuration::{
    MAX_PLUGIN_CONFIGURATION_FIELDS, PluginConfigurationField, PluginConfigurationInput,
    PluginConfigurationSchema, PluginFieldEncoding, PluginFieldType,
};
pub use descriptor::{
    PluginBleProfile, PluginFieldEndianness, PluginFixedLayoutField, PluginFramingDescriptor,
    PluginMessageDescriptor, PluginMessagePayload, PluginProtocolDescriptor,
};
pub use error::PluginContractError;
pub use manifest::{PluginFileHashes, PluginManifest};
pub use wire::{
    PluginHostRequest, PluginHostResponse, PluginOperation, PluginWireError, PluginWireErrorCode,
    PluginWireValue,
};
