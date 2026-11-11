//!
//! leeway-protocol-mtr01-plugin
//!
//! 文件职责：把 MTR01 静态协议适配器封装为官方动态插件。
//!

#![deny(unsafe_code)]

mod handler;

#[allow(unsafe_code)]
mod ffi;

pub use handler::Mtr01PluginHandler;
