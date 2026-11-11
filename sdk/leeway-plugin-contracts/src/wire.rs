//!
//! `wire.rs`
//! leeway-protocol-plugin-contracts / wire
//!
//! 文件职责：定义 Runtime、插件宿主和 dylib 共用的严格 JSON wire。
//!

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{PluginConfigurationInput, PluginContractError};

/// 协议字段的封闭 wire 值。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum PluginWireValue {
    /// 无符号整数。
    Unsigned {
        /// 数值。
        value: u64,
    },
    /// 有符号整数。
    Signed {
        /// 数值。
        value: i64,
    },
    /// 布尔值。
    Bool {
        /// 数值。
        value: bool,
    },
    /// 有限浮点数。
    Float {
        /// 数值。
        value: f64,
    },
    /// 标准 Base64 字节。
    Bytes {
        /// Base64 文本。
        base64: String,
    },
    /// UTF-8 文本。
    Text {
        /// 文本值。
        value: String,
    },
    /// 稳定枚举名称。
    Enum {
        /// 枚举名称。
        value: String,
    },
}

/// 插件宿主操作。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginOperation {
    /// 获取协议定义摘要。
    Describe,
    /// 创建协议实例。
    Create,
    /// 销毁协议实例。
    Destroy,
    /// 编码协议帧。
    Encode,
    /// 解码协议帧。
    Decode,
    /// 创建流式解码器。
    StreamCreate,
    /// 推入流式字节。
    StreamPush,
    /// 销毁流式解码器。
    StreamDestroy,
}

impl PluginOperation {
    /// 全部八个 v1 操作。
    pub const ALL: [Self; 8] = [
        Self::Describe,
        Self::Create,
        Self::Destroy,
        Self::Encode,
        Self::Decode,
        Self::StreamCreate,
        Self::StreamPush,
        Self::StreamDestroy,
    ];

    /// 返回稳定 JSON 操作名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Create => "create",
            Self::Destroy => "destroy",
            Self::Encode => "encode",
            Self::Decode => "decode",
            Self::StreamCreate => "streamCreate",
            Self::StreamPush => "streamPush",
            Self::StreamDestroy => "streamDestroy",
        }
    }
}

/// 插件宿主请求。
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "op",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PluginHostRequest {
    /// 获取协议定义。
    Describe {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
    },
    /// 创建协议实例。
    Create {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 已解码配置。
        config: PluginConfigurationInput,
    },
    /// 销毁协议实例。
    Destroy {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明实例句柄。
        handle: u64,
    },
    /// 编码协议帧。
    Encode {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明实例句柄。
        handle: u64,
        /// 稳定消息 ID。
        message_id: String,
        /// 字段值。
        values: BTreeMap<String, PluginWireValue>,
    },
    /// 解码完整帧。
    Decode {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明实例句柄。
        handle: u64,
        /// Standard Base64 帧。
        frame_base64: String,
    },
    /// 创建流式解码器。
    StreamCreate {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明实例句柄。
        handle: u64,
    },
    /// 推入流式字节。
    StreamPush {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明流句柄。
        stream_handle: u64,
        /// Standard Base64 输入。
        bytes_base64: String,
    },
    /// 销毁流式解码器。
    StreamDestroy {
        /// 单调请求 ID。
        id: u64,
        /// 宿主 ABI 版本。
        abi_version: u32,
        /// 不透明流句柄。
        stream_handle: u64,
    },
}

impl std::fmt::Debug for PluginHostRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Describe { id, abi_version } => formatter
                .debug_struct("Describe")
                .field("id", id)
                .field("abi_version", abi_version)
                .finish(),
            Self::Create {
                id, abi_version, ..
            } => formatter
                .debug_struct("Create")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("config", &"[REDACTED]")
                .finish(),
            Self::Destroy {
                id,
                abi_version,
                handle,
            } => formatter
                .debug_struct("Destroy")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("handle", handle)
                .finish(),
            Self::Encode {
                id,
                abi_version,
                handle,
                message_id,
                values,
            } => formatter
                .debug_struct("Encode")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("handle", handle)
                .field("message_id", message_id)
                .field("values", values)
                .finish(),
            Self::Decode {
                id,
                abi_version,
                handle,
                frame_base64,
            } => formatter
                .debug_struct("Decode")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("handle", handle)
                .field("frame_base64", frame_base64)
                .finish(),
            Self::StreamCreate {
                id,
                abi_version,
                handle,
            } => formatter
                .debug_struct("StreamCreate")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("handle", handle)
                .finish(),
            Self::StreamPush {
                id,
                abi_version,
                stream_handle,
                bytes_base64,
            } => formatter
                .debug_struct("StreamPush")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("stream_handle", stream_handle)
                .field("bytes_base64", bytes_base64)
                .finish(),
            Self::StreamDestroy {
                id,
                abi_version,
                stream_handle,
            } => formatter
                .debug_struct("StreamDestroy")
                .field("id", id)
                .field("abi_version", abi_version)
                .field("stream_handle", stream_handle)
                .finish(),
        }
    }
}

impl PluginHostRequest {
    /// 返回请求 ID。
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Describe { id, .. }
            | Self::Create { id, .. }
            | Self::Destroy { id, .. }
            | Self::Encode { id, .. }
            | Self::Decode { id, .. }
            | Self::StreamCreate { id, .. }
            | Self::StreamPush { id, .. }
            | Self::StreamDestroy { id, .. } => *id,
        }
    }

    /// 返回稳定操作。
    #[must_use]
    pub const fn operation(&self) -> PluginOperation {
        match self {
            Self::Describe { .. } => PluginOperation::Describe,
            Self::Create { .. } => PluginOperation::Create,
            Self::Destroy { .. } => PluginOperation::Destroy,
            Self::Encode { .. } => PluginOperation::Encode,
            Self::Decode { .. } => PluginOperation::Decode,
            Self::StreamCreate { .. } => PluginOperation::StreamCreate,
            Self::StreamPush { .. } => PluginOperation::StreamPush,
            Self::StreamDestroy { .. } => PluginOperation::StreamDestroy,
        }
    }
}

/// 插件宿主响应。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginHostResponse {
    /// 对应请求 ID。
    pub id: u64,
    /// 是否成功。
    pub ok: bool,
    /// 成功结果。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// 可恢复协议错误。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<PluginWireError>,
}

impl PluginHostResponse {
    /// 校验请求 ID、互斥载荷和操作结果形状。
    ///
    /// # Errors
    ///
    /// ID 不匹配、`result/error` 组合非法、错误路径越界或结果形状不匹配时返回错误。
    pub fn validate_for(&self, request: &PluginHostRequest) -> Result<(), PluginContractError> {
        if self.id != request.id() {
            return Err(PluginContractError::InvalidResponse);
        }
        if self.ok {
            if self.error.is_some() {
                return Err(PluginContractError::InvalidResponse);
            }
            let Some(result) = &self.result else {
                return Err(PluginContractError::InvalidResponse);
            };
            validate_success_result(request.operation(), result)
        } else {
            if self.result.is_some() {
                return Err(PluginContractError::InvalidResponse);
            }
            let Some(error) = &self.error else {
                return Err(PluginContractError::InvalidResponse);
            };
            error.validate()
        }
    }
}

/// 插件宿主可恢复错误。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginWireError {
    /// 稳定机器错误码。
    pub code: PluginWireErrorCode,
    /// 有界 JSON 路径。
    pub path: String,
    /// 可选稳定消息 ID。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

impl PluginWireError {
    fn validate(&self) -> Result<(), PluginContractError> {
        if !self.path.starts_with('$')
            || self.path.len() > 512
            || self
                .message_id
                .as_ref()
                .is_some_and(|value| value.len() > 128)
        {
            return Err(PluginContractError::InvalidResponse);
        }
        Ok(())
    }
}

/// 插件宿主稳定错误码。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginWireErrorCode {
    /// ABI 不兼容。
    AbiMismatch,
    /// 请求结构不合法。
    InvalidRequest,
    /// 缺少必需配置。
    ConfigurationRequired,
    /// 配置值不合法。
    ConfigurationInvalid,
    /// 消息 ID 未声明。
    UnknownMessage,
    /// 字段值不合法。
    InvalidFieldValue,
    /// 缺少校验密钥。
    MissingChecksumKey,
    /// 帧结构不合法。
    MalformedFrame,
    /// 帧校验失败。
    ChecksumMismatch,
    /// 字段类型不支持。
    UnsupportedType,
    /// 有界容量溢出。
    CapacityOverflow,
    /// 消息编码失败。
    MessageEncodeFailed,
    /// 帧解码失败。
    FrameDecodeFailed,
    /// 插件内部失败。
    InternalPluginError,
}

fn validate_success_result(
    operation: PluginOperation,
    result: &Value,
) -> Result<(), PluginContractError> {
    let object = result
        .as_object()
        .ok_or(PluginContractError::InvalidResponse)?;
    match operation {
        PluginOperation::Describe => exact_object(object, &["protocolDefinition"])?,
        PluginOperation::Create => {
            exact_object(object, &["handle"])?;
            unsigned_member(object, "handle")?;
        }
        PluginOperation::Destroy | PluginOperation::StreamDestroy => {
            exact_object(object, &[])?;
        }
        PluginOperation::Encode => {
            exact_object(object, &["frameBase64"])?;
            base64_member(object, "frameBase64")?;
        }
        PluginOperation::Decode => {
            exact_object(object, &["messageId", "values", "rawBase64"])?;
            let message_id = object
                .get("messageId")
                .and_then(Value::as_str)
                .ok_or(PluginContractError::InvalidResponse)?;
            if message_id.is_empty() || message_id.len() > 128 {
                return Err(PluginContractError::InvalidResponse);
            }
            if !object.get("values").is_some_and(Value::is_object) {
                return Err(PluginContractError::InvalidResponse);
            }
            base64_member(object, "rawBase64")?;
        }
        PluginOperation::StreamCreate => {
            exact_object(object, &["streamHandle"])?;
            unsigned_member(object, "streamHandle")?;
        }
        PluginOperation::StreamPush => {
            exact_object(object, &["framesBase64"])?;
            let frames = object
                .get("framesBase64")
                .and_then(Value::as_array)
                .ok_or(PluginContractError::InvalidResponse)?;
            if frames.iter().any(|frame| {
                frame
                    .as_str()
                    .and_then(|value| STANDARD.decode(value).ok())
                    .is_none()
            }) {
                return Err(PluginContractError::InvalidResponse);
            }
        }
    }
    Ok(())
}

fn exact_object(object: &Map<String, Value>, keys: &[&str]) -> Result<(), PluginContractError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(PluginContractError::InvalidResponse);
    }
    Ok(())
}

fn unsigned_member(object: &Map<String, Value>, key: &str) -> Result<(), PluginContractError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .map(|_| ())
        .ok_or(PluginContractError::InvalidResponse)
}

fn base64_member(object: &Map<String, Value>, key: &str) -> Result<(), PluginContractError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| STANDARD.decode(value).ok())
        .map(|_| ())
        .ok_or(PluginContractError::InvalidResponse)
}
