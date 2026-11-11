// 文件职责：在插件 wire 与既有 MTR01 适配器之间管理配置、实例和流。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use leeway_protocol_contracts::{ProtocolDiagnostic, ProtocolDiagnosticCode};
use leeway_protocol_core::{ProtocolAdapter, ProtocolStreamAdapter, ProtocolValue, ProtocolValues};
use leeway_protocol_mtr01::Mtr01Adapter;
use leeway_protocol_plugin_abi::{PLUGIN_ABI_VERSION, PluginAbiStatus, ProtocolPluginHandler};
use leeway_protocol_plugin_contracts::{
    PluginHostRequest, PluginHostResponse, PluginWireError, PluginWireErrorCode, PluginWireValue,
};
use serde_json::json;

const CONFIGURATION_KEY: &str = "cmacKey";

struct Instance {
    adapter: Mtr01Adapter,
}

struct Stream {
    adapter_handle: u64,
    decoder: Box<dyn ProtocolStreamAdapter>,
}

#[derive(Default)]
struct HandlerState {
    next_handle: u64,
    next_stream_handle: u64,
    instances: BTreeMap<u64, Instance>,
    streams: BTreeMap<u64, Stream>,
}

/// MTR01 官方插件处理器。
pub struct Mtr01PluginHandler {
    state: Mutex<HandlerState>,
}

impl Default for Mtr01PluginHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Mtr01PluginHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        formatter
            .debug_struct("Mtr01PluginHandler")
            .field(
                "instances",
                &state.as_ref().map(|value| value.instances.len()).ok(),
            )
            .field(
                "streams",
                &state.as_ref().map(|value| value.streams.len()).ok(),
            )
            .finish_non_exhaustive()
    }
}

impl Mtr01PluginHandler {
    /// 创建无实例的 MTR01 插件处理器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HandlerState::default()),
        }
    }

    fn handle_request(
        &self,
        request: &PluginHostRequest,
    ) -> Result<PluginHostResponse, PluginAbiStatus> {
        if abi_version(request) != PLUGIN_ABI_VERSION {
            return Err(PluginAbiStatus::AbiMismatch);
        }
        let id = request.id();
        let response = match request {
            PluginHostRequest::Describe { .. } => success(
                id,
                json!({
                    "protocolDefinition": Mtr01Adapter::new([0; 16]).definition()
                }),
            ),
            PluginHostRequest::Create { config, .. } => self.create(id, config.values()),
            PluginHostRequest::Destroy { handle, .. } => self.destroy(id, *handle),
            PluginHostRequest::Encode {
                handle,
                message_id,
                values,
                ..
            } => self.encode(id, *handle, message_id, values),
            PluginHostRequest::Decode {
                handle,
                frame_base64,
                ..
            } => self.decode(id, *handle, frame_base64),
            PluginHostRequest::StreamCreate { handle, .. } => self.stream_create(id, *handle),
            PluginHostRequest::StreamPush {
                stream_handle,
                bytes_base64,
                ..
            } => self.stream_push(id, *stream_handle, bytes_base64),
            PluginHostRequest::StreamDestroy { stream_handle, .. } => {
                self.stream_destroy(id, *stream_handle)
            }
        };
        Ok(response)
    }

    fn create(&self, id: u64, config: &BTreeMap<String, PluginWireValue>) -> PluginHostResponse {
        if !config.contains_key(CONFIGURATION_KEY) {
            return configured_failure(
                id,
                PluginWireErrorCode::ConfigurationRequired,
                "$.config.cmacKey",
            );
        }
        if config.len() != 1 {
            return configured_failure(id, PluginWireErrorCode::ConfigurationInvalid, "$.config");
        }
        let Some(PluginWireValue::Bytes { base64 }) = config.get(CONFIGURATION_KEY) else {
            return configured_failure(
                id,
                PluginWireErrorCode::ConfigurationInvalid,
                "$.config.cmacKey",
            );
        };
        let Ok(bytes) = STANDARD.decode(base64) else {
            return configured_failure(
                id,
                PluginWireErrorCode::ConfigurationInvalid,
                "$.config.cmacKey",
            );
        };
        let Ok(mut key) = <[u8; 16]>::try_from(bytes) else {
            return configured_failure(
                id,
                PluginWireErrorCode::ConfigurationInvalid,
                "$.config.cmacKey",
            );
        };
        let adapter = Mtr01Adapter::new(key);
        key.fill(0);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        let Some(handle) = state.next_handle.checked_add(1) else {
            return internal_failure(id);
        };
        state.next_handle = handle;
        state.instances.insert(handle, Instance { adapter });
        success(id, json!({"handle": handle}))
    }

    fn destroy(&self, id: u64, handle: u64) -> PluginHostResponse {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        if state.instances.remove(&handle).is_none() {
            return invalid_handle(id, "$.handle");
        }
        state
            .streams
            .retain(|_, stream| stream.adapter_handle != handle);
        success(id, json!({}))
    }

    fn encode(
        &self,
        id: u64,
        handle: u64,
        message_id: &str,
        values: &BTreeMap<String, PluginWireValue>,
    ) -> PluginHostResponse {
        let Some(payload) = payload_bytes(values) else {
            return configured_failure(
                id,
                PluginWireErrorCode::InvalidFieldValue,
                "$.values.payload",
            );
        };
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        let Some(instance) = state.instances.get(&handle) else {
            return invalid_handle(id, "$.handle");
        };
        let values = ProtocolValues::from([("payload".to_owned(), ProtocolValue::Bytes(payload))]);
        match instance.adapter.encode(message_id, &values) {
            Ok(frame) => success(
                id,
                json!({
                    "frameBase64": STANDARD.encode(frame)
                }),
            ),
            Err(error) => diagnostic_failure(id, &error),
        }
    }

    fn decode(&self, id: u64, handle: u64, frame_base64: &str) -> PluginHostResponse {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        let Some(instance) = state.instances.get(&handle) else {
            return invalid_handle(id, "$.handle");
        };
        let Ok(frame) = STANDARD.decode(frame_base64) else {
            return configured_failure(id, PluginWireErrorCode::MalformedFrame, "$.frameBase64");
        };
        match instance.adapter.decode(&frame) {
            Ok(decoded) => {
                let values = decoded
                    .values
                    .into_iter()
                    .filter_map(|(name, value)| {
                        protocol_value_to_wire(value).map(|value| (name, value))
                    })
                    .collect::<BTreeMap<_, _>>();
                success(
                    id,
                    json!({
                        "messageId": decoded.message_id,
                        "values": values,
                        "rawBase64": STANDARD.encode(decoded.raw_bytes)
                    }),
                )
            }
            Err(error) => diagnostic_failure(id, &error),
        }
    }

    fn stream_create(&self, id: u64, handle: u64) -> PluginHostResponse {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        let Some(instance) = state.instances.get(&handle) else {
            return invalid_handle(id, "$.handle");
        };
        let decoder = match instance.adapter.stream_decoder() {
            Ok(decoder) => decoder,
            Err(error) => return diagnostic_failure(id, &error),
        };
        let Some(stream_handle) = state.next_stream_handle.checked_add(1) else {
            return internal_failure(id);
        };
        state.next_stream_handle = stream_handle;
        state.streams.insert(
            stream_handle,
            Stream {
                adapter_handle: handle,
                decoder,
            },
        );
        success(id, json!({"streamHandle": stream_handle}))
    }

    fn stream_push(&self, id: u64, stream_handle: u64, bytes_base64: &str) -> PluginHostResponse {
        let Ok(bytes) = STANDARD.decode(bytes_base64) else {
            return configured_failure(id, PluginWireErrorCode::MalformedFrame, "$.bytesBase64");
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        let Some(stream) = state.streams.get_mut(&stream_handle) else {
            return invalid_handle(id, "$.streamHandle");
        };
        match stream.decoder.push(&bytes) {
            Ok(frames) => success(
                id,
                json!({
                    "framesBase64": frames
                        .into_iter()
                        .map(|frame| STANDARD.encode(frame))
                        .collect::<Vec<_>>()
                }),
            ),
            Err(error) => diagnostic_failure(id, &error),
        }
    }

    fn stream_destroy(&self, id: u64, stream_handle: u64) -> PluginHostResponse {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return internal_failure(id),
        };
        if state.streams.remove(&stream_handle).is_none() {
            return invalid_handle(id, "$.streamHandle");
        }
        success(id, json!({}))
    }
}

impl ProtocolPluginHandler for Mtr01PluginHandler {
    fn handle(&self, request: &PluginHostRequest) -> Result<PluginHostResponse, PluginAbiStatus> {
        self.handle_request(request)
    }
}

fn abi_version(request: &PluginHostRequest) -> u32 {
    match request {
        PluginHostRequest::Describe { abi_version, .. }
        | PluginHostRequest::Create { abi_version, .. }
        | PluginHostRequest::Destroy { abi_version, .. }
        | PluginHostRequest::Encode { abi_version, .. }
        | PluginHostRequest::Decode { abi_version, .. }
        | PluginHostRequest::StreamCreate { abi_version, .. }
        | PluginHostRequest::StreamPush { abi_version, .. }
        | PluginHostRequest::StreamDestroy { abi_version, .. } => *abi_version,
    }
}

fn payload_bytes(values: &BTreeMap<String, PluginWireValue>) -> Option<Vec<u8>> {
    if values.len() != 1 {
        return None;
    }
    let PluginWireValue::Bytes { base64 } = values.get("payload")? else {
        return None;
    };
    STANDARD.decode(base64).ok()
}

fn protocol_value_to_wire(value: ProtocolValue) -> Option<PluginWireValue> {
    match value {
        ProtocolValue::Unsigned(value) => Some(PluginWireValue::Unsigned { value }),
        ProtocolValue::Signed(value) => Some(PluginWireValue::Signed { value }),
        ProtocolValue::Bool(value) => Some(PluginWireValue::Bool { value }),
        ProtocolValue::Float(value) if value.is_finite() => Some(PluginWireValue::Float { value }),
        ProtocolValue::Float(_) => None,
        ProtocolValue::Bytes(value) => Some(PluginWireValue::Bytes {
            base64: STANDARD.encode(value),
        }),
        ProtocolValue::Text(value) => Some(PluginWireValue::Text { value }),
        ProtocolValue::Enum(value) => Some(PluginWireValue::Enum { value }),
    }
}

fn diagnostic_failure(id: u64, diagnostic: &ProtocolDiagnostic) -> PluginHostResponse {
    let code = match diagnostic.code {
        ProtocolDiagnosticCode::UnknownMessage => PluginWireErrorCode::UnknownMessage,
        ProtocolDiagnosticCode::MissingChecksumKey => PluginWireErrorCode::MissingChecksumKey,
        ProtocolDiagnosticCode::ChecksumMismatch => PluginWireErrorCode::ChecksumMismatch,
        ProtocolDiagnosticCode::FrameTooLarge => PluginWireErrorCode::CapacityOverflow,
        ProtocolDiagnosticCode::InvalidFieldValue | ProtocolDiagnosticCode::UnknownField => {
            PluginWireErrorCode::InvalidFieldValue
        }
        ProtocolDiagnosticCode::MalformedFrame => PluginWireErrorCode::MalformedFrame,
        _ => PluginWireErrorCode::FrameDecodeFailed,
    };
    PluginHostResponse {
        id,
        ok: false,
        result: None,
        error: Some(PluginWireError {
            code,
            path: bounded_path(&diagnostic.path),
            message_id: None,
        }),
    }
}

fn configured_failure(id: u64, code: PluginWireErrorCode, path: &str) -> PluginHostResponse {
    PluginHostResponse {
        id,
        ok: false,
        result: None,
        error: Some(PluginWireError {
            code,
            path: path.into(),
            message_id: None,
        }),
    }
}

fn invalid_handle(id: u64, path: &str) -> PluginHostResponse {
    configured_failure(id, PluginWireErrorCode::InvalidRequest, path)
}

fn internal_failure(id: u64) -> PluginHostResponse {
    configured_failure(id, PluginWireErrorCode::InternalPluginError, "$.plugin")
}

fn bounded_path(path: &str) -> String {
    if path.starts_with('$') && path.len() <= 512 {
        path.to_owned()
    } else {
        "$.plugin".into()
    }
}

fn success(id: u64, result: serde_json::Value) -> PluginHostResponse {
    PluginHostResponse {
        id,
        ok: true,
        result: Some(result),
        error: None,
    }
}
