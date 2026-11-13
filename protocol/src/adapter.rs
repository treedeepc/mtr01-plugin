//
//  adapter.rs
//  leeway-protocol-mtr01
//
//  文件职责：把 MTR01 编解码器适配为模拟器通用协议接口。
//

use leeway_protocol_contracts::{ProtocolDiagnostic, ProtocolDiagnosticCode};
use leeway_protocol_core::{
    DecodedFrame, ProtocolAdapter, ProtocolStreamAdapter, ProtocolValue, ProtocolValues,
};
use serde_json::Value;

use crate::{
    Mtr01AData, Mtr01ARequest, Mtr01BRequest, Mtr01BResponse, Mtr01BindingRequest,
    Mtr01BindingResponse, Mtr01CRequest, Mtr01CResponse, Mtr01Codec, Mtr01Command, Mtr01Error,
    Mtr01StreamDecoder,
};

/// A# 订阅消息 ID。
pub const MTR01_MESSAGE_A_SUBSCRIBE: &str = "aSubscribe";
/// A# 取消订阅消息 ID。
pub const MTR01_MESSAGE_A_UNSUBSCRIBE: &str = "aUnsubscribe";
/// A# 单次读取消息 ID。
pub const MTR01_MESSAGE_A_ONCE: &str = "aOnce";
/// A@ 实时数据消息 ID。
pub const MTR01_MESSAGE_A_DATA: &str = "aData";
/// B# cmd 00 获取设备信息。
pub const MTR01_MESSAGE_B_GET_INFO: &str = "bGetInfo";
/// B# cmd 01 基础配置。
pub const MTR01_MESSAGE_B_BASIC_CONFIG: &str = "bBasicConfig";
/// B# cmd 02 运行参数。
pub const MTR01_MESSAGE_B_RUNTIME_CONFIG: &str = "bRuntimeConfig";
/// B# cmd 03 身份信息。
pub const MTR01_MESSAGE_B_IDENTITY_CONFIG: &str = "bIdentityConfig";
/// B# cmd 04 校准控制。
pub const MTR01_MESSAGE_B_CALIBRATION_CONTROL: &str = "bCalibrationControl";
/// B@ cmd 00 设备信息。
pub const MTR01_MESSAGE_B_DEVICE_INFO: &str = "bDeviceInfo";
/// B@ cmd 01 基础配置反馈。
pub const MTR01_MESSAGE_B_BASIC_FEEDBACK: &str = "bBasicConfigFeedback";
/// B@ cmd 02 运行参数反馈。
pub const MTR01_MESSAGE_B_RUNTIME_FEEDBACK: &str = "bRuntimeConfigFeedback";
/// B@ cmd 03 身份配置反馈。
pub const MTR01_MESSAGE_B_IDENTITY_FEEDBACK: &str = "bIdentityConfigFeedback";
/// C# cmd 01 扫描请求。
pub const MTR01_MESSAGE_C_SCAN_REQUEST: &str = "cScanRequest";
/// C# cmd 02 连接控制。
pub const MTR01_MESSAGE_C_CONNECT_CONTROL: &str = "cConnectControl";
/// C# cmd 02 control 03 断开并解绑。
pub const MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND: &str = "cDisconnectAndUnbind";
/// C@ cmd 02 连接反馈。
pub const MTR01_MESSAGE_C_CONNECTION_FEEDBACK: &str = "cConnectionFeedback";
/// C@ cmd 01 扫描列表。
pub const MTR01_MESSAGE_C_SCAN_LIST: &str = "cScanList";
/// C@ cmd 01 扫描错误。
pub const MTR01_MESSAGE_C_SCAN_ERROR: &str = "cScanError";
/// D# 未绑定消息 ID。
pub const MTR01_MESSAGE_D_UNBOUND: &str = "dUnbound";
/// D# 已绑定或绑定配置消息 ID。
pub const MTR01_MESSAGE_D_BOUND: &str = "dBound";
/// D@ 深度绑定应答消息 ID。
pub const MTR01_MESSAGE_D_RESPONSE: &str = "dResponse";

const MESSAGE_IDS: [&str; 22] = [
    MTR01_MESSAGE_A_SUBSCRIBE,
    MTR01_MESSAGE_A_UNSUBSCRIBE,
    MTR01_MESSAGE_A_ONCE,
    MTR01_MESSAGE_A_DATA,
    MTR01_MESSAGE_B_GET_INFO,
    MTR01_MESSAGE_B_BASIC_CONFIG,
    MTR01_MESSAGE_B_RUNTIME_CONFIG,
    MTR01_MESSAGE_B_IDENTITY_CONFIG,
    MTR01_MESSAGE_B_CALIBRATION_CONTROL,
    MTR01_MESSAGE_B_DEVICE_INFO,
    MTR01_MESSAGE_B_BASIC_FEEDBACK,
    MTR01_MESSAGE_B_RUNTIME_FEEDBACK,
    MTR01_MESSAGE_B_IDENTITY_FEEDBACK,
    MTR01_MESSAGE_C_SCAN_REQUEST,
    MTR01_MESSAGE_C_CONNECT_CONTROL,
    MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND,
    MTR01_MESSAGE_C_CONNECTION_FEEDBACK,
    MTR01_MESSAGE_C_SCAN_LIST,
    MTR01_MESSAGE_C_SCAN_ERROR,
    MTR01_MESSAGE_D_UNBOUND,
    MTR01_MESSAGE_D_BOUND,
    MTR01_MESSAGE_D_RESPONSE,
];

/// 可注入模拟器引擎的 MTR01 协议适配器。
pub struct Mtr01Adapter {
    codec: Mtr01Codec,
}

impl Mtr01Adapter {
    /// 使用带外 16 字节 AES-CMAC 密钥创建适配器。
    #[must_use]
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            codec: Mtr01Codec::new(key),
        }
    }
}

impl std::fmt::Debug for Mtr01Adapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Mtr01Adapter { codec: Mtr01Codec([REDACTED]) }")
    }
}

impl ProtocolAdapter for Mtr01Adapter {
    fn protocol_id(&self) -> &'static str {
        "mtr01-protocol"
    }

    fn protocol_version(&self) -> &'static str {
        "1.5.1"
    }

    fn definition(&self) -> Value {
        crate::definition::protocol_definition()
    }

    fn has_message(&self, message_id: &str) -> bool {
        MESSAGE_IDS.contains(&message_id)
    }

    fn encode(
        &self,
        message_id: &str,
        values: &ProtocolValues,
    ) -> Result<Vec<u8>, ProtocolDiagnostic> {
        let payload = payload_only(values)?;
        let command = validate_payload(message_id, payload)?;
        self.codec
            .encode(command, payload)
            .map_err(|error| adapter_error(error, "$.actions"))
    }

    fn decode(&self, frame: &[u8]) -> Result<DecodedFrame, ProtocolDiagnostic> {
        let decoded = self
            .codec
            .decode(frame)
            .map_err(|error| adapter_error(error, "$.frame"))?;
        let message_id = message_id_for(decoded.command, &decoded.payload)?;
        Ok(DecodedFrame {
            message_id: message_id.to_owned(),
            values: ProtocolValues::from([(
                "payload".to_owned(),
                ProtocolValue::Bytes(decoded.payload),
            )]),
            raw_bytes: frame.to_vec(),
        })
    }

    fn stream_decoder(&self) -> Result<Box<dyn ProtocolStreamAdapter>, ProtocolDiagnostic> {
        Ok(Box::new(Mtr01StreamDecoder::new()))
    }
}

impl ProtocolStreamAdapter for Mtr01StreamDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProtocolDiagnostic> {
        Mtr01StreamDecoder::push(self, bytes).map_err(|error| adapter_error(error, "$.frame"))
    }
}

fn payload_only(values: &ProtocolValues) -> Result<&[u8], ProtocolDiagnostic> {
    if values.len() != 1 {
        return Err(adapter_diagnostic(
            ProtocolDiagnosticCode::InvalidFieldValue,
            "$.actions.values",
            "MTR01 actions must provide exactly one payload field.",
        ));
    }
    match values.get("payload") {
        Some(ProtocolValue::Bytes(payload)) => Ok(payload),
        _ => Err(adapter_diagnostic(
            ProtocolDiagnosticCode::InvalidFieldValue,
            "$.actions.values.payload",
            "MTR01 action payload must be raw bytes.",
        )),
    }
}

fn validate_payload(message_id: &str, payload: &[u8]) -> Result<Mtr01Command, ProtocolDiagnostic> {
    match message_id {
        MTR01_MESSAGE_A_SUBSCRIBE => {
            if Mtr01ARequest::from_payload(payload).map_err(payload_error)?
                != Mtr01ARequest::Subscribe
            {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::ARequest)
        }
        MTR01_MESSAGE_A_UNSUBSCRIBE => {
            if Mtr01ARequest::from_payload(payload).map_err(payload_error)?
                != Mtr01ARequest::Unsubscribe
            {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::ARequest)
        }
        MTR01_MESSAGE_A_ONCE => {
            if Mtr01ARequest::from_payload(payload).map_err(payload_error)?
                != Mtr01ARequest::ReadOnce
            {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::ARequest)
        }
        MTR01_MESSAGE_A_DATA => {
            Mtr01AData::from_payload(payload).map_err(payload_error)?;
            Ok(Mtr01Command::AResponse)
        }
        MTR01_MESSAGE_B_GET_INFO
        | MTR01_MESSAGE_B_BASIC_CONFIG
        | MTR01_MESSAGE_B_RUNTIME_CONFIG
        | MTR01_MESSAGE_B_IDENTITY_CONFIG
        | MTR01_MESSAGE_B_CALIBRATION_CONTROL => {
            let request = Mtr01BRequest::from_payload(payload).map_err(payload_error)?;
            if !b_request_matches(message_id, &request) {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::BRequest)
        }
        MTR01_MESSAGE_B_DEVICE_INFO
        | MTR01_MESSAGE_B_BASIC_FEEDBACK
        | MTR01_MESSAGE_B_RUNTIME_FEEDBACK
        | MTR01_MESSAGE_B_IDENTITY_FEEDBACK => {
            let response = Mtr01BResponse::from_payload(payload).map_err(payload_error)?;
            if b_response_message_id(&response) != message_id {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::BResponse)
        }
        MTR01_MESSAGE_C_SCAN_REQUEST
        | MTR01_MESSAGE_C_CONNECT_CONTROL
        | MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND => {
            let request = Mtr01CRequest::from_payload(payload).map_err(payload_error)?;
            if c_request_message_id(request) != message_id {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::CRequest)
        }
        MTR01_MESSAGE_C_CONNECTION_FEEDBACK
        | MTR01_MESSAGE_C_SCAN_LIST
        | MTR01_MESSAGE_C_SCAN_ERROR => {
            let response = Mtr01CResponse::from_payload(payload).map_err(payload_error)?;
            if c_response_message_id(&response) != message_id {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::CResponse)
        }
        MTR01_MESSAGE_D_UNBOUND => {
            if Mtr01BindingRequest::from_payload(payload).map_err(payload_error)?
                != Mtr01BindingRequest::Unbound
            {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::DRequest)
        }
        MTR01_MESSAGE_D_BOUND => {
            if matches!(
                Mtr01BindingRequest::from_payload(payload).map_err(payload_error)?,
                Mtr01BindingRequest::Unbound
            ) {
                return Err(payload_error(Mtr01Error::UnsupportedValue));
            }
            Ok(Mtr01Command::DRequest)
        }
        MTR01_MESSAGE_D_RESPONSE => {
            Mtr01BindingResponse::from_payload(payload).map_err(payload_error)?;
            Ok(Mtr01Command::DResponse)
        }
        _ => Err(adapter_diagnostic(
            ProtocolDiagnosticCode::UnknownMessage,
            "$.messageId",
            "Unknown MTR01 message ID.",
        )),
    }
}

fn message_id_for(
    command: Mtr01Command,
    payload: &[u8],
) -> Result<&'static str, ProtocolDiagnostic> {
    match command {
        Mtr01Command::ARequest => {
            match Mtr01ARequest::from_payload(payload).map_err(payload_error)? {
                Mtr01ARequest::Subscribe => Ok(MTR01_MESSAGE_A_SUBSCRIBE),
                Mtr01ARequest::Unsubscribe => Ok(MTR01_MESSAGE_A_UNSUBSCRIBE),
                Mtr01ARequest::ReadOnce => Ok(MTR01_MESSAGE_A_ONCE),
            }
        }
        Mtr01Command::AResponse => {
            Mtr01AData::from_payload(payload).map_err(payload_error)?;
            Ok(MTR01_MESSAGE_A_DATA)
        }
        Mtr01Command::BRequest => {
            let request = Mtr01BRequest::from_payload(payload).map_err(payload_error)?;
            Ok(b_request_message_id(&request))
        }
        Mtr01Command::BResponse => {
            let response = Mtr01BResponse::from_payload(payload).map_err(payload_error)?;
            Ok(b_response_message_id(&response))
        }
        Mtr01Command::CRequest => {
            let request = Mtr01CRequest::from_payload(payload).map_err(payload_error)?;
            Ok(c_request_message_id(request))
        }
        Mtr01Command::CResponse => {
            let response = Mtr01CResponse::from_payload(payload).map_err(payload_error)?;
            Ok(c_response_message_id(&response))
        }
        Mtr01Command::DRequest => match Mtr01BindingRequest::from_payload(payload) {
            Ok(Mtr01BindingRequest::Unbound) => Ok(MTR01_MESSAGE_D_UNBOUND),
            Ok(Mtr01BindingRequest::Bound { .. }) => Ok(MTR01_MESSAGE_D_BOUND),
            Err(error) => Err(payload_error(error)),
        },
        Mtr01Command::DResponse => {
            Mtr01BindingResponse::from_payload(payload).map_err(payload_error)?;
            Ok(MTR01_MESSAGE_D_RESPONSE)
        }
    }
}

fn b_request_matches(message_id: &str, request: &Mtr01BRequest) -> bool {
    b_request_message_id(request) == message_id
}

fn b_request_message_id(request: &Mtr01BRequest) -> &'static str {
    match request {
        Mtr01BRequest::GetInfo => MTR01_MESSAGE_B_GET_INFO,
        Mtr01BRequest::Basic(_) => MTR01_MESSAGE_B_BASIC_CONFIG,
        Mtr01BRequest::Runtime(_) => MTR01_MESSAGE_B_RUNTIME_CONFIG,
        Mtr01BRequest::Identity(_) => MTR01_MESSAGE_B_IDENTITY_CONFIG,
        Mtr01BRequest::Calibration(_) => MTR01_MESSAGE_B_CALIBRATION_CONTROL,
    }
}

fn b_response_message_id(response: &Mtr01BResponse) -> &'static str {
    match response {
        Mtr01BResponse::DeviceInfo(_) => MTR01_MESSAGE_B_DEVICE_INFO,
        Mtr01BResponse::Feedback(feedback) => match feedback.command {
            0x01 => MTR01_MESSAGE_B_BASIC_FEEDBACK,
            0x02 => MTR01_MESSAGE_B_RUNTIME_FEEDBACK,
            _ => MTR01_MESSAGE_B_IDENTITY_FEEDBACK,
        },
    }
}

fn c_request_message_id(request: Mtr01CRequest) -> &'static str {
    match request {
        Mtr01CRequest::Scan => MTR01_MESSAGE_C_SCAN_REQUEST,
        Mtr01CRequest::Connect(control) if control.control == 0x03 => {
            MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND
        }
        Mtr01CRequest::Connect(_) => MTR01_MESSAGE_C_CONNECT_CONTROL,
    }
}

fn c_response_message_id(response: &Mtr01CResponse) -> &'static str {
    match response {
        Mtr01CResponse::Connection(_) => MTR01_MESSAGE_C_CONNECTION_FEEDBACK,
        Mtr01CResponse::ScanList(_) => MTR01_MESSAGE_C_SCAN_LIST,
        Mtr01CResponse::ScanError => MTR01_MESSAGE_C_SCAN_ERROR,
    }
}

fn payload_error(error: Mtr01Error) -> ProtocolDiagnostic {
    adapter_error(error, "$.payload")
}

fn adapter_error(error: Mtr01Error, path: &str) -> ProtocolDiagnostic {
    let code = match error {
        Mtr01Error::AuthenticationFailed => ProtocolDiagnosticCode::ChecksumMismatch,
        Mtr01Error::UnsupportedCommand => ProtocolDiagnosticCode::UnknownMessage,
        Mtr01Error::InvalidAscii
        | Mtr01Error::InvalidDelimiter
        | Mtr01Error::FixedFieldTooLong
        | Mtr01Error::UnsupportedValue
        | Mtr01Error::InvalidPayloadLength => ProtocolDiagnosticCode::InvalidFieldValue,
        Mtr01Error::InvalidHeader
        | Mtr01Error::InvalidLength
        | Mtr01Error::FrameTooLarge
        | Mtr01Error::StreamInputTooLarge => ProtocolDiagnosticCode::MalformedFrame,
    };
    adapter_diagnostic(code, path, error.to_string())
}

fn adapter_diagnostic(
    code: ProtocolDiagnosticCode,
    path: &str,
    message: impl Into<String>,
) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(code, path, message)
}
