//!
//! `lib.rs`
//! leeway-protocol-mtr01
//!
//! 文件职责：提供 MTR01 BLE 计量模块协议的独立帧与业务载荷适配器。
//!

#![forbid(unsafe_code)]
#![recursion_limit = "256"]

mod adapter;
mod codec;
mod definition;
mod error;
mod messages;
mod report_fields;

pub use adapter::{
    MTR01_MESSAGE_A_DATA, MTR01_MESSAGE_A_ONCE, MTR01_MESSAGE_A_SUBSCRIBE,
    MTR01_MESSAGE_A_UNSUBSCRIBE, MTR01_MESSAGE_B_BASIC_CONFIG, MTR01_MESSAGE_B_BASIC_FEEDBACK,
    MTR01_MESSAGE_B_CALIBRATION_CONTROL, MTR01_MESSAGE_B_DEVICE_INFO, MTR01_MESSAGE_B_GET_INFO,
    MTR01_MESSAGE_B_IDENTITY_CONFIG, MTR01_MESSAGE_B_IDENTITY_FEEDBACK,
    MTR01_MESSAGE_B_RUNTIME_CONFIG, MTR01_MESSAGE_B_RUNTIME_FEEDBACK,
    MTR01_MESSAGE_C_CONNECT_CONTROL, MTR01_MESSAGE_C_CONNECTION_FEEDBACK,
    MTR01_MESSAGE_C_DISCONNECT_AND_UNBIND, MTR01_MESSAGE_C_SCAN_ERROR, MTR01_MESSAGE_C_SCAN_LIST,
    MTR01_MESSAGE_C_SCAN_REQUEST, MTR01_MESSAGE_D_BOUND, MTR01_MESSAGE_D_RESPONSE,
    MTR01_MESSAGE_D_UNBOUND, Mtr01Adapter,
};
pub use codec::{
    MTR01_FRAME_OVERHEAD, MTR01_MAX_FRAME_BYTES, MTR01_MAX_PAYLOAD_BYTES, MTR01_NOTIFICATION_BYTES,
    MTR01_PREFERRED_MTU, MTR01_RX_UUID, MTR01_SERVICE_UUID, MTR01_TX_UUID, Mtr01Codec,
    Mtr01Command, Mtr01Frame, Mtr01StreamDecoder,
};
pub use error::Mtr01Error;
pub use messages::{
    Mtr01AData, Mtr01ARequest, Mtr01BFeedback, Mtr01BRequest, Mtr01BResponse, Mtr01BasicConfig,
    Mtr01BatteryType, Mtr01BindingRequest, Mtr01BindingResponse, Mtr01BmsType, Mtr01CRequest,
    Mtr01CResponse, Mtr01CalibrationControl, Mtr01ConnectControl, Mtr01ConnectionFeedback,
    Mtr01DeviceInfoV15, Mtr01IdentityConfig, Mtr01RuntimeConfig, Mtr01ScanList, Mtr01ScanSlot,
};
pub use report_fields::{Mtr01ScalarFieldError, Mtr01ScalarFields, Mtr01ScalarOverrides};
