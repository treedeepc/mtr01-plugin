//
//  error.rs
//  leeway-protocol-mtr01
//
//  文件职责：定义不含原始帧和密钥的稳定 MTR01 适配错误。
//

/// MTR01 帧或业务载荷错误。
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Mtr01Error {
    /// 固定帧头不是 TCZQ。
    #[error("MTR01 frame header is invalid.")]
    InvalidHeader,
    /// Len 与实际帧长度不一致。
    #[error("MTR01 frame length is invalid.")]
    InvalidLength,
    /// 单帧超过协议上限。
    #[error("MTR01 frame exceeds the size limit.")]
    FrameTooLarge,
    /// 命令码不是已知的 A/B/C/D 请求或应答。
    #[error("MTR01 command is unsupported.")]
    UnsupportedCommand,
    /// AES-CMAC 不匹配。
    #[error("MTR01 frame authentication failed.")]
    AuthenticationFailed,
    /// 流式输入超过单次上限。
    #[error("MTR01 stream input exceeds the size limit.")]
    StreamInputTooLarge,
    /// 业务载荷长度不符合命令定义。
    #[error("MTR01 payload length is invalid.")]
    InvalidPayloadLength,
    /// ASCII 字段包含非法字节。
    #[error("MTR01 ASCII field is invalid.")]
    InvalidAscii,
    /// EF 分隔标识缺失或位置不合法。
    #[error("MTR01 EF delimiter is invalid.")]
    InvalidDelimiter,
    /// 固定字段超过其声明宽度。
    #[error("MTR01 fixed field exceeds its width.")]
    FixedFieldTooLong,
    /// 枚举值不属于当前协议版本。
    #[error("MTR01 enum value is unsupported.")]
    UnsupportedValue,
}
