//
//  codec.rs
//  leeway-protocol-mtr01
//
//  文件职责：编码、校验和流式划分 MTR01 TCZQ 帧。
//

use leeway_protocol_contracts::ProtocolChecksumKind;
use leeway_protocol_core::AesCmacKey;
use leeway_protocol_core::checksum::{aes_cmac, verify_checksum};

use crate::Mtr01Error;

/// MTR01 自定义透传服务 UUID。
pub const MTR01_SERVICE_UUID: &str = "0000AAA0-0000-1000-8000-00805F9B34FB";
/// MTR01 模块到小程序 Notify 特征 UUID。
pub const MTR01_TX_UUID: &str = "0000AAA1-0000-1000-8000-00805F9B34FB";
/// MTR01 小程序到模块 Write 特征 UUID。
pub const MTR01_RX_UUID: &str = "0000AAA2-0000-1000-8000-00805F9B34FB";
/// 协议声明的首选 ATT MTU。
pub const MTR01_PREFERRED_MTU: usize = 247;
/// ATT MTU 247 下的单次通知最大载荷。
pub const MTR01_NOTIFICATION_BYTES: usize = MTR01_PREFERRED_MTU - 3;
/// 固定帧头、命令、Len 和 AES-CMAC 的总开销。
pub const MTR01_FRAME_OVERHEAD: usize = 4 + 2 + 1 + 16;
/// Len 字段能够表达的最大数据域长度。
pub const MTR01_MAX_PAYLOAD_BYTES: usize = u8::MAX as usize;
/// MTR01 单帧最大字节数。
pub const MTR01_MAX_FRAME_BYTES: usize = MTR01_FRAME_OVERHEAD + MTR01_MAX_PAYLOAD_BYTES;

const HEADER: [u8; 4] = *b"TCZQ";

/// MTR01 命令码。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01Command {
    /// A#，订阅或读取实时数据。
    ARequest,
    /// A@，实时数据。
    AResponse,
    /// B#，同步设备信息。
    BRequest,
    /// B@，设备信息应答。
    BResponse,
    /// C#，蓝牙配置和控制字。
    CRequest,
    /// C@，扫描和连接反馈。
    CResponse,
    /// D#，深度绑定请求。
    DRequest,
    /// D@，深度绑定应答。
    DResponse,
}

impl Mtr01Command {
    /// 返回稳定两字节命令码。
    #[must_use]
    pub const fn bytes(self) -> [u8; 2] {
        match self {
            Self::ARequest => *b"A#",
            Self::AResponse => *b"A@",
            Self::BRequest => *b"B#",
            Self::BResponse => *b"B@",
            Self::CRequest => *b"C#",
            Self::CResponse => *b"C@",
            Self::DRequest => *b"D#",
            Self::DResponse => *b"D@",
        }
    }

    /// 从两字节命令码解析。
    ///
    /// # Errors
    ///
    /// 命令码不属于 MTR01 V1.5.1 的已知集合时返回稳定错误。
    pub const fn from_bytes(bytes: [u8; 2]) -> Result<Self, Mtr01Error> {
        match &bytes {
            b"A#" => Ok(Self::ARequest),
            b"A@" => Ok(Self::AResponse),
            b"B#" => Ok(Self::BRequest),
            b"B@" => Ok(Self::BResponse),
            b"C#" => Ok(Self::CRequest),
            b"C@" => Ok(Self::CResponse),
            b"D#" => Ok(Self::DRequest),
            b"D@" => Ok(Self::DResponse),
            _ => Err(Mtr01Error::UnsupportedCommand),
        }
    }
}

/// 已完成认证的 MTR01 业务帧。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01Frame {
    /// 两字节命令。
    pub command: Mtr01Command,
    /// 数据域，不包含 Len 和 AES-CMAC。
    pub payload: Vec<u8>,
}

/// 可复用 AES-CMAC 密钥的 MTR01 帧编解码器。
#[derive(Debug)]
pub struct Mtr01Codec {
    key: AesCmacKey,
}

impl Mtr01Codec {
    /// 使用带外提供的 16 字节 AES-CMAC 密钥创建编解码器。
    #[must_use]
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            key: AesCmacKey::new(key),
        }
    }

    /// 编码并认证一条 MTR01 帧。
    ///
    /// # Errors
    ///
    /// 数据域超过 255 字节时返回稳定错误。
    pub fn encode(&self, command: Mtr01Command, payload: &[u8]) -> Result<Vec<u8>, Mtr01Error> {
        if payload.len() > MTR01_MAX_PAYLOAD_BYTES {
            return Err(Mtr01Error::FrameTooLarge);
        }
        let mut frame = Vec::with_capacity(MTR01_FRAME_OVERHEAD + payload.len());
        frame.extend_from_slice(&HEADER);
        frame.extend_from_slice(&command.bytes());
        frame.push(u8::try_from(payload.len()).map_err(|_| Mtr01Error::FrameTooLarge)?);
        frame.extend_from_slice(payload);
        let mac = aes_cmac(&self.key, &frame).map_err(|_| Mtr01Error::AuthenticationFailed)?;
        frame.extend_from_slice(&mac);
        Ok(frame)
    }

    /// 解码并认证一条完整 MTR01 帧。
    ///
    /// # Errors
    ///
    /// 帧头、长度、命令或 AES-CMAC 不匹配时返回稳定错误。
    pub fn decode(&self, frame: &[u8]) -> Result<Mtr01Frame, Mtr01Error> {
        if frame.len() > MTR01_MAX_FRAME_BYTES {
            return Err(Mtr01Error::FrameTooLarge);
        }
        let body = frame
            .get(..MTR01_FRAME_OVERHEAD - 16)
            .ok_or(Mtr01Error::InvalidLength)?;
        let header = body.get(..4).ok_or(Mtr01Error::InvalidLength)?;
        if header != HEADER {
            return Err(Mtr01Error::InvalidHeader);
        }
        let command = Mtr01Command::from_bytes(
            body.get(4..6)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Mtr01Error::InvalidLength)?,
        )?;
        let payload_length = usize::from(*body.get(6).ok_or(Mtr01Error::InvalidLength)?);
        if frame.len() != MTR01_FRAME_OVERHEAD + payload_length {
            return Err(Mtr01Error::InvalidLength);
        }
        let authenticated = &frame[..7 + payload_length];
        let actual_mac = &frame[7 + payload_length..];
        if !verify_checksum(
            ProtocolChecksumKind::AesCmac,
            authenticated,
            actual_mac,
            Some(&self.key),
        )
        .map_err(|_| Mtr01Error::AuthenticationFailed)?
        {
            return Err(Mtr01Error::AuthenticationFailed);
        }
        Ok(Mtr01Frame {
            command,
            payload: frame[7..7 + payload_length].to_vec(),
        })
    }
}

/// 支持 BLE 写入分片的 MTR01 有界流式解码器。
#[derive(Clone, Debug)]
pub struct Mtr01StreamDecoder {
    buffer: Vec<u8>,
}

impl Default for Mtr01StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Mtr01StreamDecoder {
    /// 创建空缓冲区。
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(MTR01_MAX_FRAME_BYTES),
        }
    }

    /// 推入一段 BLE 写入并返回已经完整的完整帧。
    ///
    /// # Errors
    ///
    /// 输入过大、帧头错误或流中出现无法恢复的垃圾字节时返回稳定错误。
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Mtr01Error> {
        if bytes.len() > 65_536 {
            return Err(Mtr01Error::StreamInputTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.buffer.len() < 7 {
                break;
            }
            if self.buffer[..4] != HEADER {
                self.buffer.clear();
                return Err(Mtr01Error::InvalidHeader);
            }
            let payload_length = usize::from(self.buffer[6]);
            let total = MTR01_FRAME_OVERHEAD + payload_length;
            if self.buffer.len() < total {
                break;
            }
            frames.push(self.buffer.drain(..total).collect());
        }
        if self.buffer.len() > MTR01_MAX_FRAME_BYTES {
            self.buffer.clear();
            return Err(Mtr01Error::FrameTooLarge);
        }
        Ok(frames)
    }
}
#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
