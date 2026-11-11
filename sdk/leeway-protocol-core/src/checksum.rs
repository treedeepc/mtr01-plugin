//
//  checksum.rs
//  leeway-protocol-core / checksum
//
//  文件职责：实现 V1 支持的固定校验和算法及字节序。
//

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};
use leeway_protocol_contracts::{ProtocolChecksumKind, ProtocolDiagnostic, ProtocolDiagnosticCode};
use zeroize::Zeroize;

/// 不暴露内容的 AES-CMAC 密钥。
pub struct AesCmacKey([u8; 16]);

impl AesCmacKey {
    /// 从完整 16 字节密钥创建安全包装。
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for AesCmacKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AesCmacKey([REDACTED])")
    }
}

impl Drop for AesCmacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 计算 sum8。
#[must_use]
pub fn sum8(data: &[u8]) -> u8 {
    data.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

/// 计算 xor8。
#[must_use]
pub fn xor8(data: &[u8]) -> u8 {
    data.iter().fold(0_u8, |sum, byte| sum ^ *byte)
}

/// 计算 Modbus CRC16。
#[must_use]
pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF_u16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// 计算 CCITT-FALSE CRC16。
#[must_use]
pub fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF_u16;
    for byte in data {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// 计算 ISO-HDLC CRC32。
#[must_use]
pub fn crc32_iso_hdlc(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// 返回算法附加字节数。
#[must_use]
pub const fn checksum_size(kind: ProtocolChecksumKind) -> usize {
    match kind {
        ProtocolChecksumKind::None => 0,
        ProtocolChecksumKind::Sum8 | ProtocolChecksumKind::Xor8 => 1,
        ProtocolChecksumKind::Crc16Modbus | ProtocolChecksumKind::Crc16CcittFalse => 2,
        ProtocolChecksumKind::Crc32IsoHdlc => 4,
        ProtocolChecksumKind::AesCmac => 16,
    }
}

/// 计算算法对应的固定字节序校验值。
///
/// # Errors
///
/// AES-CMAC 缺少密钥时返回稳定诊断。
pub fn checksum_bytes(
    kind: ProtocolChecksumKind,
    data: &[u8],
    key: Option<&AesCmacKey>,
) -> Result<Vec<u8>, ProtocolDiagnostic> {
    let bytes = match kind {
        ProtocolChecksumKind::None => Vec::new(),
        ProtocolChecksumKind::Sum8 => vec![sum8(data)],
        ProtocolChecksumKind::Xor8 => vec![xor8(data)],
        ProtocolChecksumKind::Crc16Modbus => crc16_modbus(data).to_le_bytes().to_vec(),
        ProtocolChecksumKind::Crc16CcittFalse => crc16_ccitt_false(data).to_be_bytes().to_vec(),
        ProtocolChecksumKind::Crc32IsoHdlc => crc32_iso_hdlc(data).to_be_bytes().to_vec(),
        ProtocolChecksumKind::AesCmac => aes_cmac(required_key(key)?, data)?.to_vec(),
    };
    Ok(bytes)
}

/// 比较实际附加校验值与重新计算结果。
///
/// # Errors
///
/// AES-CMAC 缺少密钥时返回稳定诊断。
pub fn verify_checksum(
    kind: ProtocolChecksumKind,
    data: &[u8],
    actual: &[u8],
    key: Option<&AesCmacKey>,
) -> Result<bool, ProtocolDiagnostic> {
    if kind == ProtocolChecksumKind::AesCmac {
        let key = required_key(key)?;
        let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key.bytes())
            .map_err(|_| checksum_key_error())?;
        mac.update(data);
        return Ok(mac.verify_slice(actual).is_ok());
    }
    Ok(checksum_bytes(kind, data, None)? == actual)
}

/// 计算 NIST AES-128 CMAC。
///
/// # Errors
///
/// 密钥长度不符合 AES-128 要求时返回稳定诊断。
pub fn aes_cmac(key: &AesCmacKey, data: &[u8]) -> Result<[u8; 16], ProtocolDiagnostic> {
    let mut mac =
        <Cmac<Aes128> as KeyInit>::new_from_slice(key.bytes()).map_err(|_| checksum_key_error())?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn required_key(key: Option<&AesCmacKey>) -> Result<&AesCmacKey, ProtocolDiagnostic> {
    key.ok_or_else(|| {
        ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::MissingChecksumKey,
            "$.checksum",
            "AES-CMAC requires an out-of-band 16-byte key.",
        )
    })
}

fn checksum_key_error() -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(
        ProtocolDiagnosticCode::InvalidChecksumKey,
        "$.checksum",
        "AES-CMAC key must contain exactly 16 bytes.",
    )
}
