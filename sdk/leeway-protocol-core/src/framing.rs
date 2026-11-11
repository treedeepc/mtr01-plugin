//
//  framing.rs
//  leeway-protocol-core / framing
//
//  文件职责：实现 V1 raw、分隔符、固定长度和长度前缀 framing。
//

use leeway_protocol_contracts::{
    Endianness, ProtocolChecksumKind, ProtocolDiagnostic, ProtocolDiagnosticCode, ProtocolFraming,
};

use crate::checksum::checksum_size;

/// 给完整 payload（字段加 checksum）添加 framing。
pub(crate) fn encode_frame(
    framing: &ProtocolFraming,
    checksum_kind: ProtocolChecksumKind,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolDiagnostic> {
    match framing {
        ProtocolFraming::Raw { max_frame_bytes } => {
            ensure_limit(payload.len(), *max_frame_bytes, "$.framing")?;
            Ok(payload.to_vec())
        }
        ProtocolFraming::Delimiter {
            delimiter_hex,
            max_frame_bytes,
        } => {
            ensure_limit(payload.len(), *max_frame_bytes, "$.framing")?;
            let delimiter = decode_delimiter(delimiter_hex)?;
            let mut frame = payload.to_vec();
            frame.extend_from_slice(&delimiter);
            Ok(frame)
        }
        ProtocolFraming::FixedLength { length_bytes } => {
            if payload.len() == *length_bytes {
                Ok(payload.to_vec())
            } else {
                Err(frame_error("Frame payload does not match fixed length."))
            }
        }
        ProtocolFraming::LengthPrefixed {
            max_frame_bytes,
            length_prefix,
        } => {
            let prefix_included = usize::from(length_prefix.includes_prefix) * length_prefix.bytes;
            let report_length = payload
                .len()
                .checked_add(prefix_included)
                .and_then(|length| {
                    length.checked_sub(
                        usize::from(!length_prefix.includes_checksum)
                            * checksum_size(checksum_kind),
                    )
                })
                .ok_or_else(|| frame_error("Frame length overflowed."))?;
            let total = payload
                .len()
                .checked_add(length_prefix.bytes)
                .ok_or_else(|| frame_error("Frame length overflowed."))?;
            ensure_limit(total, *max_frame_bytes, "$.framing")?;
            let mut frame =
                write_length(report_length, length_prefix.bytes, length_prefix.endianness)?;
            frame.extend_from_slice(payload);
            Ok(frame)
        }
    }
}

/// 去掉 framing 并返回 payload（字段加 checksum）。
pub(crate) fn decode_frame<'a>(
    framing: &ProtocolFraming,
    checksum_kind: ProtocolChecksumKind,
    frame: &'a [u8],
) -> Result<&'a [u8], ProtocolDiagnostic> {
    match framing {
        ProtocolFraming::Raw { max_frame_bytes } => {
            ensure_limit(frame.len(), *max_frame_bytes, "$.framing")?;
            Ok(frame)
        }
        ProtocolFraming::Delimiter {
            delimiter_hex,
            max_frame_bytes,
        } => {
            let delimiter = decode_delimiter(delimiter_hex)?;
            let payload = frame
                .strip_suffix(delimiter.as_slice())
                .ok_or_else(|| frame_error("Frame delimiter is missing."))?;
            ensure_limit(payload.len(), *max_frame_bytes, "$.framing")?;
            Ok(payload)
        }
        ProtocolFraming::FixedLength { length_bytes } => {
            if frame.len() == *length_bytes {
                Ok(frame)
            } else {
                Err(frame_error("Frame length does not match fixed length."))
            }
        }
        ProtocolFraming::LengthPrefixed {
            max_frame_bytes,
            length_prefix,
        } => {
            ensure_limit(frame.len(), *max_frame_bytes, "$.framing")?;
            if frame.len() < length_prefix.bytes {
                return Err(frame_error("Length prefix is incomplete."));
            }
            let reported = read_length(&frame[..length_prefix.bytes], length_prefix.endianness)?;
            let prefix_included = usize::from(length_prefix.includes_prefix) * length_prefix.bytes;
            let derived = reported
                .checked_sub(prefix_included)
                .and_then(|length| {
                    if length_prefix.includes_checksum {
                        Some(length)
                    } else {
                        length.checked_add(checksum_size(checksum_kind))
                    }
                })
                .ok_or_else(|| frame_error("Length prefix value is invalid."))?;
            let expected_total = derived
                .checked_add(length_prefix.bytes)
                .ok_or_else(|| frame_error("Frame length overflowed."))?;
            if expected_total != frame.len() {
                return Err(frame_error("Frame length does not match prefix."));
            }
            Ok(&frame[length_prefix.bytes..])
        }
    }
}

/// 解析十六进制分隔符。
fn decode_delimiter(value: &str) -> Result<Vec<u8>, ProtocolDiagnostic> {
    hex::decode(value)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| frame_error("Frame delimiter is invalid."))
}

/// 编码长度字段。
fn write_length(
    value: usize,
    bytes: usize,
    endianness: Endianness,
) -> Result<Vec<u8>, ProtocolDiagnostic> {
    match (bytes, endianness) {
        (1, _) => u8::try_from(value)
            .map(|number| vec![number])
            .map_err(|_| frame_error("Length prefix value is too large.")),
        (2, Endianness::Big) => u16::try_from(value)
            .map(|number| number.to_be_bytes().to_vec())
            .map_err(|_| frame_error("Length prefix value is too large.")),
        (2, Endianness::Little) => u16::try_from(value)
            .map(|number| number.to_le_bytes().to_vec())
            .map_err(|_| frame_error("Length prefix value is too large.")),
        (4, Endianness::Big) => u32::try_from(value)
            .map(|number| number.to_be_bytes().to_vec())
            .map_err(|_| frame_error("Length prefix value is too large.")),
        (4, Endianness::Little) => u32::try_from(value)
            .map(|number| number.to_le_bytes().to_vec())
            .map_err(|_| frame_error("Length prefix value is too large.")),
        _ => Err(frame_error("Length prefix width is unsupported.")),
    }
}

/// 解码长度字段。
fn read_length(bytes: &[u8], endianness: Endianness) -> Result<usize, ProtocolDiagnostic> {
    match (bytes.len(), endianness) {
        (1, _) => Ok(usize::from(bytes[0])),
        (2, Endianness::Big) => Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))),
        (2, Endianness::Little) => Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
        (4, Endianness::Big) => {
            usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .map_err(|_| frame_error("Length prefix value is not representable."))
        }
        (4, Endianness::Little) => {
            usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .map_err(|_| frame_error("Length prefix value is not representable."))
        }
        _ => Err(frame_error("Length prefix width is unsupported.")),
    }
}

/// 检查帧上限。
fn ensure_limit(actual: usize, maximum: usize, path: &str) -> Result<(), ProtocolDiagnostic> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::FrameTooLarge,
            path,
            "Frame exceeds the configured limit.",
        ))
    }
}

/// 创建固定 framing 诊断。
fn frame_error(message: &'static str) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(ProtocolDiagnosticCode::MalformedFrame, "$.framing", message)
}
