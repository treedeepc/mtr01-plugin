//
//  stream_decoder.rs
//  leeway-protocol-core / stream
//
//  文件职责：从有界字节流中划分完整协议帧。
//

use leeway_protocol_contracts::{
    Endianness, ProtocolChecksumKind, ProtocolDiagnostic, ProtocolDiagnosticCode, ProtocolFraming,
};

use crate::checksum::checksum_size;
use crate::ir::CompiledProtocol;

/// 单次推入 stream decoder 的最大字节数。
pub const MAX_STREAM_INPUT_BYTES: usize = 65_536;

/// 可跨多次读取重组协议帧的有界流式解码器。
#[derive(Clone, Debug)]
pub struct ProtocolStreamDecoder {
    framing: StreamFraming,
    buffer: Vec<u8>,
}

#[derive(Clone, Debug)]
enum StreamFraming {
    Delimiter {
        delimiter: Vec<u8>,
        max_payload_bytes: usize,
    },
    FixedLength {
        length_bytes: usize,
    },
    LengthPrefixed {
        max_frame_bytes: usize,
        prefix_bytes: usize,
        endianness: Endianness,
        includes_prefix: bool,
        includes_checksum: bool,
        checksum_bytes: usize,
    },
}

impl CompiledProtocol {
    /// 创建与该协议 framing 绑定的有界流式解码器。
    ///
    /// # Errors
    ///
    /// raw framing 无法从 TCP/串口流推断帧边界，返回安全 framing 诊断。
    pub fn stream_decoder(&self) -> Result<ProtocolStreamDecoder, ProtocolDiagnostic> {
        ProtocolStreamDecoder::new(&self.framing, self.checksum)
    }
}

impl ProtocolStreamDecoder {
    fn new(
        framing: &ProtocolFraming,
        checksum_kind: ProtocolChecksumKind,
    ) -> Result<Self, ProtocolDiagnostic> {
        let framing = match framing {
            ProtocolFraming::Raw { .. } => {
                return Err(stream_error(
                    ProtocolDiagnosticCode::InvalidFrameConfiguration,
                    "Raw framing cannot delimit a byte stream.",
                ));
            }
            ProtocolFraming::Delimiter {
                delimiter_hex,
                max_frame_bytes,
            } => StreamFraming::Delimiter {
                delimiter: hex::decode(delimiter_hex).map_err(|_| {
                    stream_error(
                        ProtocolDiagnosticCode::InvalidFrameConfiguration,
                        "Stream delimiter is invalid.",
                    )
                })?,
                max_payload_bytes: *max_frame_bytes,
            },
            ProtocolFraming::FixedLength { length_bytes } => StreamFraming::FixedLength {
                length_bytes: *length_bytes,
            },
            ProtocolFraming::LengthPrefixed {
                max_frame_bytes,
                length_prefix,
            } => StreamFraming::LengthPrefixed {
                max_frame_bytes: *max_frame_bytes,
                prefix_bytes: length_prefix.bytes,
                endianness: length_prefix.endianness,
                includes_prefix: length_prefix.includes_prefix,
                includes_checksum: length_prefix.includes_checksum,
                checksum_bytes: checksum_size(checksum_kind),
            },
        };
        if matches!(
            &framing,
            StreamFraming::Delimiter { delimiter, .. } if delimiter.is_empty()
        ) {
            return Err(stream_error(
                ProtocolDiagnosticCode::InvalidFrameConfiguration,
                "Stream delimiter is empty.",
            ));
        }
        Ok(Self {
            framing,
            buffer: Vec::new(),
        })
    }

    /// 推入一段字节并返回本次已经完整的全部帧。
    ///
    /// 未形成完整帧的尾字节会保留到下一次调用。超过协议帧上限或单次输入
    /// 上限时返回稳定诊断，且不会继续增长内部缓冲。
    ///
    /// # Errors
    ///
    /// 输入超限、长度前缀不合法或缓冲超过协议帧上限时返回诊断。
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProtocolDiagnostic> {
        if bytes.len() > MAX_STREAM_INPUT_BYTES {
            return Err(stream_error(
                ProtocolDiagnosticCode::FrameTooLarge,
                "Stream input exceeds the per-push limit.",
            ));
        }
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(frame_length) = self.next_frame_length()? {
            frames.push(self.buffer.drain(..frame_length).collect());
        }
        if self.buffer.len() > self.maximum_buffered_bytes()? {
            self.buffer.clear();
            return Err(stream_error(
                ProtocolDiagnosticCode::FrameTooLarge,
                "Incomplete stream frame exceeds the protocol limit.",
            ));
        }
        Ok(frames)
    }

    fn next_frame_length(&self) -> Result<Option<usize>, ProtocolDiagnostic> {
        match &self.framing {
            StreamFraming::Delimiter {
                delimiter,
                max_payload_bytes,
            } => {
                let Some(position) = find_subslice(&self.buffer, delimiter) else {
                    return Ok(None);
                };
                if position > *max_payload_bytes {
                    return Err(stream_error(
                        ProtocolDiagnosticCode::FrameTooLarge,
                        "Delimited stream frame exceeds the configured limit.",
                    ));
                }
                Ok(Some(position + delimiter.len()))
            }
            StreamFraming::FixedLength { length_bytes } => {
                Ok((self.buffer.len() >= *length_bytes).then_some(*length_bytes))
            }
            StreamFraming::LengthPrefixed {
                max_frame_bytes,
                prefix_bytes,
                endianness,
                includes_prefix,
                includes_checksum,
                checksum_bytes,
            } => {
                if self.buffer.len() < *prefix_bytes {
                    return Ok(None);
                }
                let reported = read_length(&self.buffer[..*prefix_bytes], *endianness)?;
                let prefix_included = usize::from(*includes_prefix) * *prefix_bytes;
                let derived = reported
                    .checked_sub(prefix_included)
                    .and_then(|length| {
                        if *includes_checksum {
                            Some(length)
                        } else {
                            length.checked_add(*checksum_bytes)
                        }
                    })
                    .ok_or_else(|| {
                        stream_error(
                            ProtocolDiagnosticCode::MalformedFrame,
                            "Length prefix value is invalid.",
                        )
                    })?;
                let total = derived.checked_add(*prefix_bytes).ok_or_else(|| {
                    stream_error(
                        ProtocolDiagnosticCode::FrameTooLarge,
                        "Length-prefixed stream frame overflowed.",
                    )
                })?;
                if total > *max_frame_bytes {
                    return Err(stream_error(
                        ProtocolDiagnosticCode::FrameTooLarge,
                        "Length-prefixed stream frame exceeds the configured limit.",
                    ));
                }
                Ok((self.buffer.len() >= total).then_some(total))
            }
        }
    }

    fn maximum_buffered_bytes(&self) -> Result<usize, ProtocolDiagnostic> {
        match &self.framing {
            StreamFraming::Delimiter {
                delimiter,
                max_payload_bytes,
            } => max_payload_bytes
                .checked_add(delimiter.len())
                .ok_or_else(frame_limit_overflow),
            StreamFraming::FixedLength { length_bytes } => Ok(*length_bytes),
            StreamFraming::LengthPrefixed {
                max_frame_bytes, ..
            } => Ok(*max_frame_bytes),
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_length(bytes: &[u8], endianness: Endianness) -> Result<usize, ProtocolDiagnostic> {
    match (bytes.len(), endianness) {
        (1, _) => Ok(usize::from(bytes[0])),
        (2, Endianness::Big) => Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))),
        (2, Endianness::Little) => Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
        (4, Endianness::Big) => {
            usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .map_err(|_| frame_limit_overflow())
        }
        (4, Endianness::Little) => {
            usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .map_err(|_| frame_limit_overflow())
        }
        _ => Err(stream_error(
            ProtocolDiagnosticCode::InvalidFrameConfiguration,
            "Length prefix width is unsupported.",
        )),
    }
}

fn frame_limit_overflow() -> ProtocolDiagnostic {
    stream_error(
        ProtocolDiagnosticCode::FrameTooLarge,
        "Stream frame limit overflowed.",
    )
}

fn stream_error(code: ProtocolDiagnosticCode, message: &'static str) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(code, "$.framing", message)
}
