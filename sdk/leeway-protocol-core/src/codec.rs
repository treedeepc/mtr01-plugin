//
//  codec.rs
//  leeway-protocol-core / codec
//
//  文件职责：按编译后的 Protocol IR 编码、解码并执行黄金测试向量。
//

use std::collections::BTreeMap;

use leeway_protocol_contracts::{
    Endianness, ProtocolDiagnostic, ProtocolDiagnosticCode, ProtocolMatchOperator,
};
use serde_json::Value;

use crate::checksum::{checksum_bytes, checksum_size, verify_checksum};
use crate::framing::{decode_frame, encode_frame};
use crate::ir::{
    CompiledField, CompiledFieldKind, CompiledMatch, CompiledMessage, CompiledProtocol,
    CompiledTestVector,
};
use crate::value::{ProtocolValue, ProtocolValues};

/// 成功解码的协议帧。
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedFrame {
    /// 匹配的消息 ID。
    pub message_id: String,
    /// 解码字段值。
    pub values: ProtocolValues,
    /// 完整原始帧。
    pub raw_bytes: Vec<u8>,
}

impl CompiledProtocol {
    /// 按消息和字段值编码完整帧。
    ///
    /// # Errors
    ///
    /// 消息不存在、字段缺失/多余、值类型不匹配、帧超限或 checksum/framing
    /// 无法生成时返回稳定诊断。
    pub fn encode(
        &self,
        message_id: &str,
        values: &ProtocolValues,
    ) -> Result<Vec<u8>, ProtocolDiagnostic> {
        let message = self
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .ok_or_else(|| {
                codec_error(ProtocolDiagnosticCode::UnknownMessage, "Unknown message.")
            })?;
        if values.len() != message.fields.len()
            || !message
                .fields
                .iter()
                .all(|field| values.contains_key(&field.name))
        {
            return Err(codec_error(
                ProtocolDiagnosticCode::InvalidFieldValue,
                "Field values are incomplete or contain unknown fields.",
            ));
        }
        let mut payload = Vec::new();
        for field in &message.fields {
            let value = values.get(&field.name).ok_or_else(|| {
                codec_error(
                    ProtocolDiagnosticCode::InvalidFieldValue,
                    "Required field value is missing.",
                )
            })?;
            encode_field(field, value, &mut payload)?;
        }
        let checksum = checksum_bytes(self.checksum, &payload, self.checksum_key.as_ref())?;
        payload.extend_from_slice(&checksum);
        encode_frame(&self.framing, self.checksum, &payload)
    }

    /// 解码一帧并匹配唯一消息。
    ///
    /// # Errors
    ///
    /// framing、长度、checksum、字段值或消息匹配失败时返回稳定诊断。
    pub fn decode(&self, frame: &[u8]) -> Result<DecodedFrame, ProtocolDiagnostic> {
        let body = decode_frame(&self.framing, self.checksum, frame)?;
        let checksum_length = checksum_size(self.checksum);
        if body.len() < checksum_length {
            return Err(codec_error(
                ProtocolDiagnosticCode::MalformedFrame,
                "Frame is shorter than its checksum.",
            ));
        }
        let split = body.len() - checksum_length;
        let (payload, actual_checksum) = body.split_at(split);
        if !verify_checksum(
            self.checksum,
            payload,
            actual_checksum,
            self.checksum_key.as_ref(),
        )? {
            return Err(codec_error(
                ProtocolDiagnosticCode::ChecksumMismatch,
                "Frame checksum does not match.",
            ));
        }

        let mut matches = Vec::new();
        let mut layout_matched = false;
        let mut field_error = false;
        for message in &self.messages {
            if message_width(message) != payload.len() {
                continue;
            }
            layout_matched = true;
            let Ok(values) = decode_message(message, payload) else {
                field_error = true;
                continue;
            };
            if message
                .matches
                .iter()
                .all(|condition| match_condition(condition, message, &values))
            {
                matches.push((message, values));
            }
        }
        match matches.len() {
            0 if field_error => Err(codec_error(
                ProtocolDiagnosticCode::InvalidFieldValue,
                "A field value could not be decoded.",
            )),
            0 if !layout_matched => Err(codec_error(
                ProtocolDiagnosticCode::MalformedFrame,
                "No message layout matches the frame length.",
            )),
            0 => Err(codec_error(
                ProtocolDiagnosticCode::UnknownMessage,
                "No message matches the frame.",
            )),
            1 => {
                let (message, values) = matches.pop().ok_or_else(|| {
                    codec_error(
                        ProtocolDiagnosticCode::UnknownMessage,
                        "No message matches the frame.",
                    )
                })?;
                Ok(DecodedFrame {
                    message_id: message.id.clone(),
                    values,
                    raw_bytes: frame.to_vec(),
                })
            }
            _ => Err(codec_error(
                ProtocolDiagnosticCode::AmbiguousMessageMatch,
                "Multiple messages match the frame.",
            )),
        }
    }

    /// 执行协议内全部黄金测试向量。
    ///
    /// # Errors
    ///
    /// 任一编码、解码、期望字节或往返值不一致时返回全部可收集诊断。
    pub fn run_test_vectors(&self) -> Result<(), Vec<ProtocolDiagnostic>> {
        let mut diagnostics = Vec::new();
        for vector in &self.test_vectors {
            run_test_vector(self, vector, &mut diagnostics);
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// 执行单条测试向量。
fn run_test_vector(
    protocol: &CompiledProtocol,
    vector: &CompiledTestVector,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    let Some(message) = protocol
        .messages
        .iter()
        .find(|message| message.id == vector.message_id)
    else {
        diagnostics.push(vector_error(&vector.name, "Unknown test vector message."));
        return;
    };
    let Ok(values) = json_values_to_protocol(&vector.values, message) else {
        diagnostics.push(vector_error(
            &vector.name,
            "Test vector values are invalid.",
        ));
        return;
    };
    let Ok(encoded) = protocol.encode(&vector.message_id, &values) else {
        diagnostics.push(vector_error(&vector.name, "Test vector encoding failed."));
        return;
    };
    if encoded != vector.expected_bytes {
        diagnostics.push(vector_error(
            &vector.name,
            "Encoded bytes do not match the test vector.",
        ));
        return;
    }
    let Ok(decoded) = protocol.decode(&vector.expected_bytes) else {
        diagnostics.push(vector_error(&vector.name, "Test vector decoding failed."));
        return;
    };
    if decoded.message_id != vector.message_id || decoded.values != values {
        diagnostics.push(vector_error(
            &vector.name,
            "Decoded values do not match the test vector.",
        ));
    }
}

/// 按消息字段类型转换 JSON 测试向量值。
fn json_values_to_protocol(
    values: &BTreeMap<String, Value>,
    message: &CompiledMessage,
) -> Result<ProtocolValues, ()> {
    message
        .fields
        .iter()
        .map(|field| {
            let value = values.get(&field.name).ok_or(())?;
            Ok((field.name.clone(), json_value(value, &field.kind)?))
        })
        .collect()
}

/// 将 JSON 标量转换为对应字段值。
fn json_value(value: &Value, kind: &CompiledFieldKind) -> Result<ProtocolValue, ()> {
    match kind {
        CompiledFieldKind::Unsigned { .. } => value.as_u64().map(ProtocolValue::Unsigned).ok_or(()),
        CompiledFieldKind::Signed { .. } => value.as_i64().map(ProtocolValue::Signed).ok_or(()),
        CompiledFieldKind::Bool => value.as_bool().map(ProtocolValue::Bool).ok_or(()),
        CompiledFieldKind::Float { .. } => value.as_f64().map(ProtocolValue::Float).ok_or(()),
        CompiledFieldKind::Bytes { .. } => value
            .as_str()
            .and_then(|text| hex::decode(text).ok())
            .map(ProtocolValue::Bytes)
            .ok_or(()),
        CompiledFieldKind::Ascii { .. } | CompiledFieldKind::Utf8 { .. } => value
            .as_str()
            .map(|text| ProtocolValue::Text(text.into()))
            .ok_or(()),
        CompiledFieldKind::Enum { values, .. } => match value {
            Value::String(name) if values.contains_key(name) => {
                Ok(ProtocolValue::Enum(name.clone()))
            }
            Value::Number(number) => number
                .as_u64()
                .and_then(|number| {
                    values
                        .iter()
                        .find(|(_, value)| **value == number)
                        .map(|(name, _)| ProtocolValue::Enum(name.clone()))
                })
                .ok_or(()),
            _ => Err(()),
        },
    }
}

/// 编码单个字段。
fn encode_field(
    field: &CompiledField,
    value: &ProtocolValue,
    output: &mut Vec<u8>,
) -> Result<(), ProtocolDiagnostic> {
    match (&field.kind, value) {
        (CompiledFieldKind::Unsigned { width, endianness }, ProtocolValue::Unsigned(value)) => {
            write_unsigned(*value, *width, *endianness, output)
        }
        (CompiledFieldKind::Signed { width, endianness }, ProtocolValue::Signed(value)) => {
            write_signed(*value, *width, *endianness, output)
        }
        (CompiledFieldKind::Bool, ProtocolValue::Bool(value)) => {
            output.push(u8::from(*value));
            Ok(())
        }
        (CompiledFieldKind::Float { width, endianness }, ProtocolValue::Float(value))
            if value.is_finite() =>
        {
            if *width == 4 && !narrow_f32(*value).is_finite() {
                return Err(field_error("Float value cannot be represented as float32."));
            }
            match (*width, endianness) {
                (4, Endianness::Big) => {
                    output.extend_from_slice(&narrow_f32(*value).to_bits().to_be_bytes());
                }
                (4, Endianness::Little) => {
                    output.extend_from_slice(&narrow_f32(*value).to_bits().to_le_bytes());
                }
                (8, Endianness::Big) => output.extend_from_slice(&value.to_bits().to_be_bytes()),
                (8, Endianness::Little) => output.extend_from_slice(&value.to_bits().to_le_bytes()),
                _ => return Err(field_error("Unsupported floating-point width.")),
            }
            Ok(())
        }
        (CompiledFieldKind::Bytes { length }, ProtocolValue::Bytes(value))
            if value.len() == *length =>
        {
            output.extend_from_slice(value);
            Ok(())
        }
        (CompiledFieldKind::Ascii { length }, ProtocolValue::Text(value))
            if value.is_ascii() && value.len() == *length =>
        {
            output.extend_from_slice(value.as_bytes());
            Ok(())
        }
        (CompiledFieldKind::Utf8 { length }, ProtocolValue::Text(value))
            if value.len() == *length =>
        {
            output.extend_from_slice(value.as_bytes());
            Ok(())
        }
        (
            CompiledFieldKind::Enum {
                width,
                endianness,
                values,
            },
            ProtocolValue::Enum(name),
        ) => {
            let value = values
                .get(name)
                .ok_or_else(|| field_error("Unknown enum name."))?;
            write_unsigned(
                *value,
                *width,
                endianness.unwrap_or(Endianness::Big),
                output,
            )
        }
        (
            CompiledFieldKind::Enum {
                width,
                endianness,
                values,
            },
            ProtocolValue::Unsigned(value),
        ) if values.values().any(|candidate| candidate == value) => write_unsigned(
            *value,
            *width,
            endianness.unwrap_or(Endianness::Big),
            output,
        ),
        _ => Err(field_error("Field value type or length is invalid.")),
    }
}

/// 返回消息固定 payload 宽度。
fn message_width(message: &CompiledMessage) -> usize {
    message.fields.iter().map(|field| field.kind.width()).sum()
}

/// 按指定消息布局解码 payload。
fn decode_message(
    message: &CompiledMessage,
    payload: &[u8],
) -> Result<ProtocolValues, ProtocolDiagnostic> {
    let mut values = BTreeMap::new();
    for field in &message.fields {
        let start = field.offset_bytes;
        let end = start.checked_add(field.kind.width()).ok_or_else(|| {
            codec_error(
                ProtocolDiagnosticCode::MalformedFrame,
                "Field offset overflowed.",
            )
        })?;
        let bytes = payload.get(start..end).ok_or_else(|| {
            codec_error(
                ProtocolDiagnosticCode::MalformedFrame,
                "Field exceeds the decoded payload.",
            )
        })?;
        let value = decode_field(&field.kind, bytes).ok_or_else(|| {
            codec_error(
                ProtocolDiagnosticCode::InvalidFieldValue,
                "Field value could not be decoded.",
            )
        })?;
        values.insert(field.name.clone(), value);
    }
    Ok(values)
}

/// 解码单个字段。
fn decode_field(kind: &CompiledFieldKind, bytes: &[u8]) -> Option<ProtocolValue> {
    match kind {
        CompiledFieldKind::Unsigned { endianness, .. } => {
            Some(ProtocolValue::Unsigned(read_unsigned(bytes, *endianness)))
        }
        CompiledFieldKind::Signed { endianness, .. } => {
            Some(ProtocolValue::Signed(read_signed(bytes, *endianness)))
        }
        CompiledFieldKind::Bool => match bytes {
            [0] => Some(ProtocolValue::Bool(false)),
            [1] => Some(ProtocolValue::Bool(true)),
            _ => None,
        },
        CompiledFieldKind::Float { width, endianness } => {
            let value = match (*width, endianness) {
                (4, Endianness::Big) => {
                    f64::from(f32::from_bits(u32::from_be_bytes(bytes.try_into().ok()?)))
                }
                (4, Endianness::Little) => {
                    f64::from(f32::from_bits(u32::from_le_bytes(bytes.try_into().ok()?)))
                }
                (8, Endianness::Big) => f64::from_bits(u64::from_be_bytes(bytes.try_into().ok()?)),
                (8, Endianness::Little) => {
                    f64::from_bits(u64::from_le_bytes(bytes.try_into().ok()?))
                }
                _ => return None,
            };
            Some(ProtocolValue::Float(value))
        }
        CompiledFieldKind::Bytes { .. } => Some(ProtocolValue::Bytes(bytes.to_vec())),
        CompiledFieldKind::Ascii { .. } => std::str::from_utf8(bytes)
            .ok()
            .filter(|text| text.is_ascii())
            .map(|text| ProtocolValue::Text(text.into())),
        CompiledFieldKind::Utf8 { .. } => std::str::from_utf8(bytes)
            .ok()
            .map(|text| ProtocolValue::Text(text.into())),
        CompiledFieldKind::Enum {
            endianness, values, ..
        } => {
            let number = read_unsigned(bytes, endianness.unwrap_or(Endianness::Big));
            values
                .iter()
                .find(|(_, value)| **value == number)
                .map(|(name, _)| ProtocolValue::Enum(name.clone()))
        }
    }
}

/// 判断消息匹配条件是否满足。
fn match_condition(
    condition: &CompiledMatch,
    message: &CompiledMessage,
    values: &ProtocolValues,
) -> bool {
    let Some(field) = message
        .fields
        .iter()
        .find(|field| field.name == condition.field_name)
    else {
        return false;
    };
    let Some(actual) = values.get(&condition.field_name) else {
        return false;
    };
    match condition.operator {
        ProtocolMatchOperator::Equals => {
            json_value(&condition.value, &field.kind).is_ok_and(|expected| expected == *actual)
        }
        ProtocolMatchOperator::NotEquals => {
            json_value(&condition.value, &field.kind).is_ok_and(|expected| expected != *actual)
        }
        ProtocolMatchOperator::In => condition.value.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| json_value(item, &field.kind).is_ok_and(|expected| expected == *actual))
        }),
        ProtocolMatchOperator::UnsignedRange => {
            let Some(actual) = unsigned_match_value(actual) else {
                return false;
            };
            condition.value.as_array().is_some_and(|items| {
                items.len() == 2
                    && items[0].as_u64().is_some_and(|min| actual >= min)
                    && items[1].as_u64().is_some_and(|max| actual <= max)
            })
        }
    }
}

/// 提取可用于无符号范围匹配的数值。
fn unsigned_match_value(value: &ProtocolValue) -> Option<u64> {
    match value {
        ProtocolValue::Unsigned(value) => Some(*value),
        ProtocolValue::Signed(value) => u64::try_from(*value).ok(),
        ProtocolValue::Bool(value) => Some(u64::from(*value)),
        _ => None,
    }
}

/// 写入指定宽度的无符号整数。
fn write_unsigned(
    value: u64,
    width: usize,
    endianness: Endianness,
    output: &mut Vec<u8>,
) -> Result<(), ProtocolDiagnostic> {
    let maximum = if width == 8 {
        u64::MAX
    } else {
        (1_u64 << (width * 8)) - 1
    };
    if value > maximum {
        return Err(field_error("Unsigned field value is out of range."));
    }
    let bytes = match endianness {
        Endianness::Big => value.to_be_bytes(),
        Endianness::Little => value.to_le_bytes(),
    };
    append_width(bytes, width, endianness, output);
    Ok(())
}

/// 写入指定宽度的有符号整数。
fn write_signed(
    value: i64,
    width: usize,
    endianness: Endianness,
    output: &mut Vec<u8>,
) -> Result<(), ProtocolDiagnostic> {
    let bits = width * 8;
    let minimum = -(1_i128 << (bits - 1));
    let maximum = (1_i128 << (bits - 1)) - 1;
    let value_wide = i128::from(value);
    if value_wide < minimum || value_wide > maximum {
        return Err(field_error("Signed field value is out of range."));
    }
    let bytes = match endianness {
        Endianness::Big => value.to_be_bytes(),
        Endianness::Little => value.to_le_bytes(),
    };
    append_width(bytes, width, endianness, output);
    Ok(())
}

/// 从完整端序字节中追加指定宽度。
fn append_width(bytes: [u8; 8], width: usize, endianness: Endianness, output: &mut Vec<u8>) {
    match endianness {
        Endianness::Big => output.extend_from_slice(&bytes[8 - width..]),
        Endianness::Little => output.extend_from_slice(&bytes[..width]),
    }
}

/// 读取指定端序的无符号整数。
fn read_unsigned(bytes: &[u8], endianness: Endianness) -> u64 {
    let mut padded = [0_u8; 8];
    match endianness {
        Endianness::Big => padded[8 - bytes.len()..].copy_from_slice(bytes),
        Endianness::Little => padded[..bytes.len()].copy_from_slice(bytes),
    }
    match endianness {
        Endianness::Big => u64::from_be_bytes(padded),
        Endianness::Little => u64::from_le_bytes(padded),
    }
}

/// 读取指定端序的有符号整数并符号扩展。
fn read_signed(bytes: &[u8], endianness: Endianness) -> i64 {
    let value = read_unsigned(bytes, endianness);
    let bits = bytes.len() * 8;
    if bits == 64 || value & (1_u64 << (bits - 1)) == 0 {
        return i64::from_le_bytes(value.to_le_bytes());
    }
    let extended = value | (!0_u64 << bits);
    i64::from_le_bytes(extended.to_le_bytes())
}

/// 按协议声明的 float32 宽度进行有意收窄。
#[allow(clippy::cast_possible_truncation)]
fn narrow_f32(value: f64) -> f32 {
    value as f32
}

/// 创建字段值诊断。
fn field_error(message: &'static str) -> ProtocolDiagnostic {
    codec_error(ProtocolDiagnosticCode::InvalidFieldValue, message)
}

/// 创建编解码诊断。
fn codec_error(code: ProtocolDiagnosticCode, message: &'static str) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(code, "$.codec", message)
}

/// 创建测试向量诊断。
fn vector_error(name: &str, message: &'static str) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(
        ProtocolDiagnosticCode::TestVectorFailed,
        format!("$.testVectors[{name}]"),
        message,
    )
}
