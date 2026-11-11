//
//  compiler.rs
//  leeway-protocol-core / compiler
//
//  文件职责：执行 Protocol DSL 结构/语义校验并编译不可变 IR。
//

use std::collections::{BTreeMap, BTreeSet};

use leeway_protocol_contracts::{
    Endianness, MAX_PROTOCOL_BYTES, MAX_PROTOCOL_FIELDS_PER_MESSAGE, MAX_PROTOCOL_MESSAGES,
    MAX_PROTOCOL_TEST_VECTORS, PROTOCOL_SCHEMA_VERSION, ProtocolChecksumKind, ProtocolDiagnostic,
    ProtocolDiagnosticCode, ProtocolDocument, ProtocolField, ProtocolFieldType, ProtocolFraming,
    ProtocolMatchOperator, ProtocolMessage,
};
use serde_json::Value;

use crate::checksum::AesCmacKey;
use crate::ir::{
    CompiledField, CompiledFieldKind, CompiledMatch, CompiledMessage, CompiledProtocol,
    CompiledTestVector,
};

/// 协议文档最大帧字节数。
pub const MAX_PROTOCOL_FRAME_BYTES: usize = 65_536;

/// 协议 ID、消息 ID、字段名和测试向量名称最大字符数。
const MAX_IDENTIFIER_CHARS: usize = 64;

/// 协议名称和测试向量安全标签最大字符数。
const MAX_LABEL_CHARS: usize = 128;

/// Protocol JSON 编译器。
pub struct ProtocolCompiler;

impl ProtocolCompiler {
    /// 编译版本化 Protocol JSON。
    ///
    /// # Errors
    ///
    /// 返回全部可收集的结构或语义诊断；诊断不包含原始载荷。
    pub fn compile(document: &str) -> Result<CompiledProtocol, Vec<ProtocolDiagnostic>> {
        Self::compile_with_aes_cmac_key(document, None)
    }

    /// 编译版本化 Protocol JSON，并从带外参数注入 AES-CMAC 密钥。
    ///
    /// # Errors
    ///
    /// AES-CMAC 缺少密钥、文档结构或语义不合法时返回全部可收集诊断。
    pub fn compile_with_aes_cmac_key(
        document: &str,
        key: Option<[u8; 16]>,
    ) -> Result<CompiledProtocol, Vec<ProtocolDiagnostic>> {
        if document.len() > MAX_PROTOCOL_BYTES {
            return Err(vec![diagnostic(
                ProtocolDiagnosticCode::DocumentTooLarge,
                "$",
                "Protocol document exceeds the byte limit.",
            )]);
        }
        let document = serde_json::from_str::<ProtocolDocument>(document).map_err(|_| {
            vec![diagnostic(
                ProtocolDiagnosticCode::MalformedDocument,
                "$",
                "Protocol document is not valid JSON or schema.",
            )]
        })?;
        let checksum_key = key.map(AesCmacKey::new);
        let mut diagnostics = Vec::new();
        validate_document(&document, checksum_key.as_ref(), &mut diagnostics);
        validate_messages_and_vectors(&document, &mut diagnostics);
        if !diagnostics.is_empty() {
            return Err(diagnostics);
        }
        Ok(build_ir(document, checksum_key))
    }
}

/// 校验文档级元数据、framing 和容量。
fn validate_document(
    document: &ProtocolDocument,
    checksum_key: Option<&AesCmacKey>,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    if document.schema_version != PROTOCOL_SCHEMA_VERSION {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::UnsupportedSchemaVersion,
            "$.schemaVersion",
            "Unsupported protocol schema version.",
        ));
    }
    if !valid_identifier(&document.protocol_id) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidProtocolId,
            "$.protocolId",
            "Protocol ID is invalid.",
        ));
    }
    if !valid_version(&document.protocol_version) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidMetadata,
            "$.protocolVersion",
            "Protocol version is invalid.",
        ));
    }
    if !valid_label(&document.name, MAX_LABEL_CHARS) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidMetadata,
            "$.name",
            "Protocol name is invalid.",
        ));
    }
    if document.description.as_deref().is_some_and(|description| {
        description.chars().count() > 1024 || description.chars().any(char::is_control)
    }) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidMetadata,
            "$.description",
            "Protocol description is invalid.",
        ));
    }
    for feature in &document.required_features {
        let _ = feature;
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::UnknownFeature,
            "$.requiredFeatures",
            "Protocol document requires an unsupported feature.",
        ));
    }
    if document.messages.is_empty() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::TooManyMessages,
            "$.messages",
            "Protocol must define at least one message.",
        ));
    }
    if document.messages.len() > MAX_PROTOCOL_MESSAGES {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::TooManyMessages,
            "$.messages",
            "Protocol message limit is exceeded.",
        ));
    }
    if document.test_vectors.len() > MAX_PROTOCOL_TEST_VECTORS {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::TooManyTestVectors,
            "$.testVectors",
            "Protocol test vector limit is exceeded.",
        ));
    }
    validate_framing(&document.framing, document.checksum.kind, diagnostics);
    if document.checksum.kind == ProtocolChecksumKind::AesCmac && checksum_key.is_none() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::MissingChecksumKey,
            "$.checksum",
            "AES-CMAC requires an out-of-band 16-byte key.",
        ));
    }
}

/// 校验 framing 与 checksum 组合。
fn validate_framing(
    framing: &ProtocolFraming,
    checksum: ProtocolChecksumKind,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    match framing {
        ProtocolFraming::Raw { max_frame_bytes } => {
            validate_frame_limit(*max_frame_bytes, "$.framing.maxFrameBytes", diagnostics);
        }
        ProtocolFraming::Delimiter {
            delimiter_hex,
            max_frame_bytes,
        } => {
            validate_frame_limit(*max_frame_bytes, "$.framing.maxFrameBytes", diagnostics);
            match hex::decode(delimiter_hex) {
                Ok(delimiter) if !delimiter.is_empty() && delimiter.len() <= 16 => {}
                _ => diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFrameConfiguration,
                    "$.framing.delimiterHex",
                    "Delimiter must be 1 to 16 hexadecimal bytes.",
                )),
            }
        }
        ProtocolFraming::FixedLength { length_bytes } => {
            validate_frame_limit(*length_bytes, "$.framing.lengthBytes", diagnostics);
        }
        ProtocolFraming::LengthPrefixed {
            max_frame_bytes,
            length_prefix,
        } => {
            validate_frame_limit(*max_frame_bytes, "$.framing.maxFrameBytes", diagnostics);
            if !matches!(length_prefix.bytes, 1 | 2 | 4) {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFrameConfiguration,
                    "$.framing.lengthPrefix.bytes",
                    "Length prefix must use 1, 2 or 4 bytes.",
                ));
            }
            if *max_frame_bytes <= length_prefix.bytes + checksum_size(checksum) {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFrameConfiguration,
                    "$.framing.maxFrameBytes",
                    "Length-prefixed frame has no room for payload.",
                ));
            }
        }
    }
    if checksum_size(checksum) >= MAX_PROTOCOL_FRAME_BYTES {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidChecksum,
            "$.checksum",
            "Checksum configuration is invalid.",
        ));
    }
}

/// 校验单帧长度。
fn validate_frame_limit(limit: usize, path: &str, diagnostics: &mut Vec<ProtocolDiagnostic>) {
    if limit == 0 || limit > MAX_PROTOCOL_FRAME_BYTES {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFrameConfiguration,
            path,
            "Frame limit must be between 1 and 65536 bytes.",
        ));
    }
}

/// 校验消息、匹配器、字段和测试向量。
fn validate_messages_and_vectors(
    document: &ProtocolDocument,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    let mut message_ids = BTreeSet::new();
    let mut message_fields: BTreeMap<&str, BTreeMap<&str, &ProtocolField>> = BTreeMap::new();

    for (message_index, message) in document.messages.iter().enumerate() {
        let path = format!("$.messages[{message_index}]");
        if !valid_identifier(&message.id) || !message_ids.insert(message.id.as_str()) {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::DuplicateMessageId,
                format!("{path}.id"),
                "Message ID is invalid or duplicated.",
            ));
        }
        if message.fields.is_empty() {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::TooManyFields,
                format!("{path}.fields"),
                "Message must define at least one field.",
            ));
        }
        if message.fields.len() > MAX_PROTOCOL_FIELDS_PER_MESSAGE {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::TooManyFields,
                format!("{path}.fields"),
                "Message field limit is exceeded.",
            ));
        }
        let mut field_names = BTreeSet::new();
        let mut field_definitions = BTreeMap::new();
        let mut payload_bytes = 0_usize;
        for (field_index, field) in message.fields.iter().enumerate() {
            let field_path = format!("{path}.fields[{field_index}]");
            if !valid_identifier(&field.name) || !field_names.insert(field.name.as_str()) {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFieldDefinition,
                    format!("{field_path}.name"),
                    "Field name is invalid or duplicated.",
                ));
            }
            let width = validate_field(field, &field_path, diagnostics);
            payload_bytes = payload_bytes.saturating_add(width);
            field_definitions.insert(field.name.as_str(), field);
        }
        validate_message_frame_size(
            &document.framing,
            document.checksum.kind,
            payload_bytes,
            &path,
            diagnostics,
        );
        validate_matches(message, &field_definitions, &path, diagnostics);
        message_fields.insert(message.id.as_str(), field_definitions);
    }
    validate_message_ambiguity(&document.messages, diagnostics);
    validate_test_vectors(document, &message_fields, diagnostics);
}

/// 校验单字段并返回固定宽度。
fn validate_field(
    field: &ProtocolField,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) -> usize {
    match field.field_type {
        ProtocolFieldType::Uint8 | ProtocolFieldType::Int8 | ProtocolFieldType::Bool8 => {
            forbid_aux_options(field, path, diagnostics);
            1
        }
        ProtocolFieldType::Uint16 | ProtocolFieldType::Int16 => {
            require_numeric_options(field, path, diagnostics);
            2
        }
        ProtocolFieldType::Uint24 | ProtocolFieldType::Int24 => {
            require_numeric_options(field, path, diagnostics);
            3
        }
        ProtocolFieldType::Uint32 | ProtocolFieldType::Int32 | ProtocolFieldType::Float32 => {
            require_numeric_options(field, path, diagnostics);
            4
        }
        ProtocolFieldType::Uint64 | ProtocolFieldType::Int64 | ProtocolFieldType::Float64 => {
            require_numeric_options(field, path, diagnostics);
            8
        }
        ProtocolFieldType::BytesFixed
        | ProtocolFieldType::AsciiFixed
        | ProtocolFieldType::Utf8Fixed => {
            if field.endianness.is_some() || !field.enum_values.is_empty() {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFieldDefinition,
                    path,
                    "Fixed bytes/text field contains invalid options.",
                ));
            }
            validate_length(field.length, path, diagnostics)
        }
        ProtocolFieldType::Enum8 | ProtocolFieldType::Enum16 => {
            let width = if field.field_type == ProtocolFieldType::Enum8 {
                1
            } else {
                2
            };
            validate_enum_field(field, width, path, diagnostics);
            width
        }
    }
}

/// 要求多字节字段声明端序。
fn require_endianness(
    field: &ProtocolField,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    if field.endianness.is_none() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldValue,
            format!("{path}.endianness"),
            "Multi-byte field requires explicit endianness.",
        ));
    }
}

/// 要求多字节数值字段声明端序，并拒绝 length/enum 选项。
fn require_numeric_options(
    field: &ProtocolField,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    require_endianness(field, path, diagnostics);
    if field.length.is_some() || !field.enum_values.is_empty() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldDefinition,
            path,
            "Numeric field contains invalid length or enum options.",
        ));
    }
}

/// 拒绝单字节或固定 bytes 字段上的无关选项。
fn forbid_aux_options(
    field: &ProtocolField,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    if field.endianness.is_some() || field.length.is_some() || !field.enum_values.is_empty() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldDefinition,
            path,
            "Field contains options not valid for its type.",
        ));
    }
}

/// 校验固定 bytes/text 长度。
fn validate_length(
    length: Option<usize>,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) -> usize {
    match length {
        Some(length) if (1..=MAX_PROTOCOL_FRAME_BYTES).contains(&length) => length,
        _ => {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidFieldDefinition,
                format!("{path}.length"),
                "Fixed field length must be between 1 and 65536 bytes.",
            ));
            0
        }
    }
}

/// 校验 enum 值与宽度。
fn validate_enum_field(
    field: &ProtocolField,
    width: usize,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    if field.length.is_some() || (width == 1 && field.endianness.is_some()) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldDefinition,
            path,
            "Enum field contains invalid options.",
        ));
    }
    if width == 2 && field.endianness.is_none() {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldValue,
            format!("{path}.endianness"),
            "enum16 requires explicit endianness.",
        ));
    }
    if field.enum_values.is_empty() || field.enum_values.len() > 256 {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFieldDefinition,
            format!("{path}.enumValues"),
            "Enum must contain 1 to 256 values.",
        ));
    }
    let maximum = if width == 1 {
        u64::from(u8::MAX)
    } else {
        u64::from(u16::MAX)
    };
    let mut numbers = BTreeSet::new();
    for (name, value) in &field.enum_values {
        if !valid_label(name, MAX_LABEL_CHARS) || *value > maximum || !numbers.insert(*value) {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidFieldDefinition,
                format!("{path}.enumValues"),
                "Enum name or value is invalid.",
            ));
        }
    }
}

/// 校验消息字段总宽度与 framing 容量。
fn validate_message_frame_size(
    framing: &ProtocolFraming,
    checksum: ProtocolChecksumKind,
    payload_bytes: usize,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    let body_bytes = payload_bytes.saturating_add(checksum_size(checksum));
    let (limit, exact, prefix_bytes) = match framing {
        ProtocolFraming::Raw { max_frame_bytes }
        | ProtocolFraming::Delimiter {
            max_frame_bytes, ..
        } => (*max_frame_bytes, None, 0),
        ProtocolFraming::FixedLength { length_bytes } => (*length_bytes, Some(*length_bytes), 0),
        ProtocolFraming::LengthPrefixed {
            max_frame_bytes,
            length_prefix,
        } => (*max_frame_bytes, None, length_prefix.bytes),
    };
    let required = body_bytes.saturating_add(prefix_bytes);
    if exact.map_or(required > limit, |exact| body_bytes != exact) {
        diagnostics.push(diagnostic(
            ProtocolDiagnosticCode::InvalidFrameConfiguration,
            format!("{path}.fields"),
            "Message layout does not fit frame configuration.",
        ));
    }
}

/// 校验消息匹配器。
fn validate_matches(
    message: &ProtocolMessage,
    fields: &BTreeMap<&str, &ProtocolField>,
    path: &str,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    for (index, condition) in message.match_conditions.iter().enumerate() {
        let Some(field) = fields.get(condition.field.as_str()) else {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidMatchCondition,
                format!("{path}.match[{index}].field"),
                "Match condition references an unknown field.",
            ));
            continue;
        };
        if !valid_condition_value(field, condition.operator, &condition.value) {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidMatchCondition,
                format!("{path}.match[{index}].value"),
                "Match condition value is invalid.",
            ));
        }
    }
}

/// 校验匹配参数结构。
fn valid_condition_value(
    field: &ProtocolField,
    operator: ProtocolMatchOperator,
    value: &Value,
) -> bool {
    match operator {
        ProtocolMatchOperator::Equals | ProtocolMatchOperator::NotEquals => {
            valid_field_value(field, value)
        }
        ProtocolMatchOperator::In => value.as_array().is_some_and(|items| {
            !items.is_empty()
                && items.len() <= 256
                && items.iter().all(|item| valid_field_value(field, item))
        }),
        ProtocolMatchOperator::UnsignedRange => value.as_array().is_some_and(|items| {
            items.len() == 2
                && unsigned_width(field).is_some()
                && items[0]
                    .as_u64()
                    .zip(items[1].as_u64())
                    .is_some_and(|(minimum, maximum)| minimum <= maximum)
        }),
    }
}

/// 判断多条消息是否存在明显的重叠匹配。
fn validate_message_ambiguity(
    messages: &[ProtocolMessage],
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    for (left_index, left) in messages.iter().enumerate() {
        for (right_index, right) in messages.iter().enumerate().skip(left_index + 1) {
            if left.match_conditions.is_empty()
                || right.match_conditions.is_empty()
                || equivalent_matches(&left.match_conditions, &right.match_conditions)
            {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::AmbiguousMessageMatch,
                    format!("$.messages[{right_index}].match"),
                    "Message match conditions are not distinguishable.",
                ));
            }
        }
    }
}

/// 判断两组匹配条件是否等价（不要求顺序）。
fn equivalent_matches(
    left: &[leeway_protocol_contracts::ProtocolMatch],
    right: &[leeway_protocol_contracts::ProtocolMatch],
) -> bool {
    left.len() == right.len() && left.iter().all(|condition| right.contains(condition))
}

/// 校验所有测试向量及其引用。
fn validate_test_vectors(
    document: &ProtocolDocument,
    message_fields: &BTreeMap<&str, BTreeMap<&str, &ProtocolField>>,
    diagnostics: &mut Vec<ProtocolDiagnostic>,
) {
    let mut names = BTreeSet::new();
    for (index, vector) in document.test_vectors.iter().enumerate() {
        let path = format!("$.testVectors[{index}]");
        if !valid_label(&vector.name, MAX_LABEL_CHARS) || !names.insert(vector.name.as_str()) {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::DuplicateTestVectorName,
                format!("{path}.name"),
                "Test vector name is invalid or duplicated.",
            ));
        }
        let Some(fields) = message_fields.get(vector.message_id.as_str()) else {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidMatchCondition,
                format!("{path}.messageId"),
                "Test vector references an unknown message.",
            ));
            continue;
        };
        if vector.values.len() != fields.len()
            || !fields.keys().all(|name| vector.values.contains_key(*name))
        {
            diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::InvalidFieldValue,
                format!("{path}.values"),
                "Test vector field values are incomplete or contain unknown fields.",
            ));
        }
        for (name, field) in fields {
            if vector
                .values
                .get(*name)
                .is_some_and(|value| !valid_field_value(field, value))
            {
                diagnostics.push(diagnostic(
                    ProtocolDiagnosticCode::InvalidFieldValue,
                    format!("{path}.values"),
                    "Test vector field value type or range is invalid.",
                ));
            }
        }
        match hex::decode(&vector.encoded_hex) {
            Ok(bytes) if bytes.len() <= MAX_PROTOCOL_FRAME_BYTES => {}
            _ => diagnostics.push(diagnostic(
                ProtocolDiagnosticCode::MalformedFrame,
                format!("{path}.encodedHex"),
                "Test vector must contain bounded hexadecimal bytes.",
            )),
        }
    }
}

/// 构建不可变 IR。
fn build_ir(document: ProtocolDocument, checksum_key: Option<AesCmacKey>) -> CompiledProtocol {
    let definition = document.clone();
    let messages = document
        .messages
        .into_iter()
        .map(|message| {
            let mut offset = 0_usize;
            let fields = message
                .fields
                .into_iter()
                .map(|field| {
                    let kind = compile_field(&field);
                    let compiled = CompiledField {
                        name: field.name,
                        offset_bytes: offset,
                        kind,
                    };
                    offset = offset.saturating_add(compiled.kind.width());
                    compiled
                })
                .collect();
            CompiledMessage {
                id: message.id,
                matches: message
                    .match_conditions
                    .into_iter()
                    .map(|condition| CompiledMatch {
                        field_name: condition.field,
                        operator: condition.operator,
                        value: condition.value,
                    })
                    .collect(),
                fields,
            }
        })
        .collect();
    let test_vectors = document
        .test_vectors
        .into_iter()
        .map(|vector| {
            let expected_bytes = hex::decode(&vector.encoded_hex).unwrap_or_default();
            CompiledTestVector {
                name: vector.name,
                message_id: vector.message_id,
                values: vector.values,
                expected_bytes,
            }
        })
        .collect();
    CompiledProtocol {
        protocol_id: document.protocol_id,
        protocol_version: document.protocol_version,
        definition,
        name: document.name,
        framing: document.framing,
        checksum: document.checksum.kind,
        checksum_key,
        messages,
        test_vectors,
    }
}

/// 将字段 DTO 编译为不可变字段类型。
fn compile_field(field: &ProtocolField) -> CompiledFieldKind {
    let endianness = field.endianness;
    match field.field_type {
        ProtocolFieldType::Uint8 => CompiledFieldKind::Unsigned {
            width: 1,
            endianness: Endianness::Big,
        },
        ProtocolFieldType::Uint16 => int_field(2, endianness, false),
        ProtocolFieldType::Uint24 => int_field(3, endianness, false),
        ProtocolFieldType::Uint32 => int_field(4, endianness, false),
        ProtocolFieldType::Uint64 => int_field(8, endianness, false),
        ProtocolFieldType::Int8 => CompiledFieldKind::Signed {
            width: 1,
            endianness: Endianness::Big,
        },
        ProtocolFieldType::Int16 => int_field(2, endianness, true),
        ProtocolFieldType::Int24 => int_field(3, endianness, true),
        ProtocolFieldType::Int32 => int_field(4, endianness, true),
        ProtocolFieldType::Int64 => int_field(8, endianness, true),
        ProtocolFieldType::Bool8 => CompiledFieldKind::Bool,
        ProtocolFieldType::Float32 => CompiledFieldKind::Float {
            width: 4,
            endianness: endianness.unwrap_or(Endianness::Big),
        },
        ProtocolFieldType::Float64 => CompiledFieldKind::Float {
            width: 8,
            endianness: endianness.unwrap_or(Endianness::Big),
        },
        ProtocolFieldType::BytesFixed => CompiledFieldKind::Bytes {
            length: field.length.unwrap_or_default(),
        },
        ProtocolFieldType::AsciiFixed => CompiledFieldKind::Ascii {
            length: field.length.unwrap_or_default(),
        },
        ProtocolFieldType::Utf8Fixed => CompiledFieldKind::Utf8 {
            length: field.length.unwrap_or_default(),
        },
        ProtocolFieldType::Enum8 => CompiledFieldKind::Enum {
            width: 1,
            endianness: None,
            values: field.enum_values.clone(),
        },
        ProtocolFieldType::Enum16 => CompiledFieldKind::Enum {
            width: 2,
            endianness,
            values: field.enum_values.clone(),
        },
    }
}

/// 创建有符号或无符号整数字段。
fn int_field(width: usize, endianness: Option<Endianness>, signed: bool) -> CompiledFieldKind {
    let endianness = endianness.unwrap_or(Endianness::Big);
    if signed {
        CompiledFieldKind::Signed { width, endianness }
    } else {
        CompiledFieldKind::Unsigned { width, endianness }
    }
}

/// 返回校验和字节数。
pub(crate) const fn checksum_size(kind: ProtocolChecksumKind) -> usize {
    match kind {
        ProtocolChecksumKind::None => 0,
        ProtocolChecksumKind::Sum8 | ProtocolChecksumKind::Xor8 => 1,
        ProtocolChecksumKind::Crc16Modbus | ProtocolChecksumKind::Crc16CcittFalse => 2,
        ProtocolChecksumKind::Crc32IsoHdlc => 4,
        ProtocolChecksumKind::AesCmac => 16,
    }
}

/// 判断协议/消息/字段机器标识是否合法。
fn valid_identifier(value: &str) -> bool {
    (1..=MAX_IDENTIFIER_CHARS).contains(&value.chars().count())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// 判断协议版本是否安全且有界。
fn valid_version(value: &str) -> bool {
    (1..=MAX_IDENTIFIER_CHARS).contains(&value.chars().count())
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

/// 判断安全显示标签。
fn valid_label(value: &str, maximum: usize) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && value.chars().count() <= maximum && !value.chars().any(char::is_control)
}

/// 判断 JSON 值是否符合字段类型、宽度和长度。
fn valid_field_value(field: &ProtocolField, value: &Value) -> bool {
    match field.field_type {
        ProtocolFieldType::Uint8
        | ProtocolFieldType::Uint16
        | ProtocolFieldType::Uint24
        | ProtocolFieldType::Uint32
        | ProtocolFieldType::Uint64 => {
            let width = unsigned_width(field).unwrap_or_default();
            value
                .as_u64()
                .is_some_and(|number| fits_unsigned(number, width))
        }
        ProtocolFieldType::Int8
        | ProtocolFieldType::Int16
        | ProtocolFieldType::Int24
        | ProtocolFieldType::Int32
        | ProtocolFieldType::Int64 => {
            let width = signed_width(field).unwrap_or_default();
            value
                .as_i64()
                .is_some_and(|number| fits_signed(number, width))
        }
        ProtocolFieldType::Bool8 => value.is_boolean(),
        ProtocolFieldType::Float32 | ProtocolFieldType::Float64 => {
            value.as_f64().is_some_and(f64::is_finite)
        }
        ProtocolFieldType::BytesFixed => value
            .as_str()
            .and_then(|text| hex::decode(text).ok())
            .is_some_and(|bytes| Some(bytes.len()) == field.length),
        ProtocolFieldType::AsciiFixed => value
            .as_str()
            .is_some_and(|text| text.is_ascii() && Some(text.len()) == field.length),
        ProtocolFieldType::Utf8Fixed => value
            .as_str()
            .is_some_and(|text| Some(text.len()) == field.length),
        ProtocolFieldType::Enum8 | ProtocolFieldType::Enum16 => match value {
            Value::String(name) => field.enum_values.contains_key(name),
            Value::Number(number) => number
                .as_u64()
                .is_some_and(|number| field.enum_values.values().any(|value| *value == number)),
            _ => false,
        },
    }
}

/// 返回无符号类字段字节宽度。
fn unsigned_width(field: &ProtocolField) -> Option<usize> {
    match field.field_type {
        ProtocolFieldType::Uint8 | ProtocolFieldType::Enum8 => Some(1),
        ProtocolFieldType::Uint16 | ProtocolFieldType::Enum16 => Some(2),
        ProtocolFieldType::Uint24 => Some(3),
        ProtocolFieldType::Uint32 => Some(4),
        ProtocolFieldType::Uint64 => Some(8),
        _ => None,
    }
}

/// 返回有符号整数字段字节宽度。
fn signed_width(field: &ProtocolField) -> Option<usize> {
    match field.field_type {
        ProtocolFieldType::Int8 => Some(1),
        ProtocolFieldType::Int16 => Some(2),
        ProtocolFieldType::Int24 => Some(3),
        ProtocolFieldType::Int32 => Some(4),
        ProtocolFieldType::Int64 => Some(8),
        _ => None,
    }
}

/// 判断无符号值是否符合字段宽度。
fn fits_unsigned(value: u64, width: usize) -> bool {
    if width == 8 {
        true
    } else {
        value < (1_u64 << (width * 8))
    }
}

/// 判断有符号值是否符合字段宽度。
fn fits_signed(value: i64, width: usize) -> bool {
    if width == 8 {
        return true;
    }
    let bits = width * 8;
    let minimum = -(1_i128 << (bits - 1));
    let maximum = (1_i128 << (bits - 1)) - 1;
    let value = i128::from(value);
    value >= minimum && value <= maximum
}

/// 创建协议诊断。
fn diagnostic(
    code: ProtocolDiagnosticCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> ProtocolDiagnostic {
    ProtocolDiagnostic::new(code, path, message)
}
