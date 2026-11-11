//!
//! `descriptor.rs`
//! leeway-protocol-plugin-contracts / descriptor
//!
//! 文件职责：解析插件协议中与宿主能力和设备字段有关的安全描述。
//!

use serde::Deserialize;
use serde_json::Value;

use crate::PluginContractError;

const BLUETOOTH_BASE_UUID_SUFFIX: &str = "00001000800000805f9b34fb";

/// 插件协议中与宿主能力有关的描述符。
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginProtocolDescriptor {
    /// 协议 ID。
    pub protocol_id: String,
    /// 协议版本。
    pub protocol_version: String,
    /// definition kind。
    pub definition_kind: Option<String>,
    /// framing 声明。
    pub framing: Option<PluginFramingDescriptor>,
    /// canonical BLE Profile。
    pub ble_profile: Option<PluginBleProfile>,
    /// 消息描述。
    #[serde(default)]
    pub messages: Vec<PluginMessageDescriptor>,
}

/// 固定 framing 描述。
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginFramingDescriptor {
    /// framing kind。
    pub kind: String,
}

/// canonical BLE Profile。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginBleProfile {
    /// 稳定 Profile ID。
    pub id: String,
    /// 显示名称。
    pub name: String,
    /// Primary service UUID。
    pub service_uuid: String,
    /// 广播 UUID。
    pub advertisement_uuid: String,
    /// Central 写入 RX UUID。
    pub rx_uuid: String,
    /// Notify TX UUID。
    pub tx_uuid: String,
    /// 单次通知块字节数。
    pub notification_chunk_bytes: u16,
}

/// 插件消息描述。
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginMessageDescriptor {
    /// 消息 ID。
    pub id: String,
    /// 消息载荷。
    pub payload: Option<PluginMessagePayload>,
}

/// 固定布局消息载荷描述。
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginMessagePayload {
    /// 载荷种类。
    pub kind: String,
    /// 载荷长度。
    pub length_bytes: Option<usize>,
    /// 载荷默认端序。
    pub endianness: Option<PluginFieldEndianness>,
    /// 字段集合。
    #[serde(default)]
    pub fields: Vec<PluginFieldDescriptor>,
}

/// 协议数值字段的端序。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PluginFieldEndianness {
    /// 大端。
    Big,
    /// 小端。
    Little,
}

impl PluginFieldEndianness {
    /// 返回稳定文本表示。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Big => "big",
            Self::Little => "little",
        }
    }
}

/// 单个固定布局字段的声明。
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PluginFieldDescriptor {
    /// 字段名。
    pub name: String,
    /// 字段类型。
    #[serde(rename = "type")]
    pub field_type: String,
    /// 起始偏移。
    pub offset_bytes: usize,
    /// 字段自身端序。
    pub endianness: Option<PluginFieldEndianness>,
}

/// fixedLayout 字段的稳定元数据。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginFixedLayoutField<'a> {
    /// 字段名。
    pub name: &'a str,
    /// 起始偏移。
    pub offset_bytes: usize,
    /// 字段宽度。
    pub width_bytes: usize,
    /// 有效端序。
    pub endianness: Option<PluginFieldEndianness>,
    /// 是否为有符号整数。
    pub signed: bool,
    /// 数值最小值。
    pub minimum: i64,
    /// 数值最大值。
    pub maximum: i64,
}

impl PluginProtocolDescriptor {
    /// 以非严格模式解析并校验插件协议描述符。
    ///
    /// BLE Profile 仍会自动启用严格定义类型校验；普通 fixedLayout 描述符
    /// 不要求声明 `definitionKind`。
    ///
    /// # Errors
    ///
    /// ID、framing、BLE Profile 或 fixedLayout 字段不合法时
    /// 返回 `InvalidProtocolDescriptor`。
    pub fn parse(value: &Value) -> Result<Self, PluginContractError> {
        Self::parse_with_strict(value, false)
    }

    /// 按调用方指定模式解析并校验插件协议描述符。
    ///
    /// `strict` 为 `true` 时要求 `definitionKind` 为 `native`。BLE Profile
    /// 无论该参数为何值都会启用严格定义类型校验。
    ///
    /// # Errors
    ///
    /// ID、严格定义类型、framing、BLE Profile 或 fixedLayout 字段不合法时
    /// 返回 `InvalidProtocolDescriptor`。
    pub fn parse_with_strict(value: &Value, strict: bool) -> Result<Self, PluginContractError> {
        let descriptor: Self = serde_json::from_value(value.clone())
            .map_err(|_| PluginContractError::InvalidProtocolDescriptor)?;
        if !valid_protocol_id(&descriptor.protocol_id)
            || !valid_bounded_text(&descriptor.protocol_version)
        {
            return Err(PluginContractError::InvalidProtocolDescriptor);
        }
        if (strict || descriptor.ble_profile.is_some())
            && descriptor.definition_kind.as_deref() != Some("native")
        {
            return Err(PluginContractError::InvalidProtocolDescriptor);
        }
        if let Some(framing) = &descriptor.framing
            && !matches!(
                framing.kind.as_str(),
                "raw"
                    | "delimiter"
                    | "fixedLength"
                    | "lengthPrefixed"
                    | "fixedHeaderLengthPrefixed"
            )
        {
            return Err(PluginContractError::InvalidProtocolDescriptor);
        }
        if let Some(profile) = &descriptor.ble_profile {
            validate_ble_profile(profile)?;
        }
        for message in &descriptor.messages {
            if !valid_bounded_text(&message.id) {
                return Err(PluginContractError::InvalidProtocolDescriptor);
            }
            if let Some(payload) = &message.payload
                && payload.kind == "fixedLayout"
            {
                validate_fixed_layout(payload)?;
            }
        }
        Ok(descriptor)
    }

    /// 是否声明了可划帧的流式 framing。
    #[must_use]
    pub fn stream_framing_declared(&self) -> bool {
        self.framing.as_ref().is_some_and(|framing| {
            matches!(
                framing.kind.as_str(),
                "delimiter" | "fixedLength" | "lengthPrefixed" | "fixedHeaderLengthPrefixed"
            )
        })
    }

    /// 返回已经验证的 canonical BLE Profile。
    #[must_use]
    pub fn validated_ble_profile(&self) -> Option<&PluginBleProfile> {
        self.ble_profile.as_ref()
    }

    /// 查找 fixedLayout 字段并计算其有效数值元数据。
    ///
    /// # Errors
    ///
    /// 消息、字段或数值类型不合法时返回 `InvalidProtocolDescriptor`。
    pub fn fixed_layout_field(
        &self,
        message_id: &str,
        field_id: &str,
    ) -> Result<PluginFixedLayoutField<'_>, PluginContractError> {
        let message = self
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
        let payload = message
            .payload
            .as_ref()
            .filter(|payload| payload.kind == "fixedLayout")
            .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
        let field = payload
            .fields
            .iter()
            .find(|field| field.name == field_id)
            .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
        let (width_bytes, signed, minimum, maximum, forced_endianness) =
            field_shape(&field.field_type, field.endianness, payload.endianness)?;
        let end_byte = field
            .offset_bytes
            .checked_add(width_bytes)
            .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
        let length = payload
            .length_bytes
            .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
        if end_byte > length {
            return Err(PluginContractError::InvalidProtocolDescriptor);
        }
        Ok(PluginFixedLayoutField {
            name: &field.name,
            offset_bytes: field.offset_bytes,
            width_bytes,
            endianness: forced_endianness,
            signed,
            minimum,
            maximum,
        })
    }
}

fn valid_protocol_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && value.len() <= 64
}

fn valid_bounded_text(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= 64
}

fn validate_ble_profile(profile: &PluginBleProfile) -> Result<(), PluginContractError> {
    if !valid_bounded_text(&profile.id)
        || !valid_bounded_text(&profile.name)
        || !(1..=512).contains(&profile.notification_chunk_bytes)
        || !valid_uuid(&profile.service_uuid)
        || !valid_uuid(&profile.rx_uuid)
        || !valid_uuid(&profile.tx_uuid)
        || profile.rx_uuid.eq_ignore_ascii_case(&profile.tx_uuid)
        || profile.rx_uuid.eq_ignore_ascii_case(&profile.service_uuid)
        || profile.tx_uuid.eq_ignore_ascii_case(&profile.service_uuid)
    {
        return Err(PluginContractError::InvalidProtocolDescriptor);
    }
    let service = normalized_uuid(&profile.service_uuid)
        .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
    let valid_advertisement = if profile.advertisement_uuid.len() == 4
        && profile
            .advertisement_uuid
            .bytes()
            .all(is_uppercase_hex_digit)
    {
        let advertisement = profile.advertisement_uuid.to_ascii_lowercase();
        format!("0000{advertisement}{BLUETOOTH_BASE_UUID_SUFFIX}") == service
    } else {
        normalized_uuid(&profile.advertisement_uuid).is_some_and(|value| value == service)
    };
    if !valid_advertisement {
        return Err(PluginContractError::InvalidProtocolDescriptor);
    }
    Ok(())
}

fn valid_uuid(value: &str) -> bool {
    normalized_uuid(value).is_some()
}

fn normalized_uuid(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
        || !value
            .bytes()
            .all(|byte| is_uppercase_hex_digit(byte) || byte == b'-')
    {
        return None;
    }
    Some(value.replace('-', "").to_ascii_lowercase())
}

fn is_uppercase_hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn validate_fixed_layout(payload: &PluginMessagePayload) -> Result<(), PluginContractError> {
    let length = payload
        .length_bytes
        .filter(|length| *length > 0)
        .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
    for field in &payload.fields {
        if field.name.is_empty() || field.offset_bytes > length {
            return Err(PluginContractError::InvalidProtocolDescriptor);
        }
        if matches!(
            field.field_type.as_str(),
            "u8" | "i8" | "u16" | "i16" | "u24be" | "i24be"
        ) {
            let (width, _, _, _, _) =
                field_shape(&field.field_type, field.endianness, payload.endianness)?;
            let end_byte = field
                .offset_bytes
                .checked_add(width)
                .ok_or(PluginContractError::InvalidProtocolDescriptor)?;
            if end_byte > length {
                return Err(PluginContractError::InvalidProtocolDescriptor);
            }
        }
    }
    Ok(())
}

fn field_shape(
    field_type: &str,
    field_endianness: Option<PluginFieldEndianness>,
    payload_endianness: Option<PluginFieldEndianness>,
) -> Result<(usize, bool, i64, i64, Option<PluginFieldEndianness>), PluginContractError> {
    let (width, signed, minimum, maximum) = match field_type {
        "u8" => (1, false, 0, i64::from(u8::MAX)),
        "i8" => (1, true, i64::from(i8::MIN), i64::from(i8::MAX)),
        "u16" => (2, false, 0, i64::from(u16::MAX)),
        "i16" => (2, true, i64::from(i16::MIN), i64::from(i16::MAX)),
        "u24be" => (3, false, 0, 0x00ff_ffff),
        "i24be" => (3, true, -8_388_608, 8_388_607),
        _ => return Err(PluginContractError::InvalidProtocolDescriptor),
    };
    let endianness = match field_type {
        "u8" | "i8" => None,
        "u24be" | "i24be" => Some(PluginFieldEndianness::Big),
        _ => field_endianness.or(payload_endianness),
    };
    if width > 1 && endianness.is_none() && !matches!(field_type, "u24be" | "i24be") {
        return Err(PluginContractError::InvalidProtocolDescriptor);
    }
    Ok((width, signed, minimum, maximum, endianness))
}
