//!
//! `configuration.rs`
//! leeway-protocol-plugin-contracts / configuration
//!
//! 文件职责：定义封闭配置模型，并作为十六进制秘密到 wire 字节的唯一转换边界。
//!

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{PluginContractError, PluginWireValue};

/// 单个插件配置最多允许的字段数。
pub const MAX_PLUGIN_CONFIGURATION_FIELDS: usize = 8;
const MAX_PLUGIN_CONFIGURATION_LOCALIZATIONS: usize = 16;
const MAX_PLUGIN_CONFIGURATION_LABEL_CHARS: usize = 128;

/// 插件配置模型。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginConfigurationSchema {
    /// 配置 Schema 版本。
    pub schema_version: u32,
    /// 有界配置字段。
    pub fields: Vec<PluginConfigurationField>,
}

/// 单字段配置声明。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginConfigurationField {
    /// 稳定字段 ID。
    pub id: String,
    /// v1 受限字段类型。
    #[serde(rename = "type")]
    pub field_type: PluginFieldType,
    /// GUI 输入编码。
    pub encoding: PluginFieldEncoding,
    /// 解码后的固定字节长度。
    pub length: usize,
    /// 是否必须提供。
    pub required: bool,
    /// 默认配置标签。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// locale 到标签的映射。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub localized_labels: BTreeMap<String, String>,
}

/// v1 插件配置字段类型。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PluginFieldType {
    /// 固定长度秘密字节。
    SecretBytes,
}

/// v1 配置输入编码。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PluginFieldEncoding {
    /// 十六进制文本。
    Hex,
}

impl PluginConfigurationSchema {
    /// 消费配置输入并只在此处把十六进制秘密解码成 wire Base64。
    ///
    /// 原始文本和解码字节都会通过 `Zeroizing` 在离开作用域时清零。
    ///
    /// # Errors
    ///
    /// Schema 版本、字段集合、必填项、十六进制或固定长度不合法时返回错误。
    pub fn decode_input(
        &self,
        values: BTreeMap<String, String>,
    ) -> Result<PluginConfigurationInput, PluginContractError> {
        let mut values = values
            .into_iter()
            .map(|(key, value)| (key, Zeroizing::new(value)))
            .collect::<BTreeMap<_, _>>();
        if self.schema_version != 1 || self.fields.len() > MAX_PLUGIN_CONFIGURATION_FIELDS {
            return Err(PluginContractError::InvalidConfiguration);
        }
        let mut ids = BTreeSet::new();
        for field in &self.fields {
            if !valid_field_id(&field.id)
                || field.length == 0
                || !ids.insert(field.id.as_str())
                || !valid_configuration_labels(field)
            {
                return Err(PluginContractError::InvalidConfiguration);
            }
        }
        if values
            .keys()
            .any(|key| !self.fields.iter().any(|field| field.id == *key))
        {
            return Err(PluginContractError::InvalidConfiguration);
        }

        let mut decoded = PluginConfigurationInput::empty();
        for field in &self.fields {
            let Some(text) = values.remove(&field.id) else {
                if field.required {
                    return Err(PluginContractError::InvalidConfiguration);
                }
                continue;
            };
            match (field.field_type, field.encoding) {
                (PluginFieldType::SecretBytes, PluginFieldEncoding::Hex) => {
                    let bytes = Zeroizing::new(
                        hex::decode(text.as_str())
                            .map_err(|_| PluginContractError::InvalidConfiguration)?,
                    );
                    if bytes.len() != field.length {
                        return Err(PluginContractError::InvalidConfiguration);
                    }
                    decoded.values.insert(
                        field.id.clone(),
                        PluginWireValue::Bytes {
                            base64: STANDARD.encode(bytes.as_slice()),
                        },
                    );
                }
            }
        }
        Ok(decoded)
    }
}

/// 非 Clone 的插件配置输入；Drop 时清零 wire Base64。
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct PluginConfigurationInput {
    values: BTreeMap<String, PluginWireValue>,
}

impl PluginConfigurationInput {
    /// 构造空配置。
    #[must_use]
    pub fn empty() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// 从 wire map 构造非 Clone 配置。
    #[must_use]
    pub fn from_values(values: BTreeMap<String, PluginWireValue>) -> Self {
        Self { values }
    }

    /// 返回只读 wire 值。
    #[must_use]
    pub fn values(&self) -> &BTreeMap<String, PluginWireValue> {
        &self.values
    }

    /// 显式清除 wire Base64。
    pub fn clear(&mut self) {
        for value in self.values.values_mut() {
            if let PluginWireValue::Bytes { base64 } = value {
                base64.zeroize();
            }
        }
    }
}

impl Drop for PluginConfigurationInput {
    fn drop(&mut self) {
        self.clear();
    }
}

impl std::fmt::Debug for PluginConfigurationInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginConfigurationInput")
            .field("fields", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl Default for PluginConfigurationInput {
    fn default() -> Self {
        Self::empty()
    }
}

fn valid_field_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 64
}

fn valid_configuration_labels(field: &PluginConfigurationField) -> bool {
    field
        .label
        .as_ref()
        .is_none_or(|label| valid_bounded_text(label))
        && field.localized_labels.len() <= MAX_PLUGIN_CONFIGURATION_LOCALIZATIONS
        && field.localized_labels.iter().all(|(locale, value)| {
            (2..=35).contains(&locale.len())
                && locale
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && valid_bounded_text(value)
        })
}

fn valid_bounded_text(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= MAX_PLUGIN_CONFIGURATION_LABEL_CHARS
}
