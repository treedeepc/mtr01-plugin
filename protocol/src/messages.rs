//
//  messages.rs
//  leeway-protocol-mtr01
//
//  文件职责：实现 MTR01 V1.5.1 的 A/B/C/D 业务载荷编解码。
//

use crate::Mtr01Error;

const DELIMITER: u8 = 0xEF;

/// A# 实时数据请求类型。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01ARequest {
    /// 订阅 500 ms 周期实时数据。
    Subscribe,
    /// 取消订阅。
    Unsubscribe,
    /// 获取一次实时数据。
    ReadOnce,
}

impl Mtr01ARequest {
    /// 编码为 1 字节数据域。
    #[must_use]
    pub const fn to_payload(self) -> [u8; 1] {
        [match self {
            Self::Subscribe => 0x01,
            Self::Unsubscribe => 0x02,
            Self::ReadOnce => 0x03,
        }]
    }

    /// 从 1 字节数据域解析。
    ///
    /// # Errors
    ///
    /// 数据域长度或命令值不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x01] => Ok(Self::Subscribe),
            [0x02] => Ok(Self::Unsubscribe),
            [0x03] => Ok(Self::ReadOnce),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// A@ 固定 89 字节实时数据。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01AData {
    /// 32 路单体电压原始值，单位 10 mV。
    pub cell_voltage_10mv: [u16; 32],
    /// T1 到 T4 温度原始值，单位 0.1 摄氏度。
    pub temperature_deci_celsius: [u16; 4],
    /// BMS MOSFET 温度原始值，单位 0.1 摄氏度。
    pub mos_temperature_deci_celsius: u16,
    /// SOC 百分比。
    pub state_of_charge_percent: u8,
    /// 总电压原始值，单位 10 mV。
    pub total_voltage_10mv: u16,
    /// 总电流原始值，单位 0.01 A。
    pub current_centiamps: i16,
    /// 功率原始值，单位 W。
    pub power_watts: i16,
    /// 放电标识。
    pub discharge_state: u8,
    /// 充电标识。
    pub charge_state: u8,
    /// 循环次数。
    pub cycle_count: u16,
    /// 额定容量原始值，单位 10 mAh。
    pub rated_capacity_10mah: u16,
    /// 数据来源：01 本地测算，02 BMS 孪生。
    pub data_source: u8,
    /// 故障码：00 无异常，01 电流读数异常已屏蔽，02 电压读数异常已屏蔽。
    pub fault_code: u8,
}

impl Mtr01AData {
    /// A@ 数据域固定长度。
    pub const PAYLOAD_BYTES: usize = 89;

    /// 编码为固定 89 字节小端数据域。
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::PAYLOAD_BYTES);
        for value in self.cell_voltage_10mv {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        for value in self.temperature_deci_celsius {
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&self.mos_temperature_deci_celsius.to_le_bytes());
        payload.push(self.state_of_charge_percent);
        payload.extend_from_slice(&self.total_voltage_10mv.to_le_bytes());
        payload.extend_from_slice(&self.current_centiamps.to_le_bytes());
        payload.extend_from_slice(&self.power_watts.to_le_bytes());
        payload.push(self.discharge_state);
        payload.push(self.charge_state);
        payload.extend_from_slice(&self.cycle_count.to_le_bytes());
        payload.extend_from_slice(&self.rated_capacity_10mah.to_le_bytes());
        payload.push(self.data_source);
        payload.push(self.fault_code);
        payload
    }

    /// 从固定 89 字节数据域解析。
    ///
    /// # Errors
    ///
    /// 数据域长度不等于 89 字节时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        let mut offset = 0;
        let mut cell_voltage_10mv = [0_u16; 32];
        for value in &mut cell_voltage_10mv {
            *value = read_u16_le(payload, &mut offset)?;
        }
        let mut temperature_deci_celsius = [0_u16; 4];
        for value in &mut temperature_deci_celsius {
            *value = read_u16_le(payload, &mut offset)?;
        }
        let mos_temperature_deci_celsius = read_u16_le(payload, &mut offset)?;
        let state_of_charge_percent = *payload
            .get(offset)
            .ok_or(Mtr01Error::InvalidPayloadLength)?;
        offset += 1;
        let total_voltage_10mv = read_u16_le(payload, &mut offset)?;
        let current_centiamps = read_i16_le(payload, &mut offset)?;
        let power_watts = read_i16_le(payload, &mut offset)?;
        let discharge_state = *payload
            .get(offset)
            .ok_or(Mtr01Error::InvalidPayloadLength)?;
        let charge_state = *payload
            .get(offset + 1)
            .ok_or(Mtr01Error::InvalidPayloadLength)?;
        offset += 2;
        let cycle_count = read_u16_le(payload, &mut offset)?;
        let rated_capacity_10mah = read_u16_le(payload, &mut offset)?;
        let data_source = *payload
            .get(offset)
            .ok_or(Mtr01Error::InvalidPayloadLength)?;
        if !matches!(data_source, 0x01 | 0x02) {
            return Err(Mtr01Error::UnsupportedValue);
        }
        let fault_code = *payload
            .get(offset + 1)
            .ok_or(Mtr01Error::InvalidPayloadLength)?;
        if fault_code > 0x02 {
            return Err(Mtr01Error::UnsupportedValue);
        }
        Ok(Self {
            cell_voltage_10mv,
            temperature_deci_celsius,
            mos_temperature_deci_celsius,
            state_of_charge_percent,
            total_voltage_10mv,
            current_centiamps,
            power_watts,
            discharge_state,
            charge_state,
            cycle_count,
            rated_capacity_10mah,
            data_source,
            fault_code,
        })
    }
}

/// D# 深度绑定请求。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mtr01BindingRequest {
    /// 当前未绑定，仅发送 1 字节状态。
    Unbound,
    /// 已绑定或绑定配置，发送 EF 和 16 字节绑定码。
    Bound {
        /// 协议绑定状态。
        status: u8,
        /// 16 字节绑定码。
        code: [u8; 16],
    },
}

impl Mtr01BindingRequest {
    /// 编码为 1 或 18 字节载荷。
    ///
    /// # Errors
    ///
    /// 绑定状态不是 0x02 或 0x03 时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        match self {
            Self::Unbound => Ok(vec![0x01]),
            Self::Bound { status, code } if matches!(status, 0x02 | 0x03) => {
                let mut payload = Vec::with_capacity(18);
                payload.push(*status);
                payload.push(DELIMITER);
                payload.extend_from_slice(code);
                Ok(payload)
            }
            Self::Bound { .. } => Err(Mtr01Error::UnsupportedValue),
        }
    }

    /// 从 1 或 18 字节载荷解析。
    ///
    /// # Errors
    ///
    /// 长度、状态或 EF 标识不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x01] => Ok(Self::Unbound),
            [status @ (0x02 | 0x03), DELIMITER, code @ ..] if code.len() == 16 => Ok(Self::Bound {
                status: *status,
                code: code
                    .try_into()
                    .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
            }),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// D@ 深度绑定应答。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01BindingResponse {
    /// 身份确认，开始通讯。
    ConfirmIdentity,
    /// 绑定码已记录。
    BindingRecorded,
    /// 非法身份。
    RejectedIdentity,
}

impl Mtr01BindingResponse {
    /// 编码为两字节大端应答码。
    #[must_use]
    pub const fn to_payload(self) -> [u8; 2] {
        match self {
            Self::ConfirmIdentity => [0x00, 0x01],
            Self::BindingRecorded => [0x01, 0x01],
            Self::RejectedIdentity => [0x02, 0x01],
        }
    }

    /// 从两字节应答码解析。
    ///
    /// # Errors
    ///
    /// 应答码不受支持时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x00, 0x01] => Ok(Self::ConfirmIdentity),
            [0x01, 0x01] => Ok(Self::BindingRecorded),
            [0x02, 0x01] => Ok(Self::RejectedIdentity),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// V1.5.1 BMS 型号。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01BmsType {
    /// ATN-。
    AtnDash,
    /// ATN@。
    AtnAt,
    /// JBD。
    Jbd,
    /// JK。
    Jk,
    /// YY。
    Yy,
}

impl Mtr01BmsType {
    const fn byte(self) -> u8 {
        match self {
            Self::AtnDash => 0x01,
            Self::AtnAt => 0x02,
            Self::Jbd => 0x03,
            Self::Jk => 0x04,
            Self::Yy => 0x05,
        }
    }

    const fn from_byte(value: u8) -> Result<Self, Mtr01Error> {
        match value {
            0x01 => Ok(Self::AtnDash),
            0x02 => Ok(Self::AtnAt),
            0x03 => Ok(Self::Jbd),
            0x04 => Ok(Self::Jk),
            0x05 => Ok(Self::Yy),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// V1.5.1 电池种类。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01BatteryType {
    /// 三元锂。
    TernaryLithium,
    /// 磷酸铁锂。
    LithiumIronPhosphate,
    /// 铅酸。
    LeadAcid,
}

impl Mtr01BatteryType {
    const fn byte(self) -> u8 {
        match self {
            Self::TernaryLithium => 0x01,
            Self::LithiumIronPhosphate => 0x02,
            Self::LeadAcid => 0x03,
        }
    }

    const fn from_byte(value: u8) -> Result<Self, Mtr01Error> {
        match value {
            0x01 => Ok(Self::TernaryLithium),
            0x02 => Ok(Self::LithiumIronPhosphate),
            0x03 => Ok(Self::LeadAcid),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// V1.5.1 B# cmd 01 基础配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01BasicConfig {
    /// BMS 型号。
    pub bms_type: Mtr01BmsType,
    /// 电池种类。
    pub battery_type: Mtr01BatteryType,
    /// 整车协议波特率。
    pub baud_rate: u32,
    /// 整车协议，仅允许 RS 或 1W。
    pub vehicle_protocol: String,
    /// 车辆品牌，最多 5 字节 ASCII。
    pub vehicle_brand: String,
}

impl Mtr01BasicConfig {
    /// B# cmd 01 固定长度。
    pub const PAYLOAD_BYTES: usize = 13;

    /// 编码基础配置。
    ///
    /// # Errors
    ///
    /// 波特率、协议、品牌或 ASCII 字段不合法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        if self.baud_rate > 0x00ff_ffff {
            return Err(Mtr01Error::UnsupportedValue);
        }
        let protocol = exact_ascii(&self.vehicle_protocol, 2)?;
        if !matches!(protocol.as_slice(), b"RS" | b"1W") {
            return Err(Mtr01Error::UnsupportedValue);
        }
        let mut payload = Vec::with_capacity(Self::PAYLOAD_BYTES);
        payload.push(0x01);
        payload.push(self.bms_type.byte());
        payload.push(self.battery_type.byte());
        payload.extend_from_slice(&[
            u8::try_from((self.baud_rate >> 16) & 0xff)
                .map_err(|_| Mtr01Error::UnsupportedValue)?,
            u8::try_from((self.baud_rate >> 8) & 0xff).map_err(|_| Mtr01Error::UnsupportedValue)?,
            u8::try_from(self.baud_rate & 0xff).map_err(|_| Mtr01Error::UnsupportedValue)?,
        ]);
        payload.extend_from_slice(&protocol);
        payload.extend_from_slice(&left_pad_ascii(&self.vehicle_brand, 5)?);
        Ok(payload)
    }

    /// 解码基础配置。
    ///
    /// # Errors
    ///
    /// 长度、cmd、枚举、ASCII 或品牌填充不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if payload[0] != 0x01 {
            return Err(Mtr01Error::UnsupportedCommand);
        }
        let vehicle_protocol = ascii_string(&payload[6..8])?;
        if !matches!(vehicle_protocol.as_str(), "RS" | "1W") {
            return Err(Mtr01Error::UnsupportedValue);
        }
        Ok(Self {
            bms_type: Mtr01BmsType::from_byte(payload[1])?,
            battery_type: Mtr01BatteryType::from_byte(payload[2])?,
            baud_rate: u32::from_be_bytes([0, payload[3], payload[4], payload[5]]),
            vehicle_protocol,
            vehicle_brand: strip_left_padding(&payload[8..13])?,
        })
    }
}

/// V1.5.1 B# cmd 02 运行参数和原始 OCV。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01RuntimeConfig {
    /// 额定容量，单位 10 mAh。
    pub rated_capacity_10mah: u16,
    /// 电芯串数。
    pub cell_count: u8,
    /// 百公里电耗，单位 Wh/100 km。
    pub consumption_wh_per_100km: u16,
    /// 21 个 OCV 的 42 字节原始表示；全 EF 表示未配置。
    pub ocv_raw: [u8; 42],
}

impl Mtr01RuntimeConfig {
    /// B# cmd 02 固定长度。
    pub const PAYLOAD_BYTES: usize = 48;

    /// 编码运行参数。
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::PAYLOAD_BYTES);
        payload.push(0x02);
        payload.extend_from_slice(&self.rated_capacity_10mah.to_le_bytes());
        payload.push(self.cell_count);
        payload.extend_from_slice(&self.consumption_wh_per_100km.to_le_bytes());
        payload.extend_from_slice(&self.ocv_raw);
        payload
    }

    /// 解码运行参数。
    ///
    /// # Errors
    ///
    /// 长度或 cmd 不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if payload[0] != 0x02 {
            return Err(Mtr01Error::UnsupportedCommand);
        }
        Ok(Self {
            rated_capacity_10mah: u16::from_le_bytes([payload[1], payload[2]]),
            cell_count: payload[3],
            consumption_wh_per_100km: u16::from_le_bytes([payload[4], payload[5]]),
            ocv_raw: payload[6..48]
                .try_into()
                .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
        })
    }
}

/// V1.5.1 B# cmd 03 身份信息。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01IdentityConfig {
    /// BMS 序列号，12 到 32 字节 ASCII。
    pub serial_number: String,
    /// 国标码，可为空。
    pub national_code: String,
}

impl Mtr01IdentityConfig {
    /// 编码身份信息。
    ///
    /// # Errors
    ///
    /// 序列号长度、ASCII 或总长度不合法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        let serial = ascii_bytes(&self.serial_number)?;
        if !(12..=32).contains(&serial.len()) {
            return Err(Mtr01Error::UnsupportedValue);
        }
        let national = ascii_bytes(&self.national_code)?;
        let total = 3 + serial.len() + national.len();
        if total > u8::MAX as usize {
            return Err(Mtr01Error::FrameTooLarge);
        }
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&[0x03, DELIMITER]);
        payload.extend_from_slice(serial);
        payload.push(DELIMITER);
        payload.extend_from_slice(national);
        Ok(payload)
    }

    /// 解码身份信息。
    ///
    /// # Errors
    ///
    /// 长度、cmd、EF 分隔符、序列号长度或 ASCII 不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() < 3 {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if payload[0] != 0x03 {
            return Err(Mtr01Error::UnsupportedCommand);
        }
        if payload[1] != DELIMITER {
            return Err(Mtr01Error::InvalidDelimiter);
        }
        let separator = payload[2..]
            .iter()
            .position(|byte| *byte == DELIMITER)
            .map(|index| index + 2)
            .ok_or(Mtr01Error::InvalidDelimiter)?;
        let serial = &payload[2..separator];
        if !(12..=32).contains(&serial.len()) {
            return Err(Mtr01Error::UnsupportedValue);
        }
        Ok(Self {
            serial_number: ascii_string(serial)?,
            national_code: ascii_string(
                payload
                    .get(separator + 1..)
                    .ok_or(Mtr01Error::InvalidPayloadLength)?,
            )?,
        })
    }
}

/// V1.5.1 B# cmd 04 校准和设备重启。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01CalibrationControl {
    /// 电压校准。
    Voltage,
    /// 电流校准。
    Current,
    /// 设备重启。
    Restart,
}

impl Mtr01CalibrationControl {
    const fn byte(self) -> u8 {
        match self {
            Self::Voltage => 0x01,
            Self::Current => 0x02,
            Self::Restart => 0x03,
        }
    }

    const fn from_byte(value: u8) -> Result<Self, Mtr01Error> {
        match value {
            0x01 => Ok(Self::Voltage),
            0x02 => Ok(Self::Current),
            0x03 => Ok(Self::Restart),
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// V1.5.1 B# 请求。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mtr01BRequest {
    /// cmd 00 获取设备信息。
    GetInfo,
    /// cmd 01 基础配置。
    Basic(Mtr01BasicConfig),
    /// cmd 02 运行参数。
    Runtime(Mtr01RuntimeConfig),
    /// cmd 03 身份信息。
    Identity(Mtr01IdentityConfig),
    /// cmd 04 校准控制。
    Calibration(Mtr01CalibrationControl),
}

impl Mtr01BRequest {
    /// 编码 B# 请求。
    ///
    /// # Errors
    ///
    /// 载荷字段非法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        match self {
            Self::GetInfo => Ok(vec![0x00]),
            Self::Basic(config) => config.to_payload(),
            Self::Runtime(config) => Ok(config.to_payload()),
            Self::Identity(config) => config.to_payload(),
            Self::Calibration(control) => Ok(vec![0x04, control.byte()]),
        }
    }

    /// 解码 B# 请求。
    ///
    /// # Errors
    ///
    /// cmd、长度或载荷不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x00] => Ok(Self::GetInfo),
            [0x01, ..] => Ok(Self::Basic(Mtr01BasicConfig::from_payload(payload)?)),
            [0x02, ..] => Ok(Self::Runtime(Mtr01RuntimeConfig::from_payload(payload)?)),
            [0x03, ..] => Ok(Self::Identity(Mtr01IdentityConfig::from_payload(payload)?)),
            [0x04, control] => Ok(Self::Calibration(Mtr01CalibrationControl::from_byte(
                *control,
            )?)),
            [] | [0x04, ..] => Err(Mtr01Error::InvalidPayloadLength),
            _ => Err(Mtr01Error::UnsupportedCommand),
        }
    }
}

/// V1.5.1 B@ cmd 00 设备信息和当前本地配置。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01DeviceInfoV15 {
    /// 设备名称，最多 10 字节。
    pub device_name: String,
    /// 序列号，最多 32 字节。
    pub serial_number: String,
    /// 软件版本，最多 6 字节。
    pub software_version: String,
    /// 硬件版本，最多 5 字节。
    pub hardware_version: String,
    /// 当前基础配置。
    pub basic_config: Mtr01BasicConfig,
    /// 当前运行参数与 OCV 配置。
    pub runtime_config: Mtr01RuntimeConfig,
}

impl Mtr01DeviceInfoV15 {
    /// B@ cmd 00 固定长度。
    pub const PAYLOAD_BYTES: usize = 113;

    /// 编码设备信息。
    ///
    /// # Errors
    ///
    /// ASCII 或固定字段宽度不合法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        let mut payload = Vec::with_capacity(Self::PAYLOAD_BYTES);
        payload.push(0x00);
        payload.extend_from_slice(&left_pad_ascii(&self.device_name, 10)?);
        payload.extend_from_slice(&left_pad_ascii(&self.serial_number, 32)?);
        payload.extend_from_slice(&left_pad_ascii(&self.software_version, 6)?);
        payload.extend_from_slice(&left_pad_ascii(&self.hardware_version, 5)?);
        payload.extend_from_slice(&self.basic_config.to_payload()?[1..]);
        payload.extend_from_slice(&self.runtime_config.to_payload()[1..]);
        Ok(payload)
    }

    /// 解码设备信息。
    ///
    /// # Errors
    ///
    /// 长度、cmd、EF 填充或 ASCII 不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if payload[0] != 0x00 {
            return Err(Mtr01Error::UnsupportedCommand);
        }
        let mut basic_payload = Vec::with_capacity(Mtr01BasicConfig::PAYLOAD_BYTES);
        basic_payload.push(0x01);
        basic_payload.extend_from_slice(&payload[54..66]);
        let mut runtime_payload = Vec::with_capacity(Mtr01RuntimeConfig::PAYLOAD_BYTES);
        runtime_payload.push(0x02);
        runtime_payload.extend_from_slice(&payload[66..113]);
        Ok(Self {
            device_name: strip_left_padding(&payload[1..11])?,
            serial_number: strip_left_padding(&payload[11..43])?,
            software_version: strip_left_padding(&payload[43..49])?,
            hardware_version: strip_left_padding(&payload[49..54])?,
            basic_config: Mtr01BasicConfig::from_payload(&basic_payload)?,
            runtime_config: Mtr01RuntimeConfig::from_payload(&runtime_payload)?,
        })
    }
}

/// V1.5.1 B@ cmd 01/02/03 反馈。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mtr01BFeedback {
    /// 对应 B# cmd：01、02 或 03。
    pub command: u8,
    /// 稳定反馈码。
    pub code: u8,
}

impl Mtr01BFeedback {
    /// 校验该命令与反馈码组合。
    ///
    /// # Errors
    ///
    /// 命令或反馈码超出 addendum 码表时返回稳定错误。
    pub fn new(command: u8, code: u8) -> Result<Self, Mtr01Error> {
        let valid = match command {
            0x01 | 0x02 => matches!(code, 0x00..=0x02),
            0x03 => code == 0x00,
            _ => false,
        };
        if valid {
            Ok(Self { command, code })
        } else {
            Err(Mtr01Error::UnsupportedValue)
        }
    }

    /// 编码固定 2 字节反馈。
    ///
    /// # Errors
    ///
    /// 命令或反馈码超出码表时返回稳定错误。
    pub fn to_payload(self) -> Result<[u8; 2], Mtr01Error> {
        Self::new(self.command, self.code).map(|value| [value.command, value.code])
    }

    /// 解码固定 2 字节反馈。
    ///
    /// # Errors
    ///
    /// 长度或码表不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        let [command, code] = payload else {
            return Err(Mtr01Error::InvalidPayloadLength);
        };
        Self::new(*command, *code)
    }
}

/// V1.5.1 B@ 应答。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mtr01BResponse {
    /// cmd 00 设备信息。
    DeviceInfo(Mtr01DeviceInfoV15),
    /// cmd 01/02/03 反馈。
    Feedback(Mtr01BFeedback),
}

impl Mtr01BResponse {
    /// 编码 B@ 应答。
    ///
    /// # Errors
    ///
    /// 设备信息字段或反馈码非法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        match self {
            Self::DeviceInfo(info) => info.to_payload(),
            Self::Feedback(feedback) => Ok(feedback.to_payload()?.to_vec()),
        }
    }

    /// 解码 B@ 应答。
    ///
    /// # Errors
    ///
    /// cmd、长度或载荷不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload.first() {
            Some(0x00) => Ok(Self::DeviceInfo(Mtr01DeviceInfoV15::from_payload(payload)?)),
            Some(0x01..=0x03) => Ok(Self::Feedback(Mtr01BFeedback::from_payload(payload)?)),
            Some(_) => Err(Mtr01Error::UnsupportedCommand),
            None => Err(Mtr01Error::InvalidPayloadLength),
        }
    }
}

/// V1.5.1 C# 请求。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01CRequest {
    /// cmd 01 请求扫描列表。
    Scan,
    /// cmd 02 连接控制。
    Connect(Mtr01ConnectControl),
}

impl Mtr01CRequest {
    /// 编码 C# 请求。
    ///
    /// # Errors
    ///
    /// 连接控制字段非法时返回稳定错误。
    pub fn to_payload(self) -> Result<Vec<u8>, Mtr01Error> {
        match self {
            Self::Scan => Ok(vec![0x01]),
            Self::Connect(control) => Ok(control.to_payload()?.to_vec()),
        }
    }

    /// 解码 C# 请求。
    ///
    /// # Errors
    ///
    /// cmd、长度或控制字段不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x01] => Ok(Self::Scan),
            [0x02, ..] => Ok(Self::Connect(Mtr01ConnectControl::from_payload(payload)?)),
            [] => Err(Mtr01Error::InvalidPayloadLength),
            _ => Err(Mtr01Error::UnsupportedCommand),
        }
    }
}

/// V1.5.1 C# cmd 02 连接控制。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mtr01ConnectControl {
    /// 01 即时连接、02 绑定自动连接、03 断开解绑。
    pub control: u8,
    /// 地址类型；control 03 固定为 EF。
    pub address_type: u8,
    /// 6 字节大端地址；control 03 固定全 EF。
    pub address: [u8; 6],
}

impl Mtr01ConnectControl {
    /// C# cmd 02 固定长度。
    pub const PAYLOAD_BYTES: usize = 9;

    /// 编码连接控制。
    ///
    /// # Errors
    ///
    /// 控制字或断开解绑填充不合法时返回稳定错误。
    pub fn to_payload(self) -> Result<[u8; Self::PAYLOAD_BYTES], Mtr01Error> {
        let mut payload = [DELIMITER; Self::PAYLOAD_BYTES];
        payload[0] = 0x02;
        payload[1] = self.control;
        match self.control {
            0x01 | 0x02 => {
                if self.address_type == DELIMITER {
                    return Err(Mtr01Error::UnsupportedValue);
                }
                payload[2] = self.address_type;
                payload[3..].copy_from_slice(&self.address);
            }
            0x03 => {}
            _ => return Err(Mtr01Error::UnsupportedValue),
        }
        Ok(payload)
    }

    /// 解码连接控制。
    ///
    /// # Errors
    ///
    /// 长度、cmd、控制字、地址类型或 EF 填充不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if payload[0] != 0x02 {
            return Err(Mtr01Error::UnsupportedCommand);
        }
        match payload[1] {
            0x01 | 0x02 => {
                if payload[2] == DELIMITER {
                    return Err(Mtr01Error::UnsupportedValue);
                }
                Ok(Self {
                    control: payload[1],
                    address_type: payload[2],
                    address: payload[3..9]
                        .try_into()
                        .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
                })
            }
            0x03 => {
                if payload[2..].iter().any(|byte| *byte != DELIMITER) {
                    return Err(Mtr01Error::InvalidDelimiter);
                }
                Ok(Self {
                    control: 0x03,
                    address_type: DELIMITER,
                    address: [DELIMITER; 6],
                })
            }
            _ => Err(Mtr01Error::UnsupportedValue),
        }
    }
}

/// V1.5.1 C@ cmd 02 连接反馈。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mtr01ConnectionFeedback {
    /// 连接成功。
    Success,
    /// 连接失败。
    Failure,
}

impl Mtr01ConnectionFeedback {
    /// 编码固定 2 字节反馈。
    #[must_use]
    pub const fn to_payload(self) -> [u8; 2] {
        [
            0x02,
            match self {
                Self::Success => 0x01,
                Self::Failure => 0x02,
            },
        ]
    }
}

/// V1.5.1 C@ cmd 01 扫描槽位。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mtr01ScanSlot {
    /// 未使用槽位，30 字节全部为 EF。
    Empty,
    /// 一个 BLE 设备。
    Device {
        /// 蓝牙名称，最多 22 字节 ASCII。
        name: String,
        /// 地址类型。
        address_type: u8,
        /// 6 字节大端地址。
        address: [u8; 6],
        /// RSSI。
        rssi: i8,
    },
}

impl Mtr01ScanSlot {
    /// 单个扫描槽位长度。
    pub const BYTES: usize = 30;

    fn to_bytes(&self) -> Result<[u8; Self::BYTES], Mtr01Error> {
        match self {
            Self::Empty => Ok([DELIMITER; Self::BYTES]),
            Self::Device {
                name,
                address_type,
                address,
                rssi,
            } => {
                if *address_type == DELIMITER {
                    return Err(Mtr01Error::UnsupportedValue);
                }
                let mut slot = [DELIMITER; Self::BYTES];
                let name = left_pad_ascii(name, 22)?;
                slot[..22].copy_from_slice(&name);
                slot[22] = *address_type;
                slot[23..29].copy_from_slice(address);
                slot[29] = u8::from_ne_bytes(rssi.to_ne_bytes());
                Ok(slot)
            }
        }
    }

    fn from_bytes(slot: &[u8]) -> Result<Self, Mtr01Error> {
        if slot.len() != Self::BYTES {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        if slot.iter().all(|byte| *byte == DELIMITER) {
            return Ok(Self::Empty);
        }
        if slot[22] == DELIMITER {
            return Err(Mtr01Error::InvalidDelimiter);
        }
        Ok(Self::Device {
            name: strip_left_padding(&slot[..22])?,
            address_type: slot[22],
            address: slot[23..29]
                .try_into()
                .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
            rssi: i8::from_ne_bytes([slot[29]]),
        })
    }
}

/// V1.5.1 C@ cmd 01 扫描列表。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mtr01ScanList {
    /// 7 个固定槽位，按 RSSI 从强到弱排列。
    pub slots: [Mtr01ScanSlot; 7],
}

impl Mtr01ScanList {
    /// 扫描列表固定长度。
    pub const PAYLOAD_BYTES: usize = 212;

    /// 编码扫描列表。
    ///
    /// # Errors
    ///
    /// 槽位 ASCII、地址或排序不合法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        let mut previous_rssi = None;
        let mut saw_empty = false;
        let mut payload = Vec::with_capacity(Self::PAYLOAD_BYTES);
        payload.extend_from_slice(&[0x01, 0x01]);
        for slot in &self.slots {
            match slot {
                Mtr01ScanSlot::Empty => {
                    saw_empty = true;
                }
                Mtr01ScanSlot::Device { rssi, .. } => {
                    if saw_empty || previous_rssi.is_some_and(|previous| *rssi > previous) {
                        return Err(Mtr01Error::UnsupportedValue);
                    }
                    previous_rssi = Some(*rssi);
                }
            }
            payload.extend_from_slice(&slot.to_bytes()?);
        }
        Ok(payload)
    }

    /// 解码扫描列表。
    ///
    /// # Errors
    ///
    /// 长度、前缀、槽位或排序不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        if payload.len() != Self::PAYLOAD_BYTES || payload.get(..2) != Some(&[0x01, 0x01]) {
            return Err(Mtr01Error::InvalidPayloadLength);
        }
        let mut slots = Vec::with_capacity(7);
        let mut last_rssi = None;
        let mut saw_empty = false;
        for chunk in payload[2..].chunks_exact(Mtr01ScanSlot::BYTES) {
            let slot = Mtr01ScanSlot::from_bytes(chunk)?;
            match slot {
                Mtr01ScanSlot::Empty => saw_empty = true,
                Mtr01ScanSlot::Device { rssi, .. } => {
                    if saw_empty || last_rssi.is_some_and(|previous| rssi > previous) {
                        return Err(Mtr01Error::UnsupportedValue);
                    }
                    last_rssi = Some(rssi);
                }
            }
            slots.push(slot);
        }
        let slots: [Mtr01ScanSlot; 7] = slots
            .try_into()
            .map_err(|_| Mtr01Error::InvalidPayloadLength)?;
        Ok(Self { slots })
    }
}

/// V1.5.1 C@ 应答。
#[allow(
    clippy::large_enum_variant,
    reason = "扫描列表是固定 212 字节协议载荷，枚举按值承载以便直接编解码"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mtr01CResponse {
    /// cmd 02 连接反馈。
    Connection(Mtr01ConnectionFeedback),
    /// cmd 01 扫描列表。
    ScanList(Mtr01ScanList),
    /// cmd 01 扫描失败。
    ScanError,
}

impl Mtr01CResponse {
    /// 编码 C@ 应答。
    ///
    /// # Errors
    ///
    /// 扫描列表字段非法时返回稳定错误。
    pub fn to_payload(&self) -> Result<Vec<u8>, Mtr01Error> {
        match self {
            Self::Connection(value) => Ok(value.to_payload().to_vec()),
            Self::ScanList(value) => value.to_payload(),
            Self::ScanError => Ok(vec![0x01, 0x02]),
        }
    }

    /// 解码 C@ 应答。
    ///
    /// # Errors
    ///
    /// cmd、长度或载荷不合法时返回稳定错误。
    pub fn from_payload(payload: &[u8]) -> Result<Self, Mtr01Error> {
        match payload {
            [0x01, 0x01, ..] => Ok(Self::ScanList(Mtr01ScanList::from_payload(payload)?)),
            [0x01, 0x02] => Ok(Self::ScanError),
            [0x02, 0x01] => Ok(Self::Connection(Mtr01ConnectionFeedback::Success)),
            [0x02, 0x02] => Ok(Self::Connection(Mtr01ConnectionFeedback::Failure)),
            [] | [0x01, ..] | [0x02, ..] => Err(Mtr01Error::InvalidPayloadLength),
            _ => Err(Mtr01Error::UnsupportedCommand),
        }
    }
}

fn read_u16_le(payload: &[u8], offset: &mut usize) -> Result<u16, Mtr01Error> {
    let bytes = payload
        .get(*offset..*offset + 2)
        .ok_or(Mtr01Error::InvalidPayloadLength)?;
    *offset += 2;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
    ))
}

fn read_i16_le(payload: &[u8], offset: &mut usize) -> Result<i16, Mtr01Error> {
    let bytes = payload
        .get(*offset..*offset + 2)
        .ok_or(Mtr01Error::InvalidPayloadLength)?;
    *offset += 2;
    Ok(i16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Mtr01Error::InvalidPayloadLength)?,
    ))
}

fn ascii_bytes(value: &str) -> Result<&[u8], Mtr01Error> {
    let bytes = value.as_bytes();
    if bytes.is_ascii() && !bytes.contains(&DELIMITER) {
        Ok(bytes)
    } else {
        Err(Mtr01Error::InvalidAscii)
    }
}

fn ascii_string(bytes: &[u8]) -> Result<String, Mtr01Error> {
    if !bytes.is_ascii() {
        return Err(Mtr01Error::InvalidAscii);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| Mtr01Error::InvalidAscii)
}

fn exact_ascii(value: &str, width: usize) -> Result<Vec<u8>, Mtr01Error> {
    let bytes = ascii_bytes(value)?;
    if bytes.len() == width {
        Ok(bytes.to_vec())
    } else {
        Err(Mtr01Error::FixedFieldTooLong)
    }
}

fn left_pad_ascii(value: &str, width: usize) -> Result<Vec<u8>, Mtr01Error> {
    let bytes = ascii_bytes(value)?;
    if bytes.len() > width {
        return Err(Mtr01Error::FixedFieldTooLong);
    }
    let mut field = vec![DELIMITER; width - bytes.len()];
    field.extend_from_slice(bytes);
    Ok(field)
}

fn strip_left_padding(bytes: &[u8]) -> Result<String, Mtr01Error> {
    let start = bytes
        .iter()
        .position(|byte| *byte != DELIMITER)
        .unwrap_or(bytes.len());
    ascii_string(&bytes[start..])
}
