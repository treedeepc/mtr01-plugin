//!
//! `report_fields.rs`
//! leeway-protocol-mtr01 / report fields
//!
//! 文件职责：提供 MTR01 A@ 报告中的显式标量字段覆盖。
//!

use thiserror::Error;

use crate::Mtr01AData;

/// MTR01 A@ 中允许由模拟器配置的标量值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mtr01ScalarFields {
    /// 电量百分比。
    pub state_of_charge_percent: u8,
    /// MOS 温度原始值，单位为 0.1 摄氏度。
    pub mos_temperature_deci_celsius: u16,
    /// 总电压原始值，单位为 10 mV。
    pub total_voltage_10mv: u16,
    /// 总电流原始值，单位为 0.01 A。
    pub current_centiamps: i16,
    /// 功率，单位为 W。
    pub power_watts: i16,
    /// 循环次数。
    pub cycle_count: u16,
}

/// 只覆盖调用方显式提供的 MTR01 标量。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Mtr01ScalarOverrides {
    /// 可选电量百分比。
    pub state_of_charge_percent: Option<u8>,
    /// 可选 MOS 温度原始值。
    pub mos_temperature_deci_celsius: Option<u16>,
    /// 可选总电压原始值。
    pub total_voltage_10mv: Option<u16>,
    /// 可选总电流原始值。
    pub current_centiamps: Option<i16>,
    /// 可选功率。
    pub power_watts: Option<i16>,
    /// 可选循环次数。
    pub cycle_count: Option<u16>,
}

/// MTR01 标量覆盖错误。
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Mtr01ScalarFieldError {
    /// 显式电量覆盖不在 0 到 100 之间。
    #[error("MTR01 state of charge override must be between 0 and 100.")]
    StateOfChargeOutOfRange,
}

impl Mtr01AData {
    /// 返回当前报告的六个可配置标量。
    #[must_use]
    pub fn scalar_fields(&self) -> Mtr01ScalarFields {
        Mtr01ScalarFields {
            state_of_charge_percent: self.state_of_charge_percent,
            mos_temperature_deci_celsius: self.mos_temperature_deci_celsius,
            total_voltage_10mv: self.total_voltage_10mv,
            current_centiamps: self.current_centiamps,
            power_watts: self.power_watts,
            cycle_count: self.cycle_count,
        }
    }

    /// 只修改显式提供的标量；未提供字段保持不变。
    ///
    /// # Errors
    ///
    /// 显式电量不在 0 到 100 之间时返回稳定错误。
    pub fn apply_scalar_overrides(
        &mut self,
        overrides: &Mtr01ScalarOverrides,
    ) -> Result<(), Mtr01ScalarFieldError> {
        if let Some(value) = overrides.state_of_charge_percent {
            if value > 100 {
                return Err(Mtr01ScalarFieldError::StateOfChargeOutOfRange);
            }
            self.state_of_charge_percent = value;
        }
        if let Some(value) = overrides.mos_temperature_deci_celsius {
            self.mos_temperature_deci_celsius = value;
        }
        if let Some(value) = overrides.total_voltage_10mv {
            self.total_voltage_10mv = value;
        }
        if let Some(value) = overrides.current_centiamps {
            self.current_centiamps = value;
        }
        if let Some(value) = overrides.power_watts {
            self.power_watts = value;
        }
        if let Some(value) = overrides.cycle_count {
            self.cycle_count = value;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "report_fields_tests.rs"]
mod tests;
