// 文件职责：验证 MTR01 A@ 标量读取和显式覆盖。

use crate::{
    Mtr01AData, Mtr01Codec, Mtr01Command, Mtr01ScalarFieldError, Mtr01ScalarFields,
    Mtr01ScalarOverrides,
};

const ORIGINAL_REPORT_HEX: &str = "40014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0157002885ffc0ff01004101d0070100";
const SOC_40_REPORT_HEX: &str = "40014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0128002885ffc0ff01004101d0070100";
const SOC_40_FRAME_HEX: &str = "54435a5141405940014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001400140014001fa00fb00fc00fd003e0128002885ffc0ff01004101d0070100cf4a4584741a0cb0fe207692869a58d9";
const TEST_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

#[test]
fn decodes_scalar_fields() {
    let payload = hex::decode(ORIGINAL_REPORT_HEX).expect("report hex");
    let report = Mtr01AData::from_payload(&payload).expect("report");
    assert_eq!(
        report.scalar_fields(),
        Mtr01ScalarFields {
            state_of_charge_percent: 87,
            mos_temperature_deci_celsius: 318,
            total_voltage_10mv: 10_240,
            current_centiamps: -123,
            power_watts: -64,
            cycle_count: 321,
        }
    );
}

#[test]
fn empty_overrides_preserve_every_byte() {
    let original = hex::decode(ORIGINAL_REPORT_HEX).expect("report hex");
    let mut report = Mtr01AData::from_payload(&original).expect("report");
    report
        .apply_scalar_overrides(&Mtr01ScalarOverrides::default())
        .expect("overrides");
    assert_eq!(report.to_payload(), original);
}

#[test]
fn explicit_soc_override_changes_only_offset_74() {
    let original = hex::decode(ORIGINAL_REPORT_HEX).expect("report hex");
    let mut report = Mtr01AData::from_payload(&original).expect("report");
    report
        .apply_scalar_overrides(&Mtr01ScalarOverrides {
            state_of_charge_percent: Some(40),
            ..Mtr01ScalarOverrides::default()
        })
        .expect("overrides");
    let updated = report.to_payload();
    assert_eq!(hex::encode(&updated), SOC_40_REPORT_HEX);
    for index in 0..89 {
        if index != 74 {
            assert_eq!(updated[index], original[index], "byte {index}");
        }
    }
}

#[test]
fn uncovered_out_of_recommended_range_value_is_preserved() {
    let mut original = hex::decode(ORIGINAL_REPORT_HEX).expect("report hex");
    original[74] = 255;
    let mut report = Mtr01AData::from_payload(&original).expect("report");
    report
        .apply_scalar_overrides(&Mtr01ScalarOverrides::default())
        .expect("overrides");
    assert_eq!(report.to_payload()[74], 255);
}

#[test]
fn explicit_soc_above_100_is_rejected() {
    let original = hex::decode(ORIGINAL_REPORT_HEX).expect("report hex");
    let mut report = Mtr01AData::from_payload(&original).expect("report");
    assert_eq!(
        report.apply_scalar_overrides(&Mtr01ScalarOverrides {
            state_of_charge_percent: Some(101),
            ..Mtr01ScalarOverrides::default()
        }),
        Err(Mtr01ScalarFieldError::StateOfChargeOutOfRange)
    );
}

#[test]
fn updated_report_produces_golden_a_data_frame() {
    let mut report =
        Mtr01AData::from_payload(&hex::decode(ORIGINAL_REPORT_HEX).expect("report hex"))
            .expect("report");
    report
        .apply_scalar_overrides(&Mtr01ScalarOverrides {
            state_of_charge_percent: Some(40),
            ..Mtr01ScalarOverrides::default()
        })
        .expect("overrides");
    let frame = Mtr01Codec::new(TEST_KEY)
        .encode(Mtr01Command::AResponse, &report.to_payload())
        .expect("frame");
    assert_eq!(hex::encode(frame), SOC_40_FRAME_HEX);
}
