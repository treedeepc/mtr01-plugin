//
//  checksum_tests.rs
//  leeway-protocol-core / tests
//
//  文件职责：验证 V1 固定 checksum 黄金向量。
//

use leeway_protocol_core::AesCmacKey;

macro_rules! assert_not_clone {
    ($type:ty) => {
        const _: () = {
            trait AmbiguousIfClone<Marker> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}

            let _ = <$type as AmbiguousIfClone<_>>::marker;
        };
    };
}

assert_not_clone!(AesCmacKey);
use leeway_protocol_core::checksum::{
    aes_cmac, crc16_ccitt_false, crc16_modbus, crc32_iso_hdlc, sum8, xor8,
};

/// 验证 Modbus CRC16 黄金向量。
#[test]
fn crc16_modbus_matches_known_vector() {
    assert_eq!(crc16_modbus(b"123456789"), 0x4B37);
}

/// 验证 CCITT-FALSE CRC16 黄金向量。
#[test]
fn crc16_ccitt_false_matches_known_vector() {
    assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
}

/// 验证 ISO-HDLC CRC32 黄金向量。
#[test]
fn crc32_iso_hdlc_matches_known_vector() {
    assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);
}

/// 验证 8 位累加和与异或。
#[test]
fn byte_checksums_match_known_vectors() {
    assert_eq!(sum8(&[1, 2, 250]), 253);
    assert_eq!(xor8(&[1, 2, 3]), 0);
}

/// 验证 AES-CMAC 的 RFC 4493 黄金向量。
#[test]
fn aes_cmac_matches_rfc_4493_vectors() {
    let key = AesCmacKey::new([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ]);
    assert_eq!(
        aes_cmac(&key, &[]).expect("empty CMAC"),
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ]
    );
    assert_eq!(
        aes_cmac(
            &key,
            &[
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
        )
        .expect("block CMAC"),
        [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ]
    );
    assert_eq!(
        aes_cmac(
            &key,
            &hex::decode(
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
            )
            .expect("hex"),
        )
        .expect("40-byte CMAC"),
        [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
            0xc8, 0x27,
        ]
    );
    assert_eq!(
        aes_cmac(&key, &hex::decode("54435a51412301").expect("hex")).expect("partial-block CMAC"),
        [
            0x2e, 0xb9, 0xff, 0xaa, 0x61, 0x12, 0x5f, 0x8f, 0x88, 0x25, 0xdd, 0x3e, 0xc8, 0x04,
            0x33, 0xd2,
        ]
    );
}

/// 验证调试输出不会泄露 AES-CMAC 密钥。
#[test]
fn aes_cmac_key_debug_output_is_redacted() {
    let key = AesCmacKey::new([0x5a; 16]);
    assert_eq!(format!("{key:?}"), "AesCmacKey([REDACTED])");
}
