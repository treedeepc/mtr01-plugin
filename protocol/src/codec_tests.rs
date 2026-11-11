// 文件职责：验证 codec 模块的内部行为。

use super::*;

#[test]
fn stored_key_matches_direct_cmac() {
    let codec = Mtr01Codec::new([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ]);
    assert_eq!(
        hex::encode(aes_cmac(&codec.key, b"TCZQA#\x01").expect("AES-CMAC key is fixed width"),),
        "2eb9ffaa61125f8f8825dd3ec80433d2"
    );
}
