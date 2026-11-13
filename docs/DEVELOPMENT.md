# Mtr01 开发指导

## 协议行为

当前实现使用 MTR01 TCZQ 固定帧头、长度域和 16 字节 AES-CMAC：

- 支持 V1.5.1 的 A/B/C/D 请求和应答消息；
- Bundle 使用 canonical BLE Profile，通知载荷块为 244 字节；
- 默认场景 ID 为 `mtr01-sim`，收到 `aSubscribe` 后发送 `aData`；
- 默认场景通过 `editableCollections.bmsDevices` 暴露 7 个 BMS 扫描槽位；
  模拟器只显示实际 BMS，编码 C@ 时自动补齐 30 字节 EF 空槽。
- `editableFields` 的 26 个字段覆盖 A@ 全部可读字段、B@ 设备信息以及基础/运行配置字段：
  单体电压数组、电芯温度数组、状态、容量、数据来源、故障码、名称、序列号、
  软硬件版本、BMS/电池型号、波特率、整车协议、车辆品牌、电芯串数、电耗和 OCV。

修改协议时应同时更新：

1. `bundle/Contents/Resources/protocol.json`；
2. `plugin/src/handler.rs`；
3. `protocol/src/definition.rs`；
4. `plugin/tests/mtr01_plugin_tests.rs`；
5. `bundle/Contents/Resources/scenario.json`；
6. 最后更新 manifest 资源摘要。

## ABI v1 八个操作

处理器必须实现：

- `describe`：返回与 `protocol.json` 完全一致的协议定义；
- `create`：返回不透明实例句柄；
- `destroy`：释放实例句柄；
- `encode`：把消息字段编码为完整帧；
- `decode`：把完整帧解码为消息 ID、字段和原始字节；
- `streamCreate`：返回不透明流句柄；
- `streamPush`：接收 Base64 字节并返回完整帧数组；
- `streamDestroy`：释放流句柄。

可恢复协议错误使用 `{ok:false,error}`；ABI 指针、长度和 JSON 边界错误由
`leeway-protocol-plugin-abi` 统一拒绝。

## 配置模型

`configuration.json` 声明必需的 16 字节 `cmacKey`。秘密只能以固定长度
`secretBytes/hex` 输入，由宿主在调用前解码为 wire Base64。不要在日志、错误或
测试夹具中记录秘密。

## BMS 设备功能

`deviceFunctions` 只使用 V1.5.1 现有消息，不增加线上字段：

- `configureBms` 接收 B#01，保存 BMS 型号、电池类型、波特率、整车协议和品牌；
- `connectOnceBms` 处理 C#02 control 01，保存连接地址并切换到 BMS 孪生报告；
- `bindAndConnectBms` 处理 C#02 control 02，切换报告并记录已绑定；
- `disconnectBms` 处理 C#02 control 03，恢复本地测算报告且不发送 C@。

连接和断开通过把 `report` 切换到 `bmsTwinReport` 或 `localReport` 改变 A@
offset 87 的 `dataSource`，A@ 仍固定为 89 字节。B#01 同时保存当前配置状态，
使后续连接功能可以由 `configured` 启用。模拟器通用 Core 不包含 MTR01 分支。

## 安全边界

- 插件仅提供协议适配、受限配置和默认场景。
- contracts SDK 禁止 unsafe；ABI 与插件 crate 默认拒绝 unsafe。
- 仅 `plugin/src/ffi.rs` 的 `#[allow(unsafe_code)]` 模块可以承载 C ABI 指针。
- 新增 unsafe 块必须带中文 `SAFETY` 说明并单独评审。
- 插件不得打开 socket、串口、文件、窗口或 Runtime 管理能力。

## 签名与 Team ID

正式 Bundle 和 dylib 必须使用同一稳定 Apple Development Team ID。构建脚本会
拒绝 ad-hoc、缺失身份、Team ID 不一致、签名校验失败或 CodeResources 未封装
dylib 的产物。构建命令不得把签名身份写入项目文件、日志或 Git 历史。
