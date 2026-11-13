# Mtr01 官方协议插件

本目录是独立 Cargo workspace，可脱离 Leeway 源码完成测试和签名构建。

- 插件 ID：`com.leeway.mtr01`
- 协议 ID：`mtr01-protocol`
- 生成 crate：`leeway-protocol-mtr01-plugin`
- 默认场景：`mtr01-sim`
- BMS 列表：`editableCollections.bmsDevices`，协议容量 7，每槽 30 字节
- 设备参数：A@ 全部字段、B@ 设备信息、基础配置、运行参数、OCV 和状态，共 26 个标量配置项
- BMS 流程：`deviceFunctions` 声明基础配置、即时连接、绑定连接和断开解绑
- 配置持久化：上位机 B#01/B#02 与设置窗口修改会保存到 Runtime 私有状态目录

## 目录

| 路径 | 职责 |
| --- | --- |
| `plugin/` | 协议处理器、C ABI 入口和 Rust 测试 |
| `sdk/` | 当前 ABI v1 与 contracts 的独立源码快照 |
| `bundle/` | 插件 manifest、协议、模拟场景和配置 |
| `scripts/build-plugin.sh` | 模板校验、Release 构建和稳定身份签名 |

## 测试

```bash
cargo test -p leeway-protocol-mtr01
cargo test -p leeway-protocol-mtr01-plugin
```

首次测试或构建会生成根目录 `Cargo.lock`。官方插件项目应将
`Cargo.lock` 作为可复现资产提交。

## 校验

```bash
bash scripts/build-plugin.sh --validate-template
```

校验只读取 Bundle，不修改文件。修改 `protocol.json`、`scenario.json` 或
`configuration.json` 后，应先运行：

```bash
shasum -a 256 bundle/Contents/Resources/protocol.json
shasum -a 256 bundle/Contents/Resources/scenario.json
shasum -a 256 bundle/Contents/Resources/configuration.json
```

再把新摘要写入 `bundle/Contents/Resources/plugin.json` 的对应字段，最后重新
运行模板校验。

## 签名构建

先通过本机钥匙串获取稳定签名身份：

```bash
security find-identity -v -p codesigning
```

然后显式传入身份：

```bash
LEEWAY_CODE_SIGN_IDENTITY="Apple Development: ..." \
  bash scripts/build-plugin.sh
```

构建产物位于 `.build/protocol-plugins/com.leeway.mtr01.leewayplugin`。

## 清理

`target`、`.build` 和项目根 `Cargo.lock` 的状态可独立检查。删除
`target` 或 `.build` 不会修改源文件；`Cargo.lock` 是复现资产，不建议删除。
