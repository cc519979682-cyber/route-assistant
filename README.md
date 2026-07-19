# 软路由分流助手

面向新手的 Windows 软路由分流配置工具。输入 OpenWrt 的 SSH 信息后，软件会识别正在运行的 OpenClash 或 Nikki，把“域名应该直连、拒绝或交给哪个策略组”转换成安全、可预览、可回滚的配置变更。

> 当前为 v0.1 开发版。离线模拟和自动化测试已可用；在真实软路由执行写入前，请先完成只读识别验收并核对兼容性表。

## 首版能力

- Windows 10/11 x64，Tauri 2 + React + TypeScript + Rust。
- SSH 密码或私钥登录，首次显示主机指纹，指纹变化时阻止连接。
- 识别 OpenWrt、OpenClash、Nikki、插件状态和 Mihomo 核心版本。
- 支持精确域名、整站域名、直连、拒绝和现有策略组。
- 只编辑带助手标记的 OpenClash 规则块或 `route_assistant_` Nikki UCI 段。
- 写入前备份，临时文件和语法检查，120 秒路由端看门狗，验证失败自动回滚。
- DNS 只读诊断；不修改 DNS、DHCP、防火墙、订阅或节点。
- 密码和私钥引用保存在 Windows 凭据库；SQLite 不保存明文凭据。
- 无云端、无大模型、无遥测；日志和诊断包默认脱敏。

## 本地开发

需要 Node.js 20+、Rust stable、Visual Studio 2022 Build Tools（Desktop development with C++）和 WebView2。

```powershell
npm ci
npm run build
npm test
cargo test --manifest-path src-tauri/Cargo.toml --all-targets
npm run tauri build
```

在 NAS/UNC 目录开发时，建议将 `CARGO_TARGET_DIR` 指向本机磁盘，避免大量构建缓存写入共享目录。

## 安全边界

“直连”仅表示流量不经过代理，不代表 DNS 解析或 CDN 节点一定在中国大陆。详细威胁模型、备份和回滚说明见 [安全模型](docs/security-model.md)，支持范围见 [兼容性表](docs/compatibility.md)。

真实设备验收分为离线模拟、只读识别和经用户明确确认后的写入闭环，步骤见 [真机验收清单](docs/real-router-acceptance.md)。

## 路线图

v0.1 正式支持 OpenClash 与 Nikki。第二阶段按 HomeProxy、PassWall、设备/IP/端口规则和可选 DNS 分流的顺序推进，不做未经测试的“表面兼容”。

## 许可证

[MIT](LICENSE)。项目不复制 Nikki 或 OpenClash 源码，只通过公开配置和运行接口互操作。
