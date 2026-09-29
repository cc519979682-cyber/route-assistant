# 软路由分流助手

面向新手的 **Windows** 软路由分流助手。通过 SSH 连接 OpenWrt，为 OpenClash / Nikki 的自定义域名规则提供可视化编辑、变更预览、备份及失败回滚。

**当前版本：v0.4.0** · 许可证 [MIT](LICENSE)

> 当前 v0.4.0 的 OpenClash / Nikki 真机闭环验收仍在进行中，建议先在测试环境使用。

> 本地运行，不上云、不收集订阅/节点/密码。不是机场客户端，不提供节点。

## 功能概览

- Windows 10/11 x64（Tauri 2 + React + TypeScript + Rust）
- SSH 密码或私钥；首次展示主机指纹，指纹变化时拒绝连接
- 识别 OpenClash、Nikki、HomeProxy、PassWall/PassWall2 及运行状态
- OpenClash / Nikki：**助手自定义域名规则**（精确 / 后缀、直连 / 拒绝 / 策略组）
- 原有自定义规则只读；可复制为助手规则
- 写入前中文预览、备份、语法检查、验证；失败自动回滚 + 路由端看门狗
- 拒绝规则同步 OpenClash **hosts 屏蔽**（缓解「绕过大陆 IP」下 DOMAIN 拒绝对国内站无效）
- OpenClash **基础 DNS 防污染**检测；条件允许时写助手标记块（官方 overwrite 脚本）
- DNS 页展示推荐链路 / 当前配置链路 / 实际解析观测（Windows + 路由只读）
- 密码进 Windows 凭据库；日志与诊断默认脱敏

## 截图 / 发行包

安装包请见 [Releases](../../releases)（若已发布）。也可自行构建。

## 本地开发

需要：Node.js 20+、Rust stable、Visual Studio 2022 C++ 桌面工具、WebView2。

```powershell
npm ci
npm run build
npm test
cargo test --manifest-path src-tauri/Cargo.toml --lib
npm run tauri build
```

在网络盘/UNC 路径开发时，建议：

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\route-assistant-target"
```

## 文档

| 文档 | 说明 |
|---|---|
| [AI_HANDOFF.md](AI_HANDOFF.md) | 架构边界、真机踩坑、自测方法 |
| [CHANGELOG.md](CHANGELOG.md) | 版本记录 |
| [docs/security-model.md](docs/security-model.md) | 安全模型 |
| [docs/compatibility.md](docs/compatibility.md) | 兼容性 |
| [docs/real-router-acceptance.md](docs/real-router-acceptance.md) | 真机验收 |
| [SECURITY.md](SECURITY.md) | 漏洞报告 |

## 使用注意（摘要）

1. 拦截整站请选「整个域名及子域名」，不要只拦 `www`。  
2. 自测拒绝规则优先用 `example.com`，不要用本身不存在的 `*.example`。  
3. 国内站 + OpenClash「绕过大陆 IP」时，仅靠 DOMAIN 规则可能测不准；本版拒绝会写 hosts。  
4. 多插件同时接管透明代理/DNS 时，流量归属可能不清晰，请自行确认。

## 安全

发现凭据泄露、任意命令执行、越权改非助手规则、回滚失效等问题，请走 [SECURITY.md](SECURITY.md) 私下报告，附**已脱敏**复现步骤。

## 路线图

- 巩固 OpenClash 规则与 DNS 真机场景  
- Nikki / 其他插件更深适配  
- 设备、IP、端口类规则（不做未经验证的表面兼容）

## 许可证

[MIT](LICENSE)。项目不复制 OpenClash 或 Nikki 源码，只通过公开配置与运行接口互操作。
