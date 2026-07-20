# 贡献指南

感谢关注「软路由分流助手」。

## 开发前

1. 阅读 [README.md](README.md) 与 [AI_HANDOFF.md](AI_HANDOFF.md)。  
2. 未经仓库维护者与设备所有者确认，**不要**对真实路由器做写入类测试。  
3. 勿提交密码、订阅、节点、私钥或未脱敏日志。

## 建议流程

1. Fork 本仓库并创建分支。  
2. `npm ci` → `npm test` → `cargo test --manifest-path src-tauri/Cargo.toml --lib`。  
3. 改动保持小而清晰；涉及写入路径请补充失败回滚相关测试或说明。  
4. 提交 PR，说明动机、风险与测试方式。

## 代码约定

- 前端只通过 `src/api.ts` 调用 Tauri 命令。  
- OpenClash/Nikki 适配逻辑放在 `src-tauri/src/adapters/`。  
- 远程写文件须考虑精简固件（可能无 `base64` 等命令）。  
- 用户可见文案优先中文，并同步 `src/i18n.ts` 英文键。

## 许可证

贡献代码默认以 [MIT](LICENSE) 授权。
