# 参与贡献

提交前请确保：

1. `npm run build` 和 `npm test` 通过。
2. `cargo test --manifest-path src-tauri/Cargo.toml --all-targets` 通过。
3. 新增路由器写操作必须有备份、看门狗、验证和回滚测试。
4. 不记录密码、私钥内容、订阅 URL 或节点信息。
5. 新插件必须作为独立适配器完成真机闭环后才能标记为支持。

涉及真实路由器的测试必须由设备所有者明确授权，并限定到指定设备和插件。
