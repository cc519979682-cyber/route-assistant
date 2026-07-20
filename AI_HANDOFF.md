# 软路由分流助手：AI / 贡献者交接文档

> 更新时间：2026-07-20  
> 当前工作版本：v0.4.0  
> 包名：`route-assistant`（Windows 桌面，Tauri 2）

## 1. 首要原则

1. 不要用 `git reset --hard` 覆盖未确认的本地工作。  
2. 未经用户/维护者确认，不要对真实路由器执行写入、重启、改 DNS/DHCP/防火墙。  
3. 禁止在代码、文档、Issue、日志样本中写入密码、私钥、订阅 URL、API 密钥、节点信息。  
4. 前端只能调用类型化 Tauri 命令，不能直接 SSH 或读写路由文件。  
5. 每次写入须：预览 → 备份 → 候选检查 → 原子替换 → 验证 → 失败回滚（含看门狗）。

## 2. 产品边界

- 管理 OpenClash / Nikki 的**助手自定义域名规则**（直连 / 拒绝 / 策略组）。  
- 不读取、不展开订阅规则内部条目。  
- 原有自定义规则只读；助手规则可编辑删除。  
- HomeProxy、PassWall/PassWall2：仅检测，不管理。  
- 本地运行，无云端、无遥测。

## 3. 技术栈

- 前端：React 19 + TypeScript + Vite  
- 桌面：Tauri 2  
- 后端：Rust（russh、rusqlite、keyring）  
- 构建：`npm run tauri build` 产出 NSIS/MSI  

## 4. 真机踩坑（v0.4 已修）

### 4.1 部分 OpenWrt 无 `base64`

远程 `write_file` 改为 **hex + Ruby 解码**并校验字节数；应用链使用 `set -e`。

### 4.2 Mihomo API 类型名

YAML：`DOMAIN-SUFFIX` / `DOMAIN`；API：`DomainSuffix` / `Domain`。  
校验须归一化；OpenClash 应用后用**运行配置文件 + API**双重确认。

### 4.3 「仅此域名 www.x」≠ 整站

默认影响范围改为整站后缀；UI/预览提示精确匹配局限。

### 4.4 绕过大陆 IP + 国内域 Fake-IP 过滤

`china_ip_route` + 国内域真实 IP 时，DOMAIN 拒绝可能 hitCount=0。  
REJECT 同步写 OpenClash 自定义 hosts（`0.0.0.0`）并开 `custom_host`。

### 4.5 DNS 页白屏

后端缺 `chain` 字段时前端崩溃 → 归一化 + ErrorBoundary。

## 5. 推荐自测

- **软件可用性**：`example.com` 整站拒绝 → 列表出现 → 删除成功。  
- **浏览器拦截**：同上，强刷后 example.com 应失败，再删除恢复。  
- **不要**用 `*.example` 测浏览器（保留域 NXDOMAIN）。  
- **不要**只用百度判断拒绝是否生效（易受绕过大陆 IP 影响）。

## 6. 本地开发

```powershell
npm ci
npm run build
npm test
cargo test --manifest-path src-tauri/Cargo.toml --lib
npm run tauri build
```

在 UNC/网络盘上开发时，把 `CARGO_TARGET_DIR` 指到本机磁盘。

## 7. 安全与发行

- 凭据进 Windows 凭据库；诊断默认脱敏。  
- 公开发布安装包建议代码签名；个人发售可说明 SmartScreen「仍要运行」。  
- 二进制安装包默认不进 Git，用 GitHub Releases 发布。

## 8. 许可证

MIT。不复制 OpenClash/Nikki 源码，仅通过公开配置与运行接口互操作。
