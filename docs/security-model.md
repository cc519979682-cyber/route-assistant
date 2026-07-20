# 安全模型

## 凭据与连接

- 密码、私钥路径和私钥口令使用 Windows 凭据库保存；SQLite 只保存凭据引用。
- 首次连接展示 SSH 主机指纹。已保存设备的指纹变化会阻断连接。
- Mihomo API 请求通过现有 SSH 加密通道在路由器本机执行，不开放 9090 等控制端口。

## 配置所有权

- OpenClash 仅管理 `/etc/openclash/custom/openclash_custom_rules.list` 中带专属起止标记的块。
- OpenClash DNS 防护仅管理 `/etc/openclash/custom/openclash_custom_overwrite.sh` 中带 `ROUTE-ASSISTANT-DNS` 起止标记的块；重复或破损标记会拒绝写入。
- Nikki 仅管理名称以 `route_assistant_` 开头且包含助手编号的 UCI rule 段。
- 其他规则只读；不编辑订阅、节点、DHCP 或防火墙配置。

## 多插件边界

- OpenClash 与 Nikki 是 v0.4 唯一可管理的插件；HomeProxy、PassWall/PassWall2 仅检测安装和运行状态，不读取其配置。
- OpenClash 与 Nikki 同时运行时必须由用户明确选择当前管理对象，每次只调用所选插件的适配器。
- 检测到运行中的 HomeProxy、PassWall 或 PassWall2 时持续警告，但允许用户修改明确选中的 OpenClash/Nikki；每次仍只调用当前管理对象的适配器。
- 每次写入前重新检测全部插件；插件状态与预览时不一致时，原预览立即作废。
- 软件不启动、停止、重载非当前管理对象，也不改变任何插件的开机启动状态。

## DNS 防污染边界

- 只读取 OpenClash 自己的运行配置，不读取同机 Nikki、HomeProxy 或 PassWall 的 Mihomo 配置。
- 只将 OpenClash DNS 上游改为预设加密 DoH，并启用 `respect-rules`；保留现有 Fake-IP/Redir-Host 模式。
- 只有确认 dnsmasq 或 OpenClash 现有重定向已让局域网 DNS 进入 OpenClash 时才允许自动应用；无法确认时只诊断。
- 不修改 dnsmasq、DHCP、防火墙、SmartDNS、AdGuard Home、订阅或节点。多个代理插件同时接管 DNS/透明代理时，软件只能提示风险，不能承诺最终链路。
- 当前电脑的 DNS 链路从 Windows 网卡 API 只读获取，包含活动网卡、默认网关和 IPv4/IPv6 DNS；VPN、Tailscale、外部 DNS 等只标记为“可能绕过”。软件不会读取浏览器历史或声称能够确认浏览器内置 DoH。
- 路由器链路只返回白名单化的服务状态、监听端口、环回地址连接和协议数量，不返回完整配置行、上游 URL、认证字段、订阅或节点。
- 百度、Google 等解析观测只证明当次查询成功或失败，不能单独证明全程使用加密 DNS。未启用抓包，因此 UI 只能使用“已确认、根据配置推断、未知、可能绕过”。
- 如果 OpenClash 上游指向路由器环回地址上的 AdGuard Home、SmartDNS 或其他本机服务，环回跳转不计为公网明文泄漏；助手会将其视为复杂组合链路并禁止基础一键修复覆盖。

## 变更事务

每次写入前在 `/etc/route-assistant/backups` 创建权限为 0700 的备份，最多保留最近 10 份。候选文件先写入临时路径并做语法检查，再原子替换。写入前启动 120 秒路由端看门狗；只有服务恢复、核心 API 可访问且规则状态正确后才写入提交标记。客户端崩溃或 SSH 中断时，看门狗仍会恢复原配置并重启原服务。

## 数据最小化

应用无云端服务、无大模型、无遥测。操作历史只保存设备档案编号、插件、动作摘要、备份编号和结果。日志事件经过脱敏，不记录主机地址、密码、订阅 URL 或节点内容。诊断包导出前再次执行敏感字段和 URL 脱敏。
