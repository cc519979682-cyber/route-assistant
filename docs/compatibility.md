# 兼容性表

| 平台/插件 | 状态 | v0.4 范围 |
|---|---|---|
| Windows 10/11 x64 | 自动构建待发布验证 | 桌面客户端；只读检测当前电脑的活动网卡、IPv4/IPv6 DNS、默认网关及常见 VPN/隧道提示 |
| OpenWrt | 已实现识别 | SSH 管理员连接，不安装路由端常驻助手 |
| OpenClash | 适配器与离线测试已实现；待真机闭环 | 读取专用自定义规则文件；只写助手标记的高优先级域名规则块；基础 DNS 防污染检测、预览、备份、应用、验证与回滚；只读生成带置信度的当前 DNS 配置链路 |
| Nikki | 适配器与离线测试已实现；待真机闭环 | 读取结构化追加 `rule` 段；只写 `route_assistant_` UCI rule 段；混入文件仅检测 |
| HomeProxy | 仅检测 | 展示安装和运行状态；同时运行时警告但不阻止当前管理对象写入，不读取配置 |
| PassWall/PassWall2 | 仅检测 | 展示安装和运行状态；同时运行时警告但不阻止当前管理对象写入，不读取配置 |

未知插件版本、核心 API 不可用或能力不完整时应进入只读诊断，不应写入配置。公开测试版发布前，OpenClash 与 Nikki 必须各完成一次真实设备的添加、重载、验证、删除、订阅更新和回滚闭环。

订阅规则、规则集内部条目、完整运行规则、订阅 URL、API 密钥和节点配置不属于自定义规则读取接口。v0.4 只有 `DOMAIN` 与 `DOMAIN-SUFFIX` 可以复制为助手规则；其他类型只读展示。DNS 自动修复只支持 OpenClash，且要求现有局域网 DNS 已进入 OpenClash；Nikki、HomeProxy、PassWall/PassWall2 仍只显示原有 DNS 诊断。

DNS 当前链路可识别 dnsmasq、OpenClash DNS、AdGuard Home、SmartDNS 和 mosdns 的脱敏配置关系。其他组件会显示为“本机 DNS 服务”或“未知”。链路只描述安装本软件的当前 Windows 电脑和软路由配置，不能读取其他电脑、手机或电视的本地 DNS、浏览器 DoH 或 VPN 设置。
