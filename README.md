# 多线路流量限额控制器

用于 H3C Comware 7 多台防火墙的多线路流量管理。程序通过 SNMP v2c/v3 周期读取每个接口的 64 位入/出字节计数器，按线路独立累计计费周期流量；达到额度时通过 SSH 进入对应接口执行 `shutdown`。

## 功能

- 每条线路独立配置接口、SNMP `ifIndex`、流量额度和每月计费起始日（1–31 日）
- 支持管理多台防火墙，各设备独立保存 SSH 和 SNMP 参数
- 支持 SNMP v2c 和 SNMP v3，可按设备选择；v3 支持 noAuthNoPriv、authNoPriv、authPriv
- 自动采集间隔可选择 30 秒至 1 小时，也支持自定义值
- 显示每个接口最近采集区间的接收、发送及总实时速率（Mbps）
- 同步 SNMP `ifAdminStatus`/`ifOperStatus`，显示运行中、管理关闭或链路断开
- 同时累计接口入方向和出方向流量
- 使用运营商查询值手动校准本周期累计流量，后续继续增量累计
- 达到 100% 自动 SSH 关停；支持手动关停和 `undo shutdown` 恢复
- 模拟执行模式、完整操作/失败日志、重启后保留数据
- Docker Compose 一键部署

## 部署

```bash
cp .env.example .env
# 务必修改 .env 中的 ADMIN_PASSWORD
docker compose up -d --build
```

`.env` 中的 `TZ` 决定计费日切换时间和日志时间，请设置为业务所在地时区（例如 `Asia/Shanghai`）。
部署后也可以在 Web“系统设置”中修改 IANA 时区，页面会显示该时区的当前时间。内部时间统一按 UTC 保存，日志展示和计费周期再转换到所选时区。

访问 `http://服务器IP:8000`，浏览器会要求输入 `.env` 中的管理用户名和密码。首次进入后：

1. 在“防火墙设备”检查自动迁移生成的“默认防火墙”，或添加更多设备，暂时保持模拟模式。
2. 在防火墙开启 SNMP v2c 或 v3，并只允许该 Ubuntu/Docker 主机访问 UDP 161。推荐使用 v3 `authPriv`。
3. 用 H3C 命令 `display snmp-agent mib-node ifName`、`display interface` 或 SNMP walk 确认子接口对应的 `ifIndex`。
4. 添加线路并选择所属防火墙。接口示例：`GigabitEthernet 1/0/1.100`。不同防火墙可以使用相同接口名称。
5. 点两次“采集”（第一次只建立计数基线），核对增长是否合理。
6. 测试人工关停/恢复；确认配置后再关闭模拟模式。

> Docker 网络必须能访问防火墙的 UDP 161 和 TCP 22。程序不需要串接在防火墙前后，它只需要管理网络可达。

### SNMP v3 设置示例

如果 H3C 配置使用 SHA 认证和 AES-128 加密，在“防火墙设备”选择：

- SNMP 版本：`v3`
- 安全级别：`authPriv`
- 认证算法：`SHA`
- 加密算法：`AES-128`
- 用户名、认证密码、加密密码必须与防火墙配置完全一致
- Context 通常留空

可先在 Ubuntu 上验证：

```bash
snmpwalk -v3 -l authPriv -u '用户名' -a SHA -A '认证密码' \
  -x AES -X '加密密码' 防火墙IP 1.3.6.1.2.1.31.1.1.1.1
```

旧版本创建的数据库会在升级启动时自动增加 v3 配置字段，不需要删除数据库。

## 从单防火墙版本升级

升级启动时会自动把原 SSH/SNMP 配置转换为“默认防火墙”，将原有线路绑定到该设备，并保留采集、校准和日志数据。数据库还会增加实时速率字段，并把接口唯一规则调整为“同一防火墙内唯一”。升级前仍建议先按下文备份数据库。

## 计费和校准规则

- 每月起始日为 1–31；若当月没有该日期（例如 2 月 31 日），自动使用当月最后一天。
- SNMP 是累计计数器，程序每次读取差值。设备重启或计数器复位时不会把负差值计入流量。
- 第一次采集只建立基线，因此部署前已经产生的流量应使用“校准流量”录入运营商当前值。
- 实时速率是两次 SNMP 计数器读数之间的平均速率；第一次采集为 0，第二次起显示有效值。
- 接口状态随每次自动或手动采集更新；在防火墙上手动执行 `shutdown` 后，下一次采集会显示“管理关闭”。
- 每次校准将运营商值设为当期新基准，校准之后产生的 SNMP 增量继续累加，不会重复计算。
- 默认 GB 按运营商常用十进制计算：`1 GB = 1,000,000,000 bytes`。
- 当前实现按“入 + 出”统计。如果运营商只计算一个方向，需要按实际计费规则调整。

## H3C 实际执行命令

```text
system-view
interface GigabitEthernet 1/0/X.X
shutdown
return
```

恢复时第三条命令为 `undo shutdown`。建议创建最小权限的专用 SSH 管理账号，并先在测试子接口验证命令权限。

## 备份和升级

所有配置、采集和日志位于 Docker 命名卷 `traffic-controller-data` 的 `/data/traffic.db`。备份前可执行：

```bash
docker compose stop
docker cp traffic-controller:/data/traffic.db ./traffic.db.bak
docker compose start
```

恢复备份时先停止容器，再执行：

```bash
docker compose stop
docker cp ./traffic.db.bak traffic-controller:/data/traffic.db
docker compose start
```

如果使用旧版本的 `./data:/data` 目录挂载并看到 `unable to open database file`，请在项目目录执行：

```bash
mkdir -p data
chown -R 10001:10001 data
docker compose restart
```

