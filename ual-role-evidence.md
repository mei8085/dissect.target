# UAL 角色标识映射与访问记录证据强度分析

**分析对象**：`dissect.target` 的 Windows UAL 插件 `dissect/target/plugins/os/windows/ual.py`，及其底层解析器 `dissect.database.ese.tools.ual.UAL`（依赖版本 `dissect.database>=1.1,<2`）。
**验证方式**：源码静态分析 + 对真实 ESE 测试库（`Current.mdb`、`SystemIdentity.mdb`，各 1 MiB，经 Git LFS 取回）以独立虚拟环境、`python -I` 实证运行。
**结论先行**：UAL 是**按角色/产品聚合的计数器日志**，插件输出的每一行是“某客户端标识在某天对某角色 GUID 的访问次数”，**不是逐次登录事件**。角色名称完全依赖本机 `SystemIdentity.mdb` 的 `ROLE_IDS` 表事后反查；反查失败时角色 GUID 仍在，但名称为空，且插件不会用任何其他名称填补。

---

## 1. 数据来源与证据分层

UAL（User Access Logging）是 Windows Server 2012 起默认启用的服务，把角色/产品对客户端请求的统计聚合到本机 ESE（Jet Blue）数据库，目录为 `%windir%/System32/LogFiles/Sum/`（插件常量 `LOG_DB_GLOB`，ual.py:161）。一条 `client_access` 输出记录中的字段，证据来源各不相同，必须分层看待：

| 证据类别 | 输出字段 | 原始来源（库/表/列） | 产生机制 |
|---|---|---|---|
| **用户证据** | `authenticated_user`、`tenant_id` | 访问库 `CLIENTS` 表的 `AuthenticatedUserName`、`TenantId` 列 | 角色通过 `UalInstrument(UAL_DATA_BLOB)` 上报的载荷（`UAL_DATA_BLOB` 仅含 RoleGuid/TenantId/Address/UserName） |
| **客户端（设备）证据** | `address`、`client_name` | `CLIENTS` 表的 `Address`、`ClientName` 列 | 同上；`Address` 为原始 IP 字节，由解析器转成字符串（IPv4/IPv6）；`ClientName` 可为空 |
| **角色证据** | `role_guid` | `CLIENTS` 表的 `RoleGuid` 列（**库内原始值**） | 上报载荷中的角色/子产品 GUID，随访问记录一起落盘 |
| | `role_name`、`product_name` | **另一个库** `SystemIdentity.mdb` 的 `ROLE_IDS` 表（`RoleName`、`ProductName` 列） | 插件在内存里用 GUID 做字典反查**附加**得到，并非访问记录自带 |
| **时间证据** | `insert_date`、`last_access_date` | `CLIENTS` 表的 `InsertDate`、`LastAccess`（Windows FILETIME，解析器转 UTC `datetime`） | 该聚合行首次插入时间 / 最后一次访问时间 |
| | `access_date`、`access_count` | `CLIENTS` 表的 `Day1`…`Day366` 列 + `LastAccess` 的年份 | 按“年内第 N 天”存的日计数；解析器以 `LastAccess.year` 为锚换算成日期，零计数被丢弃 |
| **累计计数** | `total_access_count` | `CLIENTS` 表的 `TotalAccesses` | 该聚合行生命周期内的访问总数；实测等于各非零日计数之和（19/19 行一致） |
| **来源文件** | `path` | 具体被扫描的 `.mdb` 路径 | 插件逐文件产出，用于区分多库来源 |

实测原始 `CLIENTS` 表结构（真实库列名）：
`RoleGuid, TenantId, TotalAccesses, InsertDate, LastAccess, Address, AuthenticatedUserName, ClientName, Day1 … Day366`。
注意：**CLIENTS 表没有 FirstSeen/LastSeen 列**（实测取到 `None`）；首末 seen 时间只存在于 `ROLE_ACCESS` 表（列仅 `RoleGuid, FirstSeen, LastSeen`），对应输出 `role_access` 的 `first_seen_date/last_seen_date`。

### 1.1 “访问”不是“登录”

- 微软文档把 `ActivityCount` 定义为“某用户/设备访问某角色或服务的**次数**”，计数单位是角色对 UAL 框架的仪器化上报（`UalInstrument` 调用），而不是操作系统登录会话。
- 实测样本：单个聚合行 `TotalAccesses=2529`、某一天计数 `598/696`，用户名为机器账户 `blackclover\blackclover-dc$` 或 `nt authority\anonymous logon`——这类主体根本不存在交互式“登录”，足以说明计数语义是服务请求而非登录。
- 微软文档另明确：每个唯一客户端的日 `ActivityCount` 上限 **65,535/天**，封顶后当天再多次访问也不增长。因此计数是“至少 N 次”的下限证据，不是精确请求数。
- 聚合行的唯一粒度实测为 `(RoleGuid, AuthenticatedUserName, Address, TenantId)` 组合（19 行 = 19 个不同组合）。同一用户对多个角色的访问分别计数，不能合并成“该用户登录了 N 次”。

---

## 2. 仓库如何把角色标识映射到本地角色定义

### 2.1 映射的唯一来源：SystemIdentity.mdb 的 ROLE_IDS 表

插件初始化时（ual.py:166-207）：

1. `self.role_guid_map = {}` 起步（ual.py:171）；
2. `populate_role_guid_map()` 打开固定路径 `%windir%/System32/LogFiles/Sum/SystemIdentity.mdb`（ual.py:163-164, 188-189）；
3. 读取其中 `ROLE_IDS` 表，构造 `RoleGuid -> {product_name, role_name}` 的**内存字典**（ual.py:203-207）。

全仓库检索确认：**插件不内置任何 GUID→角色名常量表，也不查询注册表、WMI 或其他数据源**。角色名称在整个工具链中只有这一个来源，且该来源与访问记录分属不同数据库文件。

实测 `ROLE_IDS` 共 13 个角色（File Server、DHCP Server、Web Server、Hyper-V 相关等）。值得注意的是该样本里 `ProductName` 列本身存的也是一个 GUID（`0997dbd9-…`），插件原样透传，不做二次解析——因此 `product_name` 字段未必是人类可读名称。

### 2.2 映射如何作用于输出

`client_access()`（ual.py:223-239）与 `role_access()`（ual.py:241-252）对每条记录执行同一模式：

```python
role_guid_data = self.role_guid_map.get(common_values.get("role_guid"), {})
...
role_name=role_guid_data.get("role_name"),      # 未命中 -> None
product_name=role_guid_data.get("product_name") # 未命中 -> None
```

- 命中：`role_guid` 与反查到的 `role_name/product_name` 同时输出；
- 未命中：字典 `.get(guid, {})` 返回空 dict，两个名称字段为 `None`，而**原始 `role_guid` 原样保留**。插件不做猜测、不继承其他记录的名称、不写入占位文本。这与“未识别的角色标识不会被其他角色名称填补”的要求一致。
- 实测验证：样本 `CLIENTS` 中出现 2 个不同 RoleGuid，其中 `ad495fc3-0eaa-413d-ba7d-8b13fa7ec598` **不在** `ROLE_IDS` 中，输出时 `role_name=None`，GUID 仍完整可见；另一个 `10a9226f-…` 正常解析为 `File Server`。

### 2.3 角色定义不可用的三种情形（代码路径均已核对）

1. **SystemIdentity.mdb 不存在**：`identity_db.exists()` 为假，直接 `return`，`role_guid_map` 保持 `{}`（ual.py:190-191）。
2. **SystemIdentity.mdb 损坏/无法解析**：`ual.UAL(fh)` 抛 `dissect.database.exception.Error`，被捕获后仅 `log.warning` 并 `return`（ual.py:194-199），映射表同样保持空。
3. **库存在但缺少 ROLE_IDS 表或该 GUID 无对应行**：解析器对缺失表返回空迭代；字典查找未命中 → 名称为 `None`。

三种情形下，访问库的解析与 `client_access/role_access` 导出**完全不受影响、继续产出全部行**。实测模拟“无 SystemIdentity”：106 条按日输出全部带 `role_name=None`，但两个原始 GUID 均在。

另注：访问库本身打不开时（ual.py:213-217），该文件被跳过并告警，插件继续处理其余 `.mdb`；`SystemIdentity.mdb` 还被 `find_mdb_files()` 显式排除在访问库列表之外（ual.py:185），不会被当作访问库扫描。

---

## 3. 多数据库并存时的证据边界

### 3.1 为什么会有多个 .mdb（微软文档）

- `Current.mdb` 是活动数据库；UAL 每 24 小时复制一份供 WMI 提供程序使用，命名为 `{GUID}.mdb`；
- **每年第一天新建一个年度 `{GUID}.mdb`，旧文件作为归档保留，最长约两年，到期覆写**；
- `SystemIdentity.mdb` 内含 `CHAINED_DATABASES` 表记录归档链接（实测样本有 1 行：`Year=2021, FileName={6AF6D1A1-…}.mdb`）。

### 3.2 插件对多库的实际行为（已实证）

- `find_mdb_files()` 对 Sum 目录做 `*.mdb` glob，**除 SystemIdentity.mdb 外每个文件都独立打开、独立产出**（ual.py:179-186, 209-221），**没有跨库去重、没有按 CHAINED_DATABASES 做归并**。
- 实测把同一访问库复制成两个文件：各产出 106 条，合计 **212 条**，仅靠 `path` 字段区分来源。真实环境中 `Current.mdb` 与其 24 小时副本、相邻年度归档之间存在天然的时间重叠，同一聚合行会在多个文件中重复出现。
- 角色映射是**全局单份**：只从唯一一个 `SystemIdentity.mdb` 加载一次，然后套用到所有访问库。若某归档库来自另一台机器或更早的安装（SystemIdentity 已重建），其 GUID 在当前映射表中可能整体无法反查。
- 每条输出的 `path` 是多库场景下唯一的来源锚点；汇总计数时必须按 `path` 分库统计，不能跨库直接相加后当作真实访问量。

### 3.3 一条访问记录能证明到什么程度

**在角色定义可用（GUID 命中 ROLE_IDS）时，一条 `client_access` 行可以证明：**

- 该 ESE 库内存在一条聚合记录，表明 `authenticated_user`（用户证据）从 `address`/`client_name`（客户端证据）针对 `role_guid` 所标识、并由本机 `ROLE_IDS` 命名为 `role_name` 的角色/服务，在 `access_date` 当天发生了 **`access_count` 次被仪器化的访问**（计数语义，非登录次数，且受 65,535/天封顶约束）；
- 该聚合行首次插入于 `insert_date`、最后活动于 `last_access_date`（时间证据，UTC）；
- 记录来自 `path` 指向的具体数据库文件。

**角色定义不可用（SystemIdentity 缺失/损坏/GUID 未命中）时，可证事实收缩为：**

- 仍可证：某用户标识 + 某客户端地址 + **某个原始角色 GUID** + 某天 + 某计数，以及来源文件与插入/最后访问时间；
- 不可证：该 GUID 对应哪个角色名称或产品。报告中只能写“对 GUID `ad495fc3-…` 的 N 次访问”，**不得**凭常见 GUID 清单、其他记录或外部猜测填入角色名（插件本身也确实不填）；
- 名称缺失**不影响**用户、客户端、时间、计数这四类证据的有效性，也不构成记录伪造的迹象——它只反映本地角色定义表与访问记录不匹配。

**多库并存时，追加以下限制：**

- 单条记录只能证明“该文件内的聚合状态”；同一主体/角色/日期可能在多个库中重复出现，未经 `path` 级去重不能主张唯一访问量；
- 不能把多条按日记录或多个库的计数累加解释成“登录次数”；可主张的是“若干文件、若干日期上的访问计数总量（下限）”；
- 若跨机器/跨重建周期混合了数据库，角色反查命中率会下降，此时以 GUID 为限陈述事实。

### 3.4 其他取证注意点

- **日计数的年份锚定**：`DayN` 靠 `LastAccess.year` 换算日期；若 `LastAccess` 缺失，解析器丢弃全部日计数（`day_counts={}`），该聚合行将不产生任何 `client_access` 按日输出，但行本身仍在库中。
- **时间均为 UTC**：FILETIME 经 `wintimestamp` 转换带 `tzinfo=UTC`；跨时区陈述需自行换算。
- **身份字段可空/可匿名**：实测出现 `AuthenticatedUserName='\\'`、`nt authority\anonymous logon`、机器账户 `…$`，且 `ClientName` 全为 `None`；IP 同时含 IPv4、IPv6 链路本地与 `::1`。用户/客户端证据应按原值引用，不应据此推断真人身份。
- **保留与销毁**：微软文档说明 UAL 数据保留约两年、可被管理员整体删除，且 ESE 软恢复失败时服务会清空 Sum 目录重建——缺失只能证明“当前无数据”，不能证明“历史上无访问”。
- **测试数据现状**：仓库内 `tests/_data/.../ual/*.mdb` 是 Git LFS 指针（132 字节文本，真实文件各 1 MiB），未拉取 LFS 时插件测试无法读到真实 ESE 内容；本分析所用真实库经 LFS 端点取回后独立验证。

---

## 4. 结论

1. **映射机制**：角色 GUID 是访问记录的原生字段；角色名称是插件启动时从本机唯一的 `SystemIdentity.mdb!ROLE_IDS` 加载的内存字典反查结果，仓库内无任何兜底名称表。
2. **不可用时的证据强度**：反查失败只损失“名称”这一层解释，GUID、用户、客户端、时间、计数、来源路径六项事实仍然成立；未识别 GUID 保持未识别，输出 `role_name=None`，不被其他名称填补。
3. **多库时的证据强度**：插件逐文件产出且不去重，一条记录仅在其所属 `.mdb` 范围内成立；跨库重复、年度归档重叠和单份全局映射决定了计数只能分库、按 GUID 审慎汇总，始终是“访问次数（下限）”证据，任何情况下都不能解释为逐次登录。

## 附：验证依据

- 插件源码：`dissect/target/plugins/os/windows/ual.py:161-277`
- 底层解析器：`dissect.database==1.1` 的 `dissect/database/ese/tools/ual.py`（`get_table_records`、`convert_day_num_to_date`、`Day*` 列处理、FILETIME 转换）
- 实测：真实 `Current.mdb`（CLIENTS 19 行 → 展开 106 条按日记录，与 `tests/plugins/os/windows/test_ual.py` 断言一致；ROLE_ACCESS 3 行、DNS 12 行）；真实 `SystemIdentity.mdb`（ROLE_IDS 13 行、SYSTEM_IDENTITY 2 行、CHAINED_DATABASES 1 行）
- 微软文档：Get Started with User Access Logging（字段定义、聚合性质、65,535/天上限）；Manage User Access Logging（Current.mdb/年度 GUID.mdb 滚动、两年保留、恢复时清空目录）；Win32 `UAL_DATA_BLOB` / `UalInstrument`（上报载荷与计数来源）
