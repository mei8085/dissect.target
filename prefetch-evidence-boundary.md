# Windows Prefetch 证据边界分析报告

## 0. 分析范围与方法

本报告基于仓库内以下源码与测试材料，对 Windows Prefetch（`.pf`）解析能力与取证证据边界进行分析：

- 解析插件：`dissect/target/plugins/os/windows/prefetch.py`
- 单元测试：`tests/plugins/os/windows/test_prefetch.py`
- 测试样本：`tests/_data/plugins/os/windows/prefetch/MPCMDRUN.EXE-962E6200.pf`

环境约束（影响验证程度，本身也属于证据缺口）：

- 当前为浅克隆（`git log` 仅 1 个提交），无法追溯该插件的历史变更。
- 测试样本是 Git LFS 指针文件（`oid sha256:7f8a…`，真实大小 8156 字节），环境中未安装 `git-lfs` 且离线，**无法对真实字节做独立复核**；样本相关结论仅能依据测试代码中的断言反推。
- 离线环境无法外部检索格式规范，Prefetch 格式的背景知识以行业通行的 SCCA 格式知识给出，凡源码本身不能证明之处均显式标注。

核心问题——**运行计数（`run_count`）与保留的时间槽位（`last_run_time` / `last_run_remains`）不是一一对应关系**——在源码中得到明确印证，下文逐项展开。

---

## 1. 各格式版本的解析结构（源码可证）

版本分发表位于 `prefetch.py:174-179`：

| 版本号 | 文件信息结构 | 指标项结构 | 时间字段（源码定义） | 时间槽位上限 |
|---|---|---|---|---|
| 17 | `FILE_INFORMATION_17` | `FILE_METRICS_ARRAY_ENTRY_17` | `uint32 last_run_time`，**无** `last_run_remains` | 1（仅最后一次） |
| 23 | `FILE_INFORMATION_23` | `FILE_METRICS_ARRAY_ENTRY_23` | `uint64 last_run_time` + `uint64 last_run_remains[2]` | 3 |
| 30 | `FILE_INFORMATION_26` | `FILE_METRICS_ARRAY_ENTRY_23` | `uint64 last_run_time` + `uint64 last_run_remains[7]` | 8 |
| 31 | `FILE_INFORMATION_26` | `FILE_METRICS_ARRAY_ENTRY_23` | 同上 | 8 |

结构定义见 `prefetch.py:63-116`。未在表中的版本号在 `identify()` 中直接抛 `NotImplementedError`（`prefetch.py:198-205`），即**未知版本不产生任何记录**。

压缩格式处理（`prefetch.py:184-186`）：文件头前 4 字节签名为 `MAM\x04` 时，先用 `dissect.util.lzxpress_huffman.decompress` 整体解压缩，再按普通流程解析。

时间提取逻辑（`prefetch.py:237-250`）：

- `latest_timestamp` 始终返回 `wintimestamp(self.fn.last_run_time)`，**不做零值过滤**。
- `previous_timestamps` 对 `last_run_remains` 逐项转换，且**显式过滤零值**（`if timestamp != 0`）；版本 17 因无该属性，经 `AttributeError` 分支返回空列表。

### 1.1 源码可证结论

1. 解析器对每个 `.pf` 只认 `run_count`（一个累计计数器）和固定数量的时间槽位；二者在结构体中是**独立字段**，源码中没有任何把第 N 次运行映射到第 N 个槽位的逻辑。
2. 版本 17 只有 1 个时间字段；版本 23 最多 3 个时间点；版本 30/31 最多 8 个时间点。槽位之外的历史运行在文件中没有时间戳载体。
3. 空槽位（值为 0）会被 `previous_timestamps` 丢弃，因此实际输出的时间点数可能小于槽位上限。
4. 所有时间戳统一经 `wintimestamp`（按 64 位 Windows FILETIME，100ns 计数）解释。

### 1.2 证据缺口 / 源码外风险

- **版本 17 的 `last_run_time` 在结构体中是 `uint32`（`prefetch.py:93`），却仍被送入 64 位 FILETIME 解释器 `wintimestamp`。** 按通行的 SCCA 格式知识，Windows XP/2003（版本 17）使用的是 32 位 DOS/局部时间，而非 FILETIME。源码中没有任何针对版本 17 的转换分支，因此**版本 17 文件由本插件产出的 `ts` 很可能是错误时间**。该风险无法用仓库内样本验证（唯一样本是版本 30/31 类的 LFS 指针），属于真实缺陷与证据缺口的叠加，使用时不得把版本 17 的输出时间当作已证实时刻。
- 版本号与 Windows 发行版（17=XP/2003、23=Vista/7、26/30=8 系、31=10/11）的对应关系来自格式背景知识，**源码本身不包含该映射**。

---

## 2. 两种取证视图的产出方式（源码可证）

插件入口 `prefetch()` 对目录下每个 `.pf` 文件构造一个 `Prefetch` 对象，然后按 `compact` 参数分两种视图（`prefetch.py:303-340`）。

### 2.1 展开视图（默认，`PrefetchRecord`，`prefetch.py:328-340`）

```python
run_dates = [scca.latest_timestamp, *scca.previous_timestamps]
for linked_file in scca.metrics:
    for date in run_dates:
        yield PrefetchRecord(ts=date, ..., linkedfile=..., runcount=scca.fn.run_count, ...)
```

- 记录数 = **被加载文件数（metrics 条目数）× 非空时间槽位数**，是两层笛卡尔积。
- 每条记录都携带相同的 `runcount` 和相同的一组 `ts`，只是 `linkedfile` 不同。
- `linkedfile` 来自 metrics 数组（`parse_metrics`，`prefetch.py:216-228`），即该程序运行期间被追踪加载的文件路径字符串。

### 2.2 紧凑视图（`--compact`，`CompactPrefetchRecord`，`prefetch.py:317-327`）

- 每个 `.pf` 仅产出 **1 条**记录。
- `ts` = 最后一次运行时间；`previousruns` = 非零历史时间戳数组（保持文件中的原始槽位顺序，**代码不排序**）；`linkedfiles` = 完整加载文件列表；`runcount` 为同一计数器值。
- 时间与文件列表分别放在数组字段中，**不做**“某文件在某时刻被加载”的配对。

### 2.3 测试中的具体数字（来自测试断言，非真实字节复核）

`test_prefetch_compact` / `test_prefetch`（`test_prefetch.py:127-163`）对同一样本给出：

- 41 个 linked files，8 个非空时间点（1 个 `ts` + 7 个 `previousruns`）。
- 展开视图产出 41 × 8 = **328 条**记录，每个时间戳各重复 41 次。
- `previousruns` 中存在同秒内的两个不同时间点（如 `07:52:38.569597` 与 `07:52:38.319941`），说明槽位记录的是**多次独立运行**，时间可以非常接近。
- `test_prefetch_compact` 中 `# assert mpcrun.runcount == 21 : Todo : fix bug`（`test_prefetch.py:134`）——**测试刻意不断言 run count**。结合 LFS 指针标注的真实样本，预期 `run_count` 为 21，但仅保留了 8 个时间戳。这正是“计数与槽位不对应”的活样本：**至少 21 − 8 = 13 次运行没有任何时间戳留存**。由于该断言被注释且样本不可读，21 这个数值只能作为测试意图引用，不能作为已验证事实。

---

## 3. 证据边界：哪些时刻可由记录支持，哪些只是计数提示

### 3.1 可由记录支持的结论（源码 + 数据结构层面成立）

1. **可证实的执行时刻，仅限输出记录中实际出现的非零时间戳**，即：
   - 紧凑视图：`ts` 与 `previousruns` 数组中的每个非零元素；
   - 展开视图：去重后的 `ts` 集合（同一时刻因笛卡尔积被复制成每条 linked file 一行）。
   - 对版本 30/31 至多 8 个、版本 23 至多 3 个、版本 17 至多 1 个时刻能以此方式证实（且版本 17 的时间解释本身存疑，见 1.2）。
2. **`run_count` 可证实“该程序自 Prefetch 文件建立以来被计入的运行总次数”这一事实本身**——它是文件中的一个累计字段，插件原样读出。
3. 可证实该程序最近一次运行（`last_run_time`）与若干次较早运行（非零 `last_run_remains`）的时间，以及运行期间被加载的文件清单（metrics 文件名）。
4. 可证实槽位中存在被清零的位置（输出时间点少于结构上限），但清零原因（槽位未使用 / 被覆盖）无法从输出区分。

### 3.2 只能由计数提示、不能坐实到具体时刻的活动

1. **`run_count` 超过非空时间槽位数量时，差额次运行只存在“发生过 N 次”的计数证据，没有任何可定位的日期/时刻。** 以测试样本的预期值为例：21 次计数对 8 个时间戳，至少 13 次更早活动无法确定发生时间。**这些未覆盖的日期绝不能写成已证实的执行时刻**，只能表述为“计数表明在最早留存时间戳之前还存在至少 13 次运行，时刻未知”。
2. 时间槽位是循环复用的固定数组（通行格式知识：新运行移入 `last_run_time`，旧值向后挪动，最旧值被挤出）。被挤出槽位的运行在文件中**不存在任何残留**，解析器无法、也未尝试重建它们的时间。源码中没有任何槽位轮转/重建代码可证此机制，机制本身属源码外知识，但“输出只反映槽位现状”是源码可证的。
3. `run_count` 不区分运行主体与路径，无法凭计数判断各次运行由谁触发、从哪个目录启动；这些信息本插件未解析。

### 3.3 被加载文件（metrics / linkedfile）不能自动算作独立执行

这是本插件最容易被误读的地方，源码给出明确边界：

1. **metrics 条目是“某次/若干次运行期间被加载的文件”，不是“被执行的程序”。** `parse_metrics` 读取的是文件名字符串（DLL、依赖文件、资源等均会出现），其中没有任何字段把某个 linked file 标记为一次独立执行。
2. 展开视图中每个 linked file 与每个时间戳做笛卡尔积（`prefetch.py:330-340`），因此 328 条记录**不代表 328 次执行**；真实样本只有 8 个带时间戳的运行点、计数为 21。把记录条数或 linked file 数量当成执行次数，属于取证误读。
3. 同一条 linked file 出现在多个时间戳下，只表示该文件在这些运行所覆盖的追踪窗口内被加载过；**源码不提供“文件 X 具体在哪个时刻被加载”的关联**。紧凑视图把两者拆成并列数组，反而更不易产生这种错误配对。
4. 唯一可归为“被执行程序”的标识是头部 `name` 字段（`prefetch.py:314`，解码为 `filename`）与 `.pf` 文件名本身；linked files 是从属证据。

### 3.4 输出层面的额外解读风险

- **零值 `last_run_time` 不过滤**：`latest_timestamp` 没有类似 `previous_timestamps` 的零值检查（对比 `prefetch.py:240` 与 `:247`）。异常/空壳 `.pf` 可能产出 Windows 纪元（1601-01-01）时间并被下游当作真实执行时刻。
- **解析失败静默跳过**：任何异常都只记 warning 后 `continue`（`prefetch.py:307-312`）。某 `.pf` 无记录不等于该程序未运行，可能只是解析失败；无记录本身不能作为“未执行”的证据。
- 紧凑视图的 `previousruns` 不排序，时间先后需由消费方自行处理；测试中是读回后 `sorted(reverse=True)` 才得到降序（`test_prefetch.py:135`）。
- 卷信息、trace chain、metrics 中的 `start_time`/`duration`/NTFS 引用等结构虽有定义（`prefetch.py:118-170`），但插件**未导出**这些字段，无法用于佐证执行时刻。

---

## 4. 结论清单

### 源码可证结论

1. 四个受支持版本（17/23/30/31）的时间槽位上限分别为 1/3/8/8，`run_count` 是与槽位独立的累计计数器，二者不存在一一对应（`prefetch.py:63-116, 174-179`）。
2. 可证实的执行时刻 = 输出中非零的 `last_run_time` 与 `last_run_remains`；零值槽位被过滤（`prefetch.py:243-250`）。
3. 展开视图按“linked files × 时间点”做笛卡尔积，记录条数被成倍放大；紧凑视图每文件一条，时间与文件列表分离（`prefetch.py:317-340`）。
4. linked files 来自 metrics 文件名字符串，插件未赋予其任何“独立执行”语义。
5. 压缩（MAM）文件先解压再解析；未知版本抛 `NotImplementedError`；解析失败仅告警并跳过。
6. 测试样本（按测试断言）有 41 个加载文件、8 个时间点、展开为 328 条记录；`run_count` 断言被注释为待修 bug，测试不验证计数（`test_prefetch.py:134`）。

### 证据缺口（不能越界下结论之处）

1. **计数超出槽位的差额运行（测试预期样本中约 13 次）没有时间戳，禁止写成具体执行日期**；只能陈述“存在时刻未知的更早活动”。
2. 被挤出/覆盖的槽位无任何字节残留，解析器不重建历史。
3. 版本 17 的 32 位时间字段被按 64 位 FILETIME 解释，其输出时间的正确性在本仓库内无样本可证，引用时应标注存疑。
4. LFS 样本不可读，21 次计数、8 个时间戳等具体数值来自测试断言而非独立字节复核；版本与 Windows 发行版对应、槽位轮转机制属源码外的格式背景知识。
5. 无记录的 `.pf`（解析失败/未知版本）不能证明程序未运行；metrics 中的计时与 NTFS 引用字段未导出，无法用于时间线补强。
