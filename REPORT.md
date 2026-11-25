# 设计与实测报告

> 平台：Windows 11，Python 3.12.1（原生解释器），仅标准库。
> 全部 44 项测试通过；下表的数字来自 `artifacts/benchmark.json` 的真实运行。

## 1. 问题与不变量

两条隔离链路的边缘节点在维护窗切换信任代理，消息只在本地合成队列流转。
核心不变量：

1. **绑定**：每条可见消息唯一确定 `(link, generation, seq, segment, digest)`，
   `digest` 是原始载荷的 SHA-256。
2. **双独立签收**：恰好两名代理签收；控制源必须不同，"同一控制源只算一次"。
3. **同代租约**：两名代理在发布时都必须绑定到该 `(link, generation)` 且未撤销。
4. **非追溯撤销**：撤销只影响之后的发布；已发布消息与发布水位不变。
5. **可独立证明的旧水位**：撤销一名代理后，另一名仍能独立证明旧消息，
   可证明水位保持不变；只有两名都撤销才降为 0。
6. **提交即持久**：回复仅在 append 落盘（fsync）后产生；回复丢失可由磁盘重建。

## 2. 数据模型

- **消息**：`RequestKey`（幂等键）、`msg_id`、链路/代、`seq`、`segment`、
  `payload`、`digest`、两名代理的 `(agent, sig)`。
- **签收**：`sig = HMAC(agent_key, purpose||v||msg_id||link||generation||seq||segment||digest)`。
  这是**离线测试用的确定性 HMAC 模型**，不是生产签名方案；主种子存放在
  测试库的 `relay.meta.json` 中，供核验器复核历史签收。
- **租约生命周期**：`open_lease → (register_agent)* → activate_lease`，
  迁移 `migrate` 将源置 `inactive`、目标置 `active`；注册在 `active` 后关闭。
- **回执**：`submit_receipt` 绑定消息的链路/代/摘要。若消息所属租约已 `inactive`，
  该回执标记为 `late=true`（迟到），但仍被持久记录且不隐藏消息。

## 3. 持久化与恢复

`journal.py` 实现校验链式追加日志：每行
`{"seq","prev","event","outcome","digest"}`，`digest` 覆盖 `seq/prev/event/outcome`，
下一行的 `prev` 等于本行 `digest`。追加协议为 **写整行 → flush → fsync → 返回结果**。

- **幂等键**：每个事件把运行时裁决（含拒绝理由）一并写盘，重启时逐条重放，
  任何偏差即触发 `JournalIntegrityError`。
- **撕裂尾部**：读取时在首个不完整/校验失败的行停止，重启时截断该尾部；
  已提交前缀与链头不变（见 `test_torn_tail_is_truncated_and_head_preserved`）。
- **回复丢失**：`RelayRuntime.submit_with_lost_reply` 在持久提交后抛出
  `ReplyLost`，调用方未收到回复；重启后的独立核验能从磁盘重建出该消息，
  重试因幂等键被识别为 `idempotent_replay`，不会重复发布。

## 4. 独立核验器（重启后复核）

`trustrelay/verify.py` 刻意**不导入** `RelayState`：

- 只读 `relay.meta.json` 与 `relay.journal` 字节；
- 自行重算校验链；
- 用一套独立重写的规则集对每条记录重新裁决；
- 输出：可见消息、各租约发布/可证明水位、全部拒绝理由、逐字段分歧列表；
- `compare_with_runtime` 再比对"磁盘核验视图"与运行时视图的可见摘要与分区指纹。

一致时退出码为 0；任何链损坏或分歧退出码非零。CLI 真实输出见
`artifacts/audit_demo.txt`。

## 5. 两真实线程与可控屏障

`tests/test_threads.py` 用真实 `threading.Thread` 与 `threading.Barrier` 控制交错：

| 场景 | 屏障编排 | 断言 |
| --- | --- | --- |
| 回执先于迁移 | 两线程同时就绪；回执先完成，迁移后执行 | 回执 `late=false`；迁移后再来的回执 `late=true` |
| 迁移先于回执 | 迁移先完成，回执后执行 | 回执 `late=true`，仍持久记录 |
| 承诺后回复丢失 | 并发线程提交，提交路径抛 `ReplyLost` | 磁盘可见该消息；重试为 `idempotent_replay` |
| 同一序号并发发布 | 两线程同一屏障竞争 `seq=1` | 恰好一条 `accepted`，另一条 `sequence_regression` |
| 乱序发布重试 | 先 `seq=2` 后 `seq=1` | 前者 `sequence_gap`，补洞后原事件重试 `accepted` |
| 重启独立复核 | 关闭后用新运行时 `open` + `audit_store` | 可见摘要/指纹一致，拒绝理由仍在，零分歧 |

## 6. 小模型穷举

`tests/test_smallmodel.py` 在极小模型上做全量枚举，而非抽样：

- **签收组合**：5 代理池（其中两名同源、一名被撤销）的全部 **25 个有序对**，
  含自签；用独立 oracle 逐对断言结果（`duplicate_agent` / `same_control_source`
  / `revoked_agent` / `accepted` / 水位拒绝）。
- **字段篡改**：对 `link/generation/seq/segment/digest/msg_id` 逐字段篡改，
  断言全部被拒且不可见。
- **签收顺序置换**：两种审批顺序产生相同裁决（顺序无关）。
- **工作交错**：枚举两段程序序（发布×2 与 迁移 / 撤销）的全部线性扩展
  （3 种交错 × 2 组），逐一在独立库上执行，断言可见消息始终是前缀、
  被撤销后的发布必为 `revoked_agent`、迁移前撤销目标代理会使迁移 `lease_not_ready`。

## 7. 六万条分段消息：全量 vs 单租约局部撤销

构建 5 个独立分区，共 **60,000** 条消息（每分区 256 个分段标签）：

| 分区 | 消息数 |
| --- | --- |
| L1@1 | 30,000 |
| L2@1 | 12,000 |
| L3@1 | 8,000 |
| L4@1 | 6,000 |
| L5@1 | 4,000 |

对 **L3@1** 撤销其中一名代理，比较两种"证明状态再推导"策略。
两者共享一次日志重放（约 9 s，单独列在下方），差异在于撤销后重算证明状态的工作量：

| 指标 | 全量重建（重扫每条消息） | 单租约局部撤销 |
| --- | --- | --- |
| 触达消息 | 60,000 | **8,000**（13.33%） |
| 触达分区 | 5 | **1** |
| 触达分段 | 1,280 | **256** |
| 重算耗时 | 0.096 s | **0.011 s** |
| 相对加速 | 1× | **≈8.8×** |

> 日志重放（`build ≈11 s`，`full_replay ≈8.8 s`）对两种策略相同且单独计量；
> 上表刻意只比较**撤销后证明状态更新**的触达范围，避免把共享的重放开销算进加速比。

不变性结论（均为断言，非口头陈述）：

- **无关分区保持不变**：L1/L2/L4/L5 的指纹与全量重建**逐字节相同**
  （`unrelated_partitions_unchanged = true`）。
- **旧水位得以保留**：撤销一名代理后，L3@1 的 **可证明水位仍为 8,000**
  （存活代理可独立证明每条消息，`provable_watermark_preserved = true`）。
- **局部=全量**：`trustrelay.rebuild.full_rebuild`（独立的全量重扫实现）
  与局部更新后的分区指纹、可证明水位完全一致。
- **磁盘核验零分歧**：独立核验器可见摘要与运行时一致，`audit_divergences = 0`。

## 8. 精确数字

见 `artifacts/benchmark.json` 与 `artifacts/audit_demo.txt`（真实运行产物）。
计时随机器负载浮动，但触达量与不变性断言是确定性的。
