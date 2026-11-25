# 分区链路切换的信任租约回放

两条隔离网络的边缘节点在维护窗切换信任代理；消息只在本地合成队列中流转。
本项目用 **Windows 上的 Python 3.12 标准库** 实现离线中继状态机与独立核验器，
全部输入为本地合成数据，无网络、无第三方依赖。

题面见 `task/PROMPT.txt`。设计与实测结果见 [`REPORT.md`](REPORT.md)。

## 快速运行

```bat
:: 全部测试（含 60k 基准、两线程场景、小模型穷举、CLI 复核）
python -m unittest discover -s tests -v
```

测试产物写入 `artifacts/`：

| 文件 | 内容 |
| --- | --- |
| `artifacts/benchmark.json` | 60k 分段消息：全量重建 vs 单租约局部撤销的对比数据 |
| `artifacts/audit_demo.txt` | 独立核验 CLI 的真实输出（可见消息、水位、拒绝理由） |

## 独立复核（重启后，只读磁盘）

```bat
python -m trustrelay audit <store-dir>      :: 逐条重放并核对，打印可见消息/水位/拒绝理由
python -m trustrelay footprint <store-dir>  :: 打印各分区指纹
```

核验器（`trustrelay/verify.py`）**不导入**运行时状态机，自己重新解析
`relay.journal` 字节、重算校验链、按独立规则集重新裁决每条记录，并列出与
落盘结果的分歧。任何分歧都会使退出码非零。

## 语义要点

- **一条已发布消息绑定**：链路、租约代、原始内容摘要、连续序号与分段。
- **恰好两名独立签收者**：两名不同代理，且控制源不同；同一控制源只计一次。
- **同一租约代**：两名代理都必须绑定到该 `(link, generation)`，MAC 覆盖全部绑定字段。
- **撤销非追溯**：已发布消息保持可见、发布水位不回退；撤销其中一名代理时，
  另一名仍能独立证明，旧的可证明水位得以保留；两者都撤销时才降到 0。
- **提交即持久**：每条记录写满一行、flush、fsync 后才返回；回复丢失后可从磁盘重建。
- **撕裂尾部**：崩溃残留的半行在重启时被截断，已提交前缀与链头保持不变。

## 目录

```
trustrelay/
  model.py    值对象、确定性编码、HMAC 签收模型、稳定理由码
  journal.py  校验链式追加日志、fsync、撕裂尾部恢复
  state.py    事务状态机（租约生命周期、发布、回执、局部撤销）
  rebuild.py  全量重扫证明状态（基准对照用的独立实现）
  verify.py   独立磁盘核验器（不依赖状态机）
  events.py   合成事件构造器
  __main__.py CLI：audit / footprint
tests/
  test_core.py        绑定、独立性、水位、撤销、幂等
  test_threads.py     两真实线程 + 可控屏障：迁移/回执迟到/承诺后回复丢失/重启复核
  test_smallmodel.py  小模型穷举签收组合与工作交错
  test_replay_fuzz.py 随机合法操作流的重放确定性与审计一致性
  test_benchmark.py   60k 分段消息全量 vs 局部撤销
  test_cli.py         CLI 复核端到端
```
