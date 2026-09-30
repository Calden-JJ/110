# dfo-server

DFO（地下城与勇士）美服 110 版单机服务端 `USLocalServer`（C# / NativeAOT）的 Python 重写工程。

**参考端 = 0.4.4**（`../DFO110-0.4.4/Server`，2026-09-30 发布）。0.3.6 是上一代
参考，其目录已删除（仅 `_saveaudit/` 留有 exe 与存档副本），它的捕获语料不在盘上，
因此依赖那份语料的用例会显式 skip。

**现状**：登录 → 选服 → 频道 → 选角 → 进城镇 → 城镇移动 / 背包移动（含写存档）已跑通；
副本（M3.0–M3.6）已实现并对拍过。测试：**634 用例全绿，58 条 skip**
（skip 全部是「0.3.6 捕获语料不在盘上」，见下）。

## 快速自检

```sh
set PYTHONPATH=src           # PowerShell: $env:PYTHONPATH="src"
python -m unittest discover -s tests
python -c "from uslocalserver import paths; print(paths.missing_reference())"
```

`missing_reference()` 会列出当前参考树缺什么。空列表 = 夹具齐全。

## 目录

| 路径 | 内容 |
|---|---|
| `src/uslocalserver/paths.py` | **所有路径的单一出处**，按版本解析参考树（`DFO_REF` / `DFO_SERVER_DIR` / `DFO_CORPUS_LOG` 可覆盖） |
| `src/uslocalserver/` | 服务端本体（协议 / 加密 / 存档 / 两条链路） |
| `src/uslocalserver/launcher/` | 自研登录器（ctypes 注入，不依赖任何第三方二进制） |
| `data/` | 密码表、协议表、频道应答、登录器补丁、`tables/`（0.3.6 exe 抠出的 69 张表） |
| `tools/ref044/` | **0.4.4 侦察工具**：内嵌表还在不在、pvf-cache 结构、存档内容、升级层重建验收、触发器 DDL |
| `tools/audit/` | 测试审计：按依赖给模块分类、统计游戏表实际读取覆盖 |
| `tools/` | 其余提取与对拍工具（`diff_packets.py` 逐包对拍、`live_swap.py` 实时接管等） |
| `tests/` | 单测。`_save.py` = 存档夹具，`_bootstrap.py` = 路径与语料 skip |
| `PLAN.md` | 进度与设计记录（唯一进度源）。换代记录见 **REF-0.4.4** 节 |

## 0.4.4 的两处结构性差异

1. **exe 不再内嵌 69 张数据表。** 资源清单里 69 个名字还在（UTF-16LE），表体没了
   （0.3.6 是 81.5 MB 明文 JSON，0.4.4 里一个 `{"source"` 都没有）。真实数据源改成了
   `Server\Data\pvf-cache\<sha>.db`：926 MB SQLite，`scripts(path,payload,sha256)`
   493,781 条 PVF 条目。`data/tables/` 目前仍是 0.3.6 抠出来的那一份；
   69 张表里实测只有 28 张被代码读取，从 pvf-cache 重建只需覆盖这些。
2. **存档 54 → 94 表**，另有 14 个新列散在已有表上。`persistence/migrations.py`
   用 `CURRENT` 那套（6 列 + 2 触发器）即可从 0.4.4 自己的 `BootstrapSchema.sql`
   完整重建（`tools/ref044/check_migrate044.py` → `schemas match`）。

**加密与协议没变**：密钥 blob 与 9 张算法常量表逐字节相同，14 个算法照跑。

## 运行

需要 Python **3.11+**（Windows；登录器的客户端注入部分只支持 Windows）。

```sh
pip install -r requirements.txt      # 只为 tools/ 里的逆向脚本；服务端本体只用标准库

# 只跑服务端（不挂客户端，纯回放/联调）
python -m uslocalserver.server.run --host 127.0.0.1 --port 7001 --save none

# Windows：登录器（起服务端 + 挂起启动并注入客户端）
.\launcher.cmd
```

`launcher.cmd` 首次运行会写出 `launcher.json`（客户端目录、地址、存档路径）。

## 已知限制

- **58 条用例因缺少 0.3.6 捕获语料而 skip。** 要恢复只能对着 0.4.4 参考端重录一份
  （`packetHexLog` 已开；注意 `packetHexMaxBytes=2048`，比 0.3.6 的 4096 小，
  巨型帧截断点会变），或用 `DFO_CORPUS_LOG` 指向旧语料。
- 频道目录应答（`CHANNEL_ACK`）按「端口块 + 当天」生成；0.4.4 有 13 个频道。
- 0.4.4 `server.json` 绑 **127.0.0.2**。
- `data/tables/` 的来源仍是 0.3.6 exe，尚未从 0.4.4 的 pvf-cache 重建。

## 说明

仅用于单机自娱与学习交流，请自备正版客户端；仓库不含任何第三方二进制。
