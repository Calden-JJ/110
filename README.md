# dfo-server

DFO（地下城与勇士）美服 110 版单机服务端 `USLocalServer`（C# / NativeAOT）的 Python 重写工程。


**现状**：登录 → 选服 → 频道 → 选角 → 进城镇 → 城镇移动 / 背包移动（含写存档）已跑通，
可用自带登录器「冷启动」一把进城镇（不需要参考服务端在场）。副本（M3）未开工。

## 准备数据（首次）

仓库不含从参考服务端提取的大体积游戏数据（`data/tables/` 与物品目录）。运行前自备参考服务端
`USLocalServer.Server.exe`（默认在 `<仓库>/../DFO110-0.3.6/Server`，可用环境变量 `DFO_SERVER_DIR` 覆盖）：

```sh
python tools/extract_tables.py     # -> data/tables/，69 张表
```

物品目录 `item_content_110us.db` 由参考端单独分发，放到
`%LOCALAPPDATA%\USLocalServer\Tester\Content\`（可用 `DFO_ITEM_CONTENT_DB` 覆盖）。
`data/` 其余内容（协议表、密码表、频道应答、登录器补丁）随仓库提供。

## 运行

需要 Python **3.11+**（Windows；登录器的客户端注入部分只支持 Windows）。

```sh
# 服务端本体与测试只用标准库；这行只为 tools/ 里的逆向脚本
pip install -r requirements.txt

# 只跑服务端（不挂客户端，纯回放/联调）
set PYTHONPATH=src           # PowerShell: $env:PYTHONPATH="src"
python -m uslocalserver.server.run --host 127.0.0.1 --port 7001 --save none

# 测试
python -m unittest discover -s tests

# Windows：登录器（起服务端 + 挂起启动并注入客户端，二选一即可）
.\launcher.cmd
```

`launcher.cmd` 首次运行会写出 `launcher.json`（客户端目录、地址、存档路径），改那里或加命令行参数即可。

## 目录

| 路径 | 内容 |
|---|---|
| `src/uslocalserver/` | 服务端本体（协议 / 加密 / 存档 / 两条链路） |
| `src/uslocalserver/launcher/` | 自研登录器（ctypes 注入，不依赖任何第三方二进制） |
| `data/` | 密码表、协议表、频道应答、登录器补丁（`tables/` 与物品库需自备，见上） |
| `tools/` | 提取与对拍工具（`diff_packets.py` 逐包对拍、`live_swap.py` 实时接管等） |
| `tests/` | 347 条单测（`python -m unittest discover -s tests`） |
| `PLAN.md` | 进度与设计记录（唯一进度源） |

## 已知限制

- 频道目录应答（`CHANNEL_ACK`）按「端口块 + 当天」生成，离线回放需当天从参考端重采一次
  （`tools/extract_channel_replies.py`）；解出密钥来源是下一步。
- 日常开发以美服 110 版客户端 `2.31.1.117` 为基准，登录器对客户端有版本校验。

## 说明

仅用于单机自娱与学习交流，请自备正版客户端；仓库不含任何第三方二进制。
