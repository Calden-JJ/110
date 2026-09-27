"""One button: check everything, start the server, bring the client up patched.

`Launcher` holds the whole sequence and talks to the world through a `log`
callback, so `--no-gui` and the tkinter window are the same code path.  The
steps and their order are the reference launcher's, minus everything the
rewrite replaces: no `server.json` rewrite (the server is ours), no port
drift (the passport is built here), no `Dll1.dll` (two ctypes writes).
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import client, config as config_mod, patches, ports, win32
from .config import LauncherConfig
from .server import ServerProcess, ServerStartError, advertise_address

#: Both NGS sites sit in the entry path; Themida's unpack runs before it, so
#: re-reading shortly after resume is what tells us the writes held.
VERIFY_DELAY_SECONDS = 2.0


class LaunchError(RuntimeError):
    """Anything that should reach the user as one clear sentence."""


@dataclass
class Run:
    process: win32.Process
    server: ServerProcess
    patched: list[patches.Applied]


class Launcher:
    def __init__(self, config: LauncherConfig, log=print):
        self.config = config
        self.log = log
        self.run: Run | None = None
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> Run:
        with self._lock:
            if self.run is not None:
                raise LaunchError("已经在运行了。")
            cfg = self.config
            self.log("[launcher] 校验客户端 …")
            exe = client.validate(cfg.client_dir)
            client.ensure_no_running_client()
            ports.ensure_free()
            patch_set = patches.load()
            address = advertise_address(cfg)
            passport = client.build_passport(address, ports.CHANNEL)
            self.log(f"[launcher] 端点 {address}:{ports.CHANNEL}，客户端 {exe}")

            server = ServerProcess(cfg, log=self.log)
            server.start()
            try:
                server.wait_ready()
            except ServerStartError as e:
                server.stop()
                raise LaunchError(str(e)) from None

            self.log("[launcher] 挂起启动客户端 …")
            try:
                process = win32.create_suspended(
                    exe, f'"{exe}" "{passport}"', cfg.client_dir)
            except OSError as e:
                server.stop()
                raise LaunchError(str(e)) from None

            patched: list[patches.Applied] = []
            try:
                handle = win32.open_process(process.pid)
                try:
                    base = win32.image_base(handle)
                    patched = patches.apply(handle, base, patch_set)
                finally:
                    win32.close_handle(handle)
                process.resume()
            except Exception:
                process.terminate()
                process.close()
                server.stop()
                raise

            self.log(f"[launcher] 客户端 PID {process.pid} 已放行"
                     f"（本次写入 {len(patched)}/{len(patch_set.sites)} 处补丁）")
            self.run = Run(process, server, patched)

        time.sleep(VERIFY_DELAY_SECONDS)
        self._verify_patches()
        self._save_config()
        return self.run

    def _verify_patches(self) -> None:
        if not self.run or not self.run.patched:
            return
        if not self.run.process.alive():
            self.log("[launcher] ⚠ 客户端已退出 —— 看客户端窗口的报错内容")
            return
        try:
            handle = win32.open_process(self.run.process.pid, win32.PROCESS_VM_READ
                                        | win32.PROCESS_QUERY_INFORMATION)
            try:
                lost = patches.verify_still_applied(handle, self.run.patched)
            finally:
                win32.close_handle(handle)
        except OSError as e:
            # Verification is diagnostic; a client that is mid-exit must not
            # turn a successful launch into a failure.
            self.log(f"[launcher] ⚠ 补丁回读失败：{e}")
            return
        if lost:
            self.log(f"[launcher] ⚠ 补丁被覆盖：{', '.join(lost)} —— 客户端可能已在解壳时还原")
        else:
            self.log(f"[launcher] ✅ {len(self.run.patched)} 处补丁在解壳后仍然生效")

    def stop(self) -> None:
        with self._lock:
            if self.run is None:
                return
            run, self.run = self.run, None
        if run.process.alive():
            self.log(f"[launcher] 结束客户端 PID {run.process.pid}")
            run.process.terminate()
        run.process.close()
        run.server.stop()

    def is_running(self) -> bool:
        return self.run is not None and (self.run.server.is_running()
                                         or self.run.process.alive())

    def _save_config(self) -> None:
        try:
            config_mod.save(self.config)
        except OSError as e:
            self.log(f"[launcher] 配置没写进 launcher.json：{e}")


def run_headless(config: LauncherConfig, log=print) -> int:
    """`--no-gui`: start, then stay up until interrupted."""
    launcher = Launcher(config, log=log)
    try:
        launcher.start()
    except (LaunchError, OSError, client.ClientError, ports.PortsBusy,
            patches.PatchError, config_mod.ConfigError) as e:
        log(f"[launcher] ✗ {e}")
        return 1
    log("[launcher] 运行中，Ctrl+C 结束（会一并关闭客户端与服务端）。")
    try:
        while launcher.is_running():
            time.sleep(0.5)
        log("[launcher] 客户端已退出。")
    except KeyboardInterrupt:
        log("[launcher] 收到中断。")
    finally:
        launcher.stop()
    return 0


class Window:
    """tkinter front end: same `Launcher`, logs pumped through a queue."""

    def __init__(self, config: LauncherConfig):
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext

        self._tk = tk
        self._filedialog = filedialog
        self._messagebox = messagebox
        self.config = config
        self.launcher = Launcher(config, log=self._enqueue)
        self.queue: queue.Queue[str] = queue.Queue()
        self.worker: threading.Thread | None = None
        self._confirmed_close = False

        self.root = tk.Tk()
        self.root.title("DFO 本地服务端（自研登录器）")
        self.root.geometry("760x460")

        frame = tk.Frame(self.root)
        frame.pack(fill="x", padx=10, pady=(10, 4))
        self.client_var = tk.StringVar(value=str(config.client_dir))
        self.address_var = tk.StringVar(value=config.server_address)
        self.save_var = tk.StringVar(value="none" if config.save_db is None
                                     else str(config.save_db))
        for row, (label, var, pick) in enumerate((
                ("客户端目录", self.client_var, self._pick_dir),
                ("服务器地址", self.address_var, None),
                ("存档", self.save_var, self._pick_file))):
            tk.Label(frame, text=label, width=10, anchor="e").grid(row=row, column=0, sticky="e")
            tk.Entry(frame, textvariable=var).grid(row=row, column=1, sticky="ew", padx=4)
            if pick:
                tk.Button(frame, text="浏览…", command=pick).grid(row=row, column=2)
        frame.columnconfigure(1, weight=1)
        tk.Label(frame, text=f"端口固定 7001 + {ports.GAME[0]}–{ports.GAME[-1]}",
                 fg="#666").grid(row=3, column=1, sticky="w", padx=4)

        buttons = tk.Frame(self.root)
        buttons.pack(fill="x", padx=10)
        self.start_button = tk.Button(buttons, text="启动", width=10, command=self._start)
        self.start_button.pack(side="left")
        self.stop_button = tk.Button(buttons, text="停止", width=10, state="disabled",
                                     command=self._stop)
        self.stop_button.pack(side="left", padx=6)
        self.status = tk.Label(buttons, text="已停止", fg="#666")
        self.status.pack(side="left", padx=12)

        self.text = scrolledtext.ScrolledText(self.root, height=18, state="disabled")
        self.text.pack(fill="both", expand=True, padx=10, pady=8)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain)

    # -- logging -----------------------------------------------------------

    def _enqueue(self, line: str) -> None:
        self.queue.put(line)

    def _drain(self) -> None:
        while True:
            try:
                line = self.queue.get_nowait()
            except queue.Empty:
                break
            self.text.configure(state="normal")
            self.text.insert("end", line + "\n")
            self.text.see("end")
            self.text.configure(state="disabled")
        self.root.after(100, self._drain)

    # -- buttons -----------------------------------------------------------

    def _pick_dir(self) -> None:
        chosen = self._filedialog.askdirectory(title="选择客户端目录")
        if chosen:
            self.client_var.set(chosen)

    def _pick_file(self) -> None:
        chosen = self._filedialog.askopenfilename(
            title="选择存档数据库", filetypes=[("SQLite", "*.db"), ("全部", "*.*")])
        if chosen:
            self.save_var.set(chosen)

    def _config_from_fields(self) -> LauncherConfig:
        save = self.save_var.get().strip()
        client = self.client_var.get().strip()
        address = self.address_var.get().strip()
        return replace(
            self.config,
            client_dir=Path(client) if client else self.config.client_dir,
            server_address=address or self.config.server_address,
            save_db=None if save.lower() in ("", "none") else Path(save))

    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        try:
            self.config = self._config_from_fields()
        except Exception as e:  # pragma: no cover - defensive
            self._messagebox.showerror("配置有误", str(e))
            return
        self.launcher = Launcher(self.config, log=self._enqueue)
        self.start_button.configure(state="disabled")
        self.status.configure(text="启动中 …", fg="#a60")
        self.worker = threading.Thread(target=self._start_bg, daemon=True)
        self.worker.start()

    def _start_bg(self) -> None:
        try:
            self.launcher.start()
        except Exception as e:
            message = str(e)  # bound now: the closure cannot see `e` later
            self._enqueue(f"[launcher] ✗ {message}")
            self.root.after(0, lambda: self._set_idle("启动失败", "#a00"))
            self.root.after(0, lambda: self._messagebox.showerror("启动失败", message))
            return
        self.root.after(0, lambda: self._set_running())

    def _stop(self) -> None:
        if not self._messagebox.askyesno("停止", "停止服务端并关闭客户端？"):
            return
        threading.Thread(target=self._stop_bg, daemon=True).start()

    def _stop_bg(self) -> None:
        self.launcher.stop()
        self.root.after(0, lambda: self._set_idle("已停止", "#666"))

    def _set_running(self) -> None:
        pid = self.launcher.run.process.pid if self.launcher.run else "?"
        self.status.configure(text=f"运行中（客户端 PID {pid}）", fg="#060")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

    def _set_idle(self, text: str, colour: str) -> None:
        self.status.configure(text=text, fg=colour)
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _on_close(self) -> None:
        if not self._confirmed_close:
            busy = self.launcher.is_running() or (self.worker is not None
                                                  and self.worker.is_alive())
            if busy and not self._messagebox.askyesno(
                    "退出", "服务端还在运行或正在启动，退出会一并关闭客户端。继续？"):
                return
            self._confirmed_close = True
        if self.worker is not None and self.worker.is_alive():
            # A start in flight owns the child processes; let it finish before
            # tearing the window down, or they would outlive us.
            self.root.after(200, self._on_close)
            return
        self.launcher.stop()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
