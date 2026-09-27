# AIGC START
"""只读扫描海康枪机主码流视频参数 — 图形界面。绝不改写设备配置。"""
from __future__ import annotations

import csv
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from scan_core import ScanOptions, StreamInfo, parse_targets, scan_targets

CSV_COLUMNS = [
    "IP",
    "状态",
    "设备名称",
    "型号",
    "码流类型",
    "视频类型",
    "分辨率",
    "码率类型",
    "图像质量",
    "视频帧率",
    "码率上限",
    "平均码率",
    "视频编码",
    "编码复杂度",
    "超级智能编码",
    "I帧间隔",
    "码流平滑",
    "预计存储",
    "错误",
]


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("海康枪机分辨率只读扫描")
        self.geometry("980x720")
        self.minsize(860, 640)

        self._stop = False
        self._running = False
        self._results: list[StreamInfo] = []

        pad = {"padx": 12, "pady": 4}
        root = ttk.Frame(self)
        root.pack(fill=tk.BOTH, expand=True, **pad)

        tip = (
            "只读工具：全程仅发送 GET，不会修改任何摄像头配置。\n"
            "填写统一账号密码与网段（如 192.168.22.1-254 或 192.168.22.0/24），"
            "失败记录在下方日志，可导出 CSV。"
        )
        ttk.Label(root, text=tip, justify=tk.LEFT).pack(anchor="w", pady=(0, 8))

        form = ttk.Frame(root)
        form.pack(fill=tk.X)

        self.username = tk.StringVar(value="admin")
        self.password = tk.StringVar(value="")
        self.range_text = tk.StringVar(value="192.168.22.1-254")
        self.workers = tk.StringVar(value="6")
        self.timeout = tk.StringVar(value="4")
        self.port = tk.StringVar(value="80")
        self.probe = tk.BooleanVar(value=True)

        self._labeled_entry(form, 0, "用户名", self.username)
        self._labeled_entry(form, 1, "密码", self.password, show="*")
        self._labeled_entry(form, 2, "网段/范围", self.range_text)

        row = ttk.Frame(form)
        row.grid(row=3, column=0, columnspan=2, sticky="ew", pady=2)
        ttk.Label(row, text="并发数", width=12).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.workers, width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="超时(秒)", width=10).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Entry(row, textvariable=self.timeout, width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="端口", width=6).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Entry(row, textvariable=self.port, width=6).pack(side=tk.LEFT)
        ttk.Checkbutton(row, text="先探测端口再查询（更保守）", variable=self.probe).pack(
            side=tk.LEFT, padx=16
        )
        form.columnconfigure(1, weight=1)

        btns = ttk.Frame(root)
        btns.pack(fill=tk.X, pady=8)
        self.start_btn = ttk.Button(btns, text="开始只读扫描", command=self.start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(
            btns, text="停止", command=self.request_stop, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(btns, text="导出 CSV", command=self.export_csv).pack(side=tk.LEFT, padx=8)
        ttk.Button(btns, text="保存失败日志", command=self.save_fail_log).pack(side=tk.LEFT)
        ttk.Button(btns, text="清空结果", command=self.clear_results).pack(side=tk.RIGHT)

        table_frm = ttk.Frame(root)
        table_frm.pack(fill=tk.BOTH, expand=True)
        cols = (
            "IP",
            "分辨率",
            "编码",
            "码率上限",
            "帧率",
            "码率类型",
            "智能编码",
            "设备名称",
            "状态",
        )
        self.tree = ttk.Treeview(table_frm, columns=cols, show="headings", height=14)
        widths = {
            "IP": 120,
            "分辨率": 100,
            "编码": 70,
            "码率上限": 80,
            "帧率": 50,
            "码率类型": 70,
            "智能编码": 70,
            "设备名称": 140,
            "状态": 160,
        }
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths.get(c, 100), anchor="w")
        sy = ttk.Scrollbar(table_frm, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sy.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Label(root, text="运行日志（失败会标 [失败]）").pack(anchor="w", pady=(8, 2))
        self.log = tk.Text(
            root, height=10, font=("Consolas", 9), bg="#1e1e1e", fg="#dddddd"
        )
        self.log.pack(fill=tk.BOTH, expand=False)
        self.log.configure(state=tk.DISABLED)

        self.status = tk.StringVar(value="就绪 · 只读模式")
        ttk.Label(root, textvariable=self.status).pack(anchor="w", pady=(4, 0))

    def _labeled_entry(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        var: tk.StringVar,
        show: str | None = None,
    ) -> None:
        ttk.Label(parent, text=label, width=12).grid(row=row, column=0, sticky="w", pady=2)
        kw: dict = {"textvariable": var}
        if show is not None:
            kw["show"] = show
        ttk.Entry(parent, **kw).grid(row=row, column=1, sticky="ew", pady=2)

    def append_log(self, msg: str) -> None:
        def _do() -> None:
            self.log.configure(state=tk.NORMAL)
            self.log.insert(tk.END, msg + "\n")
            self.log.see(tk.END)
            self.log.configure(state=tk.DISABLED)

        self.after(0, _do)

    def add_row(self, info: StreamInfo) -> None:
        def _do() -> None:
            status = "成功" if info.ok else (info.error or "失败")
            self.tree.insert(
                "",
                tk.END,
                values=(
                    info.ip,
                    info.resolution,
                    info.video_codec,
                    info.max_bitrate,
                    info.frame_rate,
                    info.bitrate_type,
                    info.smart_codec,
                    info.device_name,
                    status,
                ),
            )

        self.after(0, _do)

    def clear_results(self) -> None:
        if self._running:
            messagebox.showinfo("提示", "扫描进行中，请先停止")
            return
        self._results.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)
        self.status.set("已清空 · 只读模式")

    def request_stop(self) -> None:
        self._stop = True
        self.append_log("正在停止…（已发出的请求会自然结束）")

    def start(self) -> None:
        if self._running:
            return
        user = self.username.get().strip()
        password = self.password.get()
        range_text = self.range_text.get().strip()
        if not user or not password:
            messagebox.showwarning("缺少信息", "请填写用户名和密码")
            return
        if not range_text:
            messagebox.showwarning("缺少信息", "请填写网段或 IP 范围")
            return
        try:
            ips = parse_targets(range_text)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("范围无效", str(exc))
            return
        if not ips:
            messagebox.showwarning("范围无效", "没有解析到任何 IP")
            return
        if len(ips) > 1024 and not messagebox.askyesno(
            "范围较大", f"将扫描 {len(ips)} 个地址，可能较慢。是否继续？"
        ):
            return
        try:
            workers = int(self.workers.get().strip() or "6")
            timeout = float(self.timeout.get().strip() or "4")
            port = int(self.port.get().strip() or "80")
        except ValueError:
            messagebox.showerror("参数错误", "并发数 / 超时 / 端口 必须是数字")
            return

        workers = max(1, min(workers, 16))
        opt = ScanOptions(
            username=user,
            password=password,
            timeout=timeout,
            workers=workers,
            port=port,
            probe_port_first=self.probe.get(),
        )

        self._stop = False
        self._running = True
        self._results = []
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.status.set(f"扫描中… 目标 {len(ips)} 台（只读 GET）")
        self.append_log("=" * 60)
        self.append_log(
            f"目标数 {len(ips)} · 并发 {workers} · 超时 {timeout}s · 端口 {port}"
        )
        self.append_log("安全约束：仅 GET /ISAPI/... ，禁止改写配置")

        def worker() -> None:
            def on_result(info: StreamInfo) -> None:
                self._results.append(info)
                self.add_row(info)

            try:
                scan_targets(
                    ips,
                    opt,
                    on_result=on_result,
                    on_log=self.append_log,
                    should_stop=lambda: self._stop,
                )
            finally:
                self.after(0, self._scan_finished)

        threading.Thread(target=worker, daemon=True).start()

    def _scan_finished(self) -> None:
        self._running = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        ok_n = sum(1 for r in self._results if r.ok)
        fail_n = len(self._results) - ok_n
        self.status.set(f"完成 · 成功 {ok_n} · 失败 {fail_n} · 只读模式")
        self.append_log(f"完成：成功 {ok_n}，失败 {fail_n}")

    def export_csv(self) -> None:
        if not self._results:
            messagebox.showinfo("导出", "暂无结果可导出")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="导出 CSV",
            defaultextension=".csv",
            initialfile=f"scan_results_{stamp}.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        rows = sorted(self._results, key=lambda r: tuple(int(x) for x in r.ip.split(".")))
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for info in rows:
                writer.writerow(info.to_row())
        messagebox.showinfo("导出", f"已保存：\n{path}")

    def save_fail_log(self) -> None:
        fails = [r for r in self._results if not r.ok]
        if not fails:
            messagebox.showinfo("失败日志", "当前没有失败记录")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="保存失败日志",
            defaultextension=".log",
            initialfile=f"fail_{stamp}.log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt")],
        )
        if not path:
            return
        lines = [f"# 只读扫描失败日志 {stamp}", f"# 共 {len(fails)} 条", ""]
        for info in sorted(fails, key=lambda r: r.ip):
            lines.append(f"{info.ip}\t{info.error}")
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        messagebox.showinfo("失败日志", f"已保存：\n{path}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
# AIGC END
