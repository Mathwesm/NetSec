"""Provide a small Windows-friendly launcher for validation and native firewall use."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from netsec.desktop_process import is_elevated, request_elevation, run_command
from netsec.runtime import RuntimeFailureError


class Desktop:
    """Keep privileges explicit and display the same source-linked CLI diagnostics."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.file = tk.StringVar()
        self.status = tk.StringVar(value="Administrador" if is_elevated() else "Usuário padrão")
        self.results: queue.Queue[tuple[int, str]] = queue.Queue()
        self.busy = False
        root.title("NetSec — Redes e segurança")
        root.geometry("960x650")
        root.minsize(780, 540)
        self._layout()
        root.after(100, self._poll)

    def _layout(self) -> None:
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="NetSec", font=("Segoe UI", 25, "bold")).pack(anchor="w")
        ttk.Label(
            frame, text="Valide a linguagem, visualize a política e aplique quando estiver pronto."
        ).pack(anchor="w", pady=(0, 14))
        ttk.Label(frame, textvariable=self.status).pack(anchor="w")
        selector = ttk.Frame(frame)
        selector.pack(fill="x", pady=12)
        ttk.Entry(selector, textvariable=self.file).pack(side="left", fill="x", expand=True)
        ttk.Button(selector, text="Escolher .netsec", command=self._choose).pack(
            side="left", padx=(8, 0)
        )
        actions = ttk.Frame(frame)
        actions.pack(fill="x")
        for label, operation in (
            ("Validar", "check"),
            ("Prévia", "preview"),
            ("Diagnóstico", "doctor"),
            ("Aplicar localmente", "run"),
            ("Remover regras", "firewall-remove"),
        ):
            ttk.Button(actions, text=label, command=partial(self._execute, operation)).pack(
                side="left", padx=(0, 6)
            )
        ttk.Button(
            frame, text="Abrir outra janela como administrador (UAC)", command=self._elevate
        ).pack(anchor="w", pady=12)
        ttk.Label(
            frame,
            text=(
                "Elevação é opcional para validar. Firewall exige administrador. "
                "Nenhuma regra é aplicada ao abrir."
            ),
            wraplength=870,
        ).pack(anchor="w")
        self.output = scrolledtext.ScrolledText(
            frame, wrap="word", font=("Consolas", 10), height=20
        )
        self.output.pack(fill="both", expand=True, pady=(12, 0))
        self.output.insert("end", "Selecione um programa e clique em Validar ou Prévia.\n")

    def _choose(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("NetSec", "*.netsec"), ("Todos", "*.*")])
        if selected:
            self.file.set(selected)

    def _execute(self, operation: str) -> None:
        if self.busy:
            return
        if operation != "doctor" and not Path(self.file.get()).is_file():
            messagebox.showerror("Arquivo inválido", "Escolha um arquivo .netsec existente.")
            return
        arguments = [operation] if operation == "doctor" else [operation, self.file.get()]
        if operation in {"run", "firewall-remove"}:
            if not messagebox.askyesno(
                "Alteração de firewall",
                "Alterar as regras locais indicadas por este arquivo? "
                "Revise a Prévia antes de continuar.",
            ):
                return
            arguments.extend(["--mode", "local", "--apply", "--fail-fast"])
            arguments.extend(["--journal-root", str(Path.home() / ".netsec" / "runs")])
        self.busy = True
        self.output.insert("end", f"\nExecutando: {operation}\n")
        threading.Thread(target=self._worker, args=(arguments,), daemon=True).start()

    def _worker(self, arguments: list[str]) -> None:
        try:
            self.results.put(run_command(arguments))
        except RuntimeFailureError as error:
            self.results.put((2, str(error)))

    def _poll(self) -> None:
        try:
            code, output = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.output.insert("end", output + f"\nCódigo de saída: {code}\n")
            self.output.see("end")
        self.root.after(100, self._poll)

    def _elevate(self) -> None:
        try:
            request_elevation()
        except RuntimeFailureError as error:
            messagebox.showerror("Elevação não realizada", str(error))


def main() -> None:
    """Open the desktop without executing a policy or requesting administrator privileges."""
    root = tk.Tk()
    Desktop(root)
    root.mainloop()


if __name__ == "__main__":
    main()
