"""Double-click launcher for the local Aegis Guard web dashboard on Windows."""

from __future__ import annotations

import os
import sys
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import messagebox


def main() -> None:
    """Start the local dashboard and open it in the default browser."""
    app_dir = Path(__file__).resolve().parent
    os.chdir(app_dir)
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))

    try:
        from aegis.web import serve

        serve(port=8765, open_browser=True)
    except Exception as exc:
        details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        try:
            dialog = tk.Tk()
            dialog.withdraw()
            messagebox.showerror(
                "Aegis Guard could not start",
                f"{exc}\n\nCheck that Python 3.10+ is installed and the Aegis Guard folder is complete.\n\nTechnical details:\n{details}",
                parent=dialog,
            )
            dialog.destroy()
        except tk.TclError:
            error_log = app_dir / "aegis-launch-error.txt"
            error_log.write_text(details, encoding="utf-8")
            raise


if __name__ == "__main__":
    main()
