import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import qrcode
from PIL import Image, ImageTk


# ---------- Helpers ----------
def show_menu(event, widget, menu):
    widget.focus_set()
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()


def select_all_entry(event, entry: tk.Entry):
    # Robust guard (prevents "a" from acting like Ctrl+A on some layouts)
    CTRL_MASK = 0x4
    if not (event.state & CTRL_MASK):
        return

    entry.focus_set()
    entry.selection_range(0, tk.END)
    entry.icursor(tk.END)
    return "break"


def enable_clipboard_shortcuts(widget: tk.Entry):
    widget.bind("<Control-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Control-v>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Control-x>", lambda e: (widget.event_generate("<<Cut>>"), "break"))

    # Robust Select All
    widget.bind("<KeyPress-a>", lambda e: select_all_entry(e, widget))
    widget.bind("<KeyPress-A>", lambda e: select_all_entry(e, widget))

    # macOS (optional)
    widget.bind("<Command-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Command-v>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Command-x>", lambda e: (widget.event_generate("<<Cut>>"), "break"))
    widget.bind("<Command-a>", lambda e: select_all_entry(e, widget))


def add_context_menu(root, widget: tk.Entry):
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="Select All", command=lambda: widget.selection_range(0, tk.END))

    widget.bind("<Button-3>", lambda e: show_menu(e, widget, menu))  # Windows/Linux
    widget.bind("<Button-2>", lambda e: show_menu(e, widget, menu))  # macOS


def make_wifi_payload(ssid: str, password: str, auth: str, hidden: bool) -> str:
    r"""
    WiFi QR payload format (commonly supported by phones):
      WIFI:T:<WPA|WEP|nopass>;S:<ssid>;P:<password>;H:<true|false>;;
    Escape \ ; , : and " by prefixing with backslash.
    """
    def esc(s: str) -> str:
        return (s.replace("\\", "\\\\")
                 .replace(";", r"\;")
                 .replace(",", r"\,")
                 .replace(":", r"\:")
                 .replace('"', r"\""))

    ssid_e = esc(ssid)
    pwd_e = esc(password)

    if auth == "nopass":
        pwd_e = ""
    hidden_str = "true" if hidden else "false"

    return f"WIFI:T:{auth};S:{ssid_e};P:{pwd_e};H:{hidden_str};;"


# ---------- App ----------
class QRCodeGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("QR Code Generator")

        #allow resizing; we will auto-fit to content
        self.resizable(True, True)
        self.minsize(520, 650)

        self.qr_pil_image: Image.Image | None = None
        self.qr_tk_image: ImageTk.PhotoImage | None = None

        self.mode_var = tk.StringVar(value="Text")
        self.size_var = tk.IntVar(value=320)   # final QR size (px)
        self.ec_var = tk.StringVar(value="M")  # L/M/Q/H

        self._build_ui()
        self._switch_mode()

        # Start with a sensible size
        self.geometry("720x650")

    def _build_ui(self):
        top = tk.Frame(self)
        top.pack(pady=12, fill="x")

        tk.Label(top, text="Mode:").pack(side=tk.LEFT, padx=(12, 8))
        self.mode_combo = ttk.Combobox(
            top, textvariable=self.mode_var,
            values=["Text", "Link", "WiFi"],
            state="readonly", width=10
        )
        self.mode_combo.pack(side=tk.LEFT)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self._switch_mode())

        controls = tk.LabelFrame(self, text="QR Settings", padx=10, pady=10)
        controls.pack(fill="x", padx=12, pady=6)

        tk.Label(controls, text="Error correction:").grid(row=0, column=0, sticky="w")
        self.ec_combo = ttk.Combobox(
            controls, textvariable=self.ec_var,
            values=["L", "M", "Q", "H"],
            state="readonly", width=6
        )
        self.ec_combo.grid(row=0, column=1, sticky="w", padx=(8, 0))
        tk.Label(
            controls,
            text="(L=low, M=default, Q=high, H=highest)",
            fg="gray"
        ).grid(row=0, column=1, sticky="w", padx=(100, 0))

        tk.Label(controls, text="QR size (px):").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.size_scale = tk.Scale(
            controls, from_=160, to=900, orient="horizontal",
            variable=self.size_var, length=250
        )
        self.size_scale.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(10, 0))
        tk.Label(controls, textvariable=self.size_var).grid(row=1, column=2, sticky="w", padx=(10, 0), pady=(10, 0))

        controls.grid_columnconfigure(2, weight=1)

        self.form = tk.LabelFrame(self, text="Input", padx=10, pady=10)
        self.form.pack(fill="x", padx=12, pady=10)

        btns = tk.Frame(self)
        btns.pack(pady=8)

        tk.Button(btns, text="Generate", width=12, command=self.generate_qr_code).pack(side=tk.LEFT, padx=6)
        tk.Button(btns, text="Save", width=12, command=self.save_qr_code).pack(side=tk.LEFT, padx=6)

        # Preview frame expands/shrinks; label expands to image
        self.preview = tk.LabelFrame(self, text="Preview", padx=10, pady=10)
        self.preview.pack(fill="both", expand=True, padx=12, pady=10)

        self.preview_label = tk.Label(self.preview, text="No QR generated yet.")
        self.preview_label.pack(pady=10, expand=True)

        self.bind("<Return>", lambda e: self.generate_qr_code())

    def _clear_form(self):
        for child in self.form.winfo_children():
            child.destroy()

    def _switch_mode(self):
        self._clear_form()
        mode = self.mode_var.get()

        if mode in ("Text", "Link"):
            lbl = "Text to encode:" if mode == "Text" else "URL to encode:"
            tk.Label(self.form, text=lbl).pack(anchor="w")

            self.single_entry = tk.Entry(self.form, width=58)
            self.single_entry.pack(pady=(6, 0))
            enable_clipboard_shortcuts(self.single_entry)
            add_context_menu(self, self.single_entry)
            self.single_entry.focus_set()

            if mode == "Link":
                tk.Label(self.form, text="Tip: include https:// for best results", fg="gray").pack(anchor="w", pady=(6, 0))

        elif mode == "WiFi":
            tk.Label(self.form, text="SSID (network name):").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
            self.ssid_entry = tk.Entry(self.form, width=40)
            self.ssid_entry.grid(row=0, column=1, sticky="w", pady=(0, 6))
            enable_clipboard_shortcuts(self.ssid_entry)
            add_context_menu(self, self.ssid_entry)

            tk.Label(self.form, text="Security:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
            self.auth_var = tk.StringVar(value="WPA")
            self.auth_combo = ttk.Combobox(
                self.form, textvariable=self.auth_var,
                values=["WPA", "WEP", "nopass"],
                state="readonly", width=10
            )
            self.auth_combo.grid(row=1, column=1, sticky="w", pady=(0, 6))
            self.auth_combo.bind("<<ComboboxSelected>>", lambda e: self._update_wifi_fields())

            tk.Label(self.form, text="Password:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
            self.pwd_entry = tk.Entry(self.form, width=40, show="•")
            self.pwd_entry.grid(row=2, column=1, sticky="w", pady=(0, 6))
            enable_clipboard_shortcuts(self.pwd_entry)
            add_context_menu(self, self.pwd_entry)

            self.show_pwd_var = tk.BooleanVar(value=False)
            tk.Checkbutton(
                self.form, text="Show password",
                variable=self.show_pwd_var,
                command=self._toggle_password_visibility
            ).grid(row=3, column=1, sticky="w", pady=(0, 6))

            self.hidden_var = tk.BooleanVar(value=False)
            tk.Checkbutton(
                self.form,
                text="Hidden network (SSID not broadcast)",
                variable=self.hidden_var
            ).grid(row=4, column=1, sticky="w")

            self.form.grid_columnconfigure(1, weight=1)
            self.ssid_entry.focus_set()
            self._update_wifi_fields()

    def _toggle_password_visibility(self):
        self.pwd_entry.configure(show="" if self.show_pwd_var.get() else "•")

    def _update_wifi_fields(self):
        if self.auth_var.get() == "nopass":
            self.pwd_entry.delete(0, tk.END)
            self.pwd_entry.configure(state="disabled")
        else:
            self.pwd_entry.configure(state="normal")

    def _get_payload(self) -> str:
        mode = self.mode_var.get()

        if mode == "Text":
            data = self.single_entry.get().strip()
            if not data:
                raise ValueError("Please enter some text.")
            return data

        if mode == "Link":
            url = self.single_entry.get().strip()
            if not url:
                raise ValueError("Please enter a URL.")
            if "://" not in url:
                url = "https://" + url
            return url

        if mode == "WiFi":
            ssid = self.ssid_entry.get().strip()
            if not ssid:
                raise ValueError("Please enter the Wi-Fi SSID.")

            auth = self.auth_var.get()
            pwd = self.pwd_entry.get() if auth != "nopass" else ""

            if auth != "nopass" and not pwd:
                raise ValueError("Please enter the Wi-Fi password (or choose 'nopass').")

            return make_wifi_payload(ssid, pwd, auth, self.hidden_var.get())

        raise ValueError("Unknown mode selected.")

    def _get_error_correction_const(self):
        mapping = {
            "L": qrcode.constants.ERROR_CORRECT_L,
            "M": qrcode.constants.ERROR_CORRECT_M,
            "Q": qrcode.constants.ERROR_CORRECT_Q,
            "H": qrcode.constants.ERROR_CORRECT_H,
        }
        return mapping.get(self.ec_var.get(), qrcode.constants.ERROR_CORRECT_M)

    # resize window to fit preview/content
    def _resize_window_to_content(self):
        self.update_idletasks()

        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()

        # Keep within screen bounds
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        # Leave a little margin so it doesn't touch screen edges
        w = min(req_w, screen_w - 80)
        h = min(req_h, screen_h - 120)

        self.geometry(f"{w}x{h}")

    def generate_qr_code(self):
        try:
            payload = self._get_payload()
        except ValueError as e:
            messagebox.showwarning("Input required", str(e))
            return

        ec = self._get_error_correction_const()
        target_px = int(self.size_var.get())

        qr = qrcode.QRCode(
            version=None,
            error_correction=ec,
            box_size=10,
            border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        img = img.resize((target_px, target_px), Image.NEAREST)

        self.qr_pil_image = img
        self.qr_tk_image = ImageTk.PhotoImage(img)

        self.preview_label.configure(image=self.qr_tk_image, text="")

        #auto-fit preview area/window to QR size
        #self._resize_window_to_content()

    def save_qr_code(self):
        if self.qr_pil_image is None:
            messagebox.showinfo("Nothing to save", "Generate a QR code first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
        )
        if file_path:
            self.qr_pil_image.save(file_path)


if __name__ == "__main__":
    app = QRCodeGenerator()
    app.mainloop()
