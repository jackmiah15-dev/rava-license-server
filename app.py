from __future__ import annotations
import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import queue
import signal
import sys
import tempfile
import threading
import time
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
import contextlib


# --- Third-party (must be installed) ---
# pip install PyQt5 psutil pystray pillow iqoptionapi
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QMessageBox, QHBoxLayout
)
import psutil
from PIL import Image, ImageDraw
import pystray

# --- Broker libs (user-provided) ---
# Ensure these are installed/available in the environment/executable.
try:
    from iqoptionapi.stable_api import IQ_Option
except Exception:
    IQ_Option = None  # Avoid crash at import; fail later with clear message.

try:
    from ejtraderIQ import IQOption as EJ_IQOption
except Exception:
    EJ_IQOption = None

# ========== Paths & Config ==========

def get_app_dirs() -> Tuple[Path, Path]:
    """Return (config_dir, log_dir) in a canonical, per-user location."""
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        root = base / "Rava"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support" / "Rava"
    else:
        root = Path.home() / ".config" / "rava"
    cfg = root
    logs = root / "logs"
    cfg.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    return cfg, logs


CONFIG_DIR, LOG_DIR = get_app_dirs()
CONFIG_FILE = CONFIG_DIR / "config.json"
LOCK_FILE = Path(tempfile.gettempdir()) / "rava.lock"
LOG_FILE = LOG_DIR / f"rava_{datetime.now():%Y-%m-%d}.log"


@dataclass
class RavaConfig:
    username: str
    password: str
    account_type: str  # PRACTICE | REAL
    start_amount: float
    profit_ratio: float
    asset: str
    license_key: str = ""

    def validate(self) -> None:
        """Raise ValueError on invalid input. Keeps GUI & bot aligned."""
        acct = self.account_type.strip().upper()
        if acct not in {"PRACTICE", "REAL"}:
            raise ValueError("Account Type must be PRACTICE or REAL.")
        if not self.username.strip() or not self.password:
            raise ValueError("Username and Password are required.")
        if self.start_amount <= 0:
            raise ValueError("Start Amount must be > 0.")
        if not (0.01 <= self.profit_ratio <= 2.0):
            # Why: unrealistic profit ratios cause math issues or absurd compounding.
            raise ValueError("Profit Ratio must be between 0.01 and 2.0.")
        if not self.asset.strip():
            raise ValueError("Asset is required.")
        if acct == "REAL" and not self.license_key.strip():
            raise ValueError("License Key is required for REAL accounts.")

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "RavaConfig":
        return RavaConfig(
            username=d.get("username", "").strip(),
            password=d.get("password", ""),
            account_type=d.get("account_type", "PRACTICE").strip(),
            start_amount=float(d.get("start_amount", 1.0)),
            profit_ratio=float(d.get("profit_ratio", 0.8)),
            asset=d.get("asset", "GBPUSD-OTC").strip(),
            license_key=d.get("license_key", "").strip(),
        )


class ConfigManager:
    """Single source of truth. GUI always saves here; bot uses in-memory object."""

    @staticmethod
    def load() -> Optional[RavaConfig]:
        if not CONFIG_FILE.exists():
            return None
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            d = json.load(f)
        return RavaConfig.from_dict(d)

    @staticmethod
    def save(cfg: RavaConfig) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with CONFIG_FILE.open("w", encoding="utf-8") as f:
            json.dump(cfg.to_dict(), f, indent=4)


# ========== Logging ==========

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s — %(levelname)s — %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.info("Logging initialized.")


# ========== Single Instance Guard ==========

class SingleInstance:
    """Cross-platform single instance using lock file + pid check."""

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            return psutil.pid_exists(pid)
        except Exception:
            # Fallback: try signal 0 (posix only)
            try:
                os.kill(pid, 0)
                return True
            except Exception:
                return False

    @classmethod
    def acquire(cls) -> None:
        if LOCK_FILE.exists():
            try:
                old_pid = int(LOCK_FILE.read_text().strip())
            except Exception:
                old_pid = -1
            if cls._pid_alive(old_pid):
                raise RuntimeError("Rava is already running.")
            else:
                try:
                    LOCK_FILE.unlink()
                except Exception:
                    pass
        LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")
        logging.info("Lock acquired.")

    @staticmethod
    def release() -> None:
        try:
            if LOCK_FILE.exists():
                LOCK_FILE.unlink()
                logging.info("Lock released.")
        except Exception:
            pass


import certifi
import requests

API_BASE = "https://rava-license-server.onrender.com/api"

def validate_license(email: str, license_key: str) -> Tuple[bool, str]:
    """
    Validate license against the backend API.
    Returns (is_valid, status_message).
    """
    try:
        url = f"{API_BASE}/check_license?email={email}&key={license_key}"
        res = requests.get(url, timeout=8, verify=certifi.where())  # ✅ SSL fix here
        data = res.json()

        status = data.get("status")
        if status == "valid":
            return True, f"License valid until {data.get('expires_on', '?')}"
        elif status == "expired":
            return False, "License expired"
        elif status == "pending":
            return False, "License pending approval"
        elif status == "rejected":
            return False, "License rejected"
        else:
            return False, f"Invalid: {data.get('message', 'Unknown error')}"

    except requests.exceptions.SSLError as e:
        logging.error("SSL certificate verification failed: %s", e)
        return False, "SSL certificate verification failed — please check your network or system time."
    except ValueError:
        logging.error("Invalid JSON from license server.")
        return False, "Invalid response from license server."
    except Exception as e:
        logging.error("License check failed: %s", e)
        return False, "License server error"


# ========== Tray Icon Controller ==========

class TrayController:
    """System tray with Quit; communicates via a shared shutdown event."""

    def __init__(self, shutdown_event: threading.Event):
        self._shutdown_event = shutdown_event
        self._icon: Optional[pystray.Icon] = None
        self._lock = threading.Lock()
        self._status = "RAVA — idle"
        self._color = (0, 200, 0)
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _circle(color: Tuple[int, int, int]) -> Image.Image:
        img = Image.new("RGBA", (64, 64), (255, 255, 255, 0))
        dc = ImageDraw.Draw(img)
        dc.ellipse((8, 8, 56, 56), fill=color)
        return img

    def _quit(self, *_):
        # Why: quit from tray must stop bot & GUI cleanly.
        self._shutdown_event.set()
        if self._icon:
            self._icon.stop()

    def _run(self):
        menu = pystray.Menu(pystray.MenuItem("Quit Rava", self._quit))
        self._icon = pystray.Icon("RAVA", self._circle(self._color), self._status, menu)
        self._icon.run()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def update(self, status: Optional[str] = None, color: Optional[Tuple[int, int, int]] = None):
        with self._lock:
            if status is not None:
                self._status = status
            if color is not None:
                self._color = color
            if self._icon:
                self._icon.icon = self._circle(self._color)
                self._icon.title = self._status


# ========== Bot Runner (async) ==========

class RavaBot:
    """Async trading bot using in-memory config and a shared shutdown event."""

    def __init__(self, cfg: RavaConfig, shutdown_event: threading.Event, tray: TrayController):
        self.cfg = cfg
        self.shutdown_event = shutdown_event
        self.tray = tray
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()

    def start(self):
        """Launch bot in its own thread with its own event loop."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._started.set()
        try:
            self._loop.run_until_complete(self._main_async())
        finally:
            try:
                SingleInstance.release()
            finally:
                if self._loop and self._loop.is_running():
                    self._loop.stop()

    async def _to_thread(self, fn, *args, **kwargs):
        return await asyncio.to_thread(fn, *args, **kwargs)

    async def _main_async(self):
        logging.info("Bot starting...")
        self.tray.update("RAVA — starting...", (255, 215, 0))

        # License
        if self.cfg.account_type.upper() == "REAL":
            ok, msg = validate_license(self.cfg.username, self.cfg.license_key)
            if not ok:
                logging.error(msg)
                self.tray.update(msg, (255, 0, 0))
                return
            else:
                logging.info(msg)
        else:
            logging.info("PRACTICE account — license check skipped.")

        # Brokers
        if IQ_Option is None:
            logging.error("iqoptionapi not available.")
            return
        if EJ_IQOption is None:
            logging.error("ejtraderIQ not available.")
            return

        # Connect (in threads to avoid blocking)
        iq = IQ_Option(self.cfg.username, self.cfg.password)
        if not await self._to_thread(iq.connect):
            logging.error("Failed to connect to IQ Option.")
            return
        if not iq.check_connect():
            logging.error("IQ Option not connected.")
            return
        logging.info("Connected to IQ Option (data).")

        # Switch balance type explicitly (PRACTICE/REAL)
        try:
            balance_type = self.cfg.account_type.upper()
            if balance_type in {"PRACTICE", "REAL"}:
                await self._to_thread(iq.change_balance, balance_type)
                logging.info("Switched account type → %s", balance_type)
            else:
                logging.warning("Unknown account type: %s (defaulting to PRACTICE)", balance_type)
                await self._to_thread(iq.change_balance, "PRACTICE")
        except Exception as exc:
            logging.error("Failed to switch account type: %s", exc)
            return

        try:
            ej = EJ_IQOption(self.cfg.username, self.cfg.password, self.cfg.account_type)
        except Exception as exc:
            logging.error("EJTraderIQ connect error: %s", exc)
            return
        logging.info("Connected to EJTraderIQ (execution).")

        # Precompute compound ladder
        compounds = [round(self.cfg.start_amount, 2)]
        for _ in range(4):
            last = compounds[-1]
            next_amt = round(last + round(last * self.cfg.profit_ratio, 2), 2)
            compounds.append(next_amt)
        logging.info("Compound levels: %s", compounds)

        # Trade loop
        self.tray.update(f"RAVA — trading {self.cfg.asset}", (0, 200, 0))
        await self._trade_loop(iq, compounds)

        logging.info("Bot exiting...")

        # --- New helpers for precise timing & countdown ---
    async def _sleep_until(self, target_ts: float) -> None:
        """Sleep until UNIX timestamp `target_ts`, second-aligned to system clock.
        Why: keeps countdown & scheduling tightly synced to the OS clock.
        """
        while not self.shutdown_event.is_set():
            now = time.time()
            remaining = target_ts - now
            if remaining <= 0:
                return
            # Align to next whole second for top-notch accuracy
            next_tick = math.floor(now) + 1
            sleep_for = min(max(remaining, 0.0), max(next_tick - now, 0.0))
            await asyncio.sleep(sleep_for if sleep_for > 0 else 0)

    async def _countdown_worker(self, period: int = 300) -> None:
        """Continuously log `Next trade cycle in Xs` every second, synced to system clock."""
        try:
            while not self.shutdown_event.is_set():
                now = time.time()
                next_mark = ((int(now) // period) + 1) * period
                remaining = int(max(0, round(next_mark - now)))
                logging.info("Next trade cycle in %ds", remaining)
                # Sleep exactly to the next whole second boundary
                next_sec = math.floor(now) + 1
                await asyncio.sleep(max(0.0, next_sec - time.time()))
        except asyncio.CancelledError:
            return

    # ========== Adjusted Trade Loop (with continuous countdown) ==========
    async def _trade_loop(self, iq, compounds):
        trade_active = False
        compound_index = 0
        in_recovery = False
        compound_index_before_recovery = 0
        recovery_amount = self.cfg.start_amount
        asset = self.cfg.asset
        pr = self.cfg.profit_ratio
        period = 300  # 5m
        settle_sec = 2  # small buffer after candle close

        # Start continuous per-second countdown logger
        countdown_task = asyncio.create_task(self._countdown_worker(period))

        # Anchor to the NEXT 5-minute boundary
        now = time.time()
        cycle_epoch = ((int(now) // period) + 1) * period

        try:
            while not self.shutdown_event.is_set() and compound_index < len(compounds):
                # Wait exactly until the cycle start (5-minute boundary)
                await self._sleep_until(cycle_epoch)
                if self.shutdown_event.is_set():
                    break

                # If a trade is somehow still active at boundary, skip this cycle to avoid overlap
                if trade_active:
                    logging.warning("Boundary @ %s reached but previous trade still active; skipping this cycle.",
                                    datetime.fromtimestamp(cycle_epoch).strftime("%H:%M:%S"))
                    cycle_epoch += period
                    continue

                # Balance
                try:
                    bal = iq.get_balance()
                except Exception as exc:
                    logging.warning("Balance read error: %s; retrying next cycle.", exc)
                    cycle_epoch += period
                    continue
                logging.info("Balance: $%.2f", bal)

                # Signal (based on the candle that just closed at cycle_epoch)
                signal, prev = await self._to_thread(self._generate_signal, iq, asset)
                if signal is None:
                    logging.info("No signal at boundary %s; deferring to next cycle.",
                                 datetime.fromtimestamp(cycle_epoch).strftime("%H:%M:%S"))
                    cycle_epoch += period
                    continue

                trade_amt = recovery_amount if in_recovery else compounds[compound_index]
                mode = "Recovery" if in_recovery else f"Compound {compound_index + 1}"
                logging.info("Signal=%s | Amount=$%.2f | Mode=%s", signal, trade_amt, mode)

                # STRICT EXPIRY: always next candle close. Use safety buffer check.
                expiry_min = self.get_expiry_minutes(5, min_buffer_sec=10)
                if expiry_min is None:
                    logging.warning("Too close to candle close; skipping this cycle.")
                    cycle_epoch += period
                    continue

                # Place trade ASAP after boundary
                try:
                    direction = "call" if signal == "CALL" else "put"
                    ok, trade_id = iq.buy(trade_amt, asset, direction, expiry_min)
                    placed_ts = time.time()
                    placed_str = datetime.fromtimestamp(placed_ts).strftime("%H:%M:%S.%f")[:-3]
                    if not ok:
                        logging.warning("Trade placement failed at %s; deferring to next cycle.", placed_str)
                        cycle_epoch += period
                        continue

                    next_close_ts = cycle_epoch + period
                    expiry_time = datetime.fromtimestamp(next_close_ts).strftime("%H:%M:%S")
                    remaining_seconds = int(max(0, round(next_close_ts - placed_ts)))

                    logging.info(
                        "Trade placed @ %s: %s $%.2f expiry @ %s (%ds left)",
                        placed_str, signal, trade_amt, expiry_time, remaining_seconds
                    )
                    self.tray.update(f"{asset} {signal} ${trade_amt:.2f} [{mode}]", (0, 120, 255))
                    trade_active = True
                except Exception as exc:
                    logging.error("Trade error: %s", exc)
                    cycle_epoch += period
                    continue

                # Wait precisely until expiry (next boundary) + small settlement buffer
                await self._sleep_until(next_close_ts + settle_sec)
                if self.shutdown_event.is_set():
                    break

                # Fetch result
                try:
                    new_bal = iq.get_balance()
                except Exception as exc:
                    logging.warning("Balance read error after expiry: %s", exc)
                    new_bal = bal  # fall back; treated as no change

                payout = new_bal - bal
                real_win = payout > 0
                real_loss = payout < 0
                logical_win = (signal == "CALL" and prev["close"] > prev["open"]) or \
                              (signal == "PUT" and prev["close"] < prev["open"]) 

                if real_win:
                    logging.info("[WIN] +$%.2f", payout)
                    self.tray.update(f"WIN +${payout:.2f}", (0, 200, 0))
                    if in_recovery:
                        in_recovery = False
                        compound_index = compound_index_before_recovery + 1
                    else:
                        compound_index += 1
                elif real_loss:
                    logging.info("[LOSS] -$%.2f", -payout)
                    self.tray.update(f"LOSS -${-payout:.2f}", (255, 0, 0))
                    if not in_recovery:
                        compound_index_before_recovery = compound_index
                    in_recovery = True
                    recovery_amount = round((trade_amt + (trade_amt * pr)) / max(pr, 1e-6), 2)
                else:
                    logging.info("[NO CHANGE]")

                if logical_win and real_loss:
                    logging.warning("[MISMATCH] Logical win but real loss (slippage?)")

                trade_active = False
                # Advance to next cycle boundary
                cycle_epoch += period

            logging.info("Trade loop done.")
            self.tray.update("RAVA — stopped", (120, 120, 120))
        finally:
            # Stop countdown task
            if countdown_task and not countdown_task.done():
                countdown_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await countdown_task



    @staticmethod
    def _generate_signal(iq, asset):
        tf = 300
        now = int(time.time())
        prev_candle_time = now - (now % tf) - tf
        candles = iq.get_candles(asset, tf, 3, prev_candle_time)
        if not candles:
            return None, None
        prev = candles[-1]
        if prev["close"] > prev["open"]:
            return "CALL", prev
        if prev["close"] < prev["open"]:
            return "PUT", prev
        return None, prev

    @staticmethod
    def get_expiry_minutes(interval_minutes: int, min_buffer_sec: int = 10) -> Optional[int]:
        """
        Always expire exactly at the *next* candle close for the given interval.
        Uses CEIL to prevent accidental 4-minute expiries.
        If we are too close to the boundary (within min_buffer_sec), skip this cycle.
        """
        now = time.time()
        period = interval_minutes * 60
        next_candle = ((int(now) // period) + 1) * period
        remaining_seconds = next_candle - now

        if remaining_seconds < min_buffer_sec:
            return None  # too close; try next cycle

        # CEIL ensures e.g. 4m20s left → 5 minutes expiry, not 4
        expiry_minutes = int(math.ceil(remaining_seconds / 60.0))
        return expiry_minutes



# ========== GUI (PyQt5) ==========

class RavaGUI(QWidget):
    """Single GUI that edits config, runs/stops bot, and keeps everything in sync."""

    bot_started = pyqtSignal()
    bot_stopped = pyqtSignal()

    def __init__(self, shutdown_event: threading.Event, tray: TrayController):
        super().__init__()
        self.shutdown_event = shutdown_event
        self.tray = tray
        self.bot: Optional[RavaBot] = None

        self.setWindowTitle("RAVA™ — Elite Trader")
        self.setGeometry(500, 200, 420, 520)

        layout = QVBoxLayout()

        # Username
        layout.addWidget(QLabel("Username (email):"))
        self.username = QLineEdit()
        layout.addWidget(self.username)

        # Password
        layout.addWidget(QLabel("Password:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        # Account type
        layout.addWidget(QLabel("Account Type:"))
        self.account_type = QComboBox()
        self.account_type.addItems(["PRACTICE", "REAL"])
        layout.addWidget(self.account_type)

        # License
        layout.addWidget(QLabel("License Key (REAL only):"))
        self.license_key = QLineEdit()
        self.license_key.setPlaceholderText("Required for REAL; ignored for PRACTICE")
        layout.addWidget(self.license_key)

        # Start amount
        layout.addWidget(QLabel("Start Amount ($):"))
        self.start_amount = QLineEdit()
        self.start_amount.setPlaceholderText("e.g. 5")
        layout.addWidget(self.start_amount)

        # Profit ratio
        layout.addWidget(QLabel("Profit Ratio (e.g., 0.85):"))
        self.profit_ratio = QLineEdit()
        self.profit_ratio.setPlaceholderText("0.85")
        layout.addWidget(self.profit_ratio)

        # Asset
        layout.addWidget(QLabel("Asset:"))
        self.asset = QLineEdit()
        self.asset.setPlaceholderText("e.g., GBPUSD-OTC")
        layout.addWidget(self.asset)

        # Buttons
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start")
        self.stop_btn = QPushButton("🛑 Stop")
        self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        layout.addLayout(btn_row)

        self.setLayout(layout)

        # Events
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.account_type.currentIndexChanged.connect(self._toggle_license)
        self.bot_started.connect(self._on_bot_started)
        self.bot_stopped.connect(self._on_bot_stopped)

        # Prefill from existing config if present
        self._load_existing()
        self._toggle_license()

    def _load_existing(self):
        cfg = ConfigManager.load()
        if not cfg:
            return
        self.username.setText(cfg.username)
        self.password.setText(cfg.password)
        self.account_type.setCurrentText(cfg.account_type.upper())
        self.license_key.setText(cfg.license_key)
        self.start_amount.setText(str(cfg.start_amount))
        self.profit_ratio.setText(str(cfg.profit_ratio))
        self.asset.setText(cfg.asset)

    def _toggle_license(self):
        is_PRACTICE = self.account_type.currentText().upper() == "PRACTICE"
        self.license_key.setDisabled(is_PRACTICE)
        if is_PRACTICE:
            self.license_key.setPlaceholderText("Ignored in PRACTICE")
        else:
            self.license_key.setPlaceholderText("Required for REAL")

    def _read_config_from_ui(self) -> RavaConfig:
        cfg = RavaConfig(
            username=self.username.text().strip(),
            password=self.password.text(),
            account_type=self.account_type.currentText().strip(),
            start_amount=float(self.start_amount.text().strip()),
            profit_ratio=float(self.profit_ratio.text().strip()),
            asset=self.asset.text().strip(),
            license_key=self.license_key.text().strip(),
        )
        cfg.validate()
        return cfg

    def on_start(self):
        try:
            cfg = self._read_config_from_ui()
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", str(e))
            return
        except Exception:
            QMessageBox.warning(self, "Invalid Input", "Please fill all fields correctly.")
            return

        # Persist immediately (always rewritable)
        ConfigManager.save(cfg)

        # Enforce single instance
        try:
            SingleInstance.acquire()
        except RuntimeError as e:
            QMessageBox.warning(self, "Already Running", str(e))
            return

        # Start tray (idempotent)
        self.tray.update("RAVA — starting...", (255, 215, 0))

        # Start bot
        self.bot = RavaBot(cfg, self.shutdown_event, self.tray)
        self.bot.start()
        self.bot_started.emit()

    def on_stop(self):
        self.shutdown_event.set()
        self.tray.update("RAVA — stopping...", (255, 120, 0))
        self.bot_stopped.emit()

    def _on_bot_started(self):
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def _on_bot_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


# ========== Entrypoint ==========

def main():
    # Logging first
    setup_logging()

    # Global shutdown event (tray + GUI + bot share it)
    shutdown_event = threading.Event()

    # Trap Ctrl+C and OS signals
    def _sig_handler(signum, _):
        logging.info("Signal %s received; shutting down...", signum)
        shutdown_event.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _sig_handler)
        except Exception:
            pass

    # Tray
    tray = TrayController(shutdown_event)
    tray.start()

    # GUI
    app = QApplication(sys.argv)
    gui = RavaGUI(shutdown_event, tray)
    gui.show()

    # When shutdown_event is set (e.g., tray quit), close GUI too.
    def _watch_shutdown():
        shutdown_event.wait()
        gui.close()
    threading.Thread(target=_watch_shutdown, daemon=True).start()

    code = app.exec_()
    # Ensure lock released if GUI-initiated stop
    SingleInstance.release()
    sys.exit(code)


if __name__ == "__main__":
    main()

