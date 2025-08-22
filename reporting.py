from __future__ import annotations
import os
import time
import threading

from .config import Config
from .storage import DataStore


class Reporter(threading.Thread):
    def __init__(self, store: DataStore, config: Config):
        super().__init__(daemon=True)
        self.store = store
        self.config = config
        os.makedirs(self.config.report_dir, exist_ok=True)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            self.export_once()
            self._stop.wait(self.config.report_interval_sec)

    def export_once(self):
        df = self.store.snapshot()
        if df.empty:
            return
        ts = int(time.time())
        csv_path = os.path.join(self.config.report_dir, f"dns_events_{ts}.csv")
        json_path = os.path.join(self.config.report_dir, f"dns_events_{ts}.json")
        try:
            df.to_csv(csv_path, index=False)
            df.to_json(json_path, orient='records')
        except Exception:
            pass
