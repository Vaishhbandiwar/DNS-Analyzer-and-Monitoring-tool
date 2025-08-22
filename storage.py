from __future__ import annotations
import threading
from typing import List, Dict, Any
import pandas as pd


class DataStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._df = pd.DataFrame(columns=[
            "timestamp", "src_ip", "dst_ip", "domain", "qtype",
            "ips", "ttl", "record_types", "entropy", "umbrella_status", "umbrella_categories",
            "anomalies", "geo"
        ])

    def append_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            # Ensure consistent columns and assign via loc to avoid concat warnings
            row = {col: event.get(col, pd.NA) for col in self._df.columns}
            self._df.loc[len(self._df)] = row
            # Keep dataframe from growing unbounded (sliding window ~50k rows)
            if len(self._df) > 50000:
                self._df = self._df.iloc[-40000:].reset_index(drop=True)

    def snapshot(self) -> pd.DataFrame:
        with self._lock:
            return self._df.copy()

    def recent(self, n: int | None = None) -> pd.DataFrame:
        """Return a copy of the last n rows. If n is None, return all rows.
        Default used to be 500; callers should provide desired sizes.
        """
        with self._lock:
            if n is None:
                return self._df.copy()
            return self._df.tail(n).copy()
