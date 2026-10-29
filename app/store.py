"""Expiring, bounded process-local storage for a single-process local demo."""
import secrets
import time
from threading import RLock

class Store:
    def __init__(self, limit=1000):
        self.items, self.lock, self.limit = {}, RLock(), limit

    def put(self, data, ttl=3600):
        with self.lock:
            self.items = {k: v for k, v in self.items.items() if v[0] > time.time()}
            if len(self.items) >= self.limit:
                raise ValueError("Local session store is full; retry after sessions expire")
            key = secrets.token_urlsafe(32)
            self.items[key] = (time.time() + ttl, data)
            return key

    def get(self, key, pop=False):
        with self.lock:
            entry = self.items.pop(key, None) if pop else self.items.get(key)
            if entry and entry[0] > time.time():
                return entry[1]
            self.items.pop(key, None)
            return None
