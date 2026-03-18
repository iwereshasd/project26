import json
from pathlib import Path

class OfflineCollector:
    def __init__(self, samples_dir="samples"):
        self.samples_dir = Path(samples_dir)

    def list_containers(self):
        return [f.stem for f in self.samples_dir.glob("*.json")]

    def inspect_container(self, name):
        path = self.samples_dir / f"{name}.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data[0]  # docker inspect всегда возвращает список
