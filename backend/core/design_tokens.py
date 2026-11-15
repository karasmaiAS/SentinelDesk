import json
from functools import lru_cache
from pathlib import Path

from django.conf import settings


@lru_cache(maxsize=1)
def get_design_tokens():
    token_file = Path(settings.BASE_DIR).parent / "shared" / "design_tokens.json"
    with token_file.open(encoding="utf-8") as file:
        return json.load(file)
