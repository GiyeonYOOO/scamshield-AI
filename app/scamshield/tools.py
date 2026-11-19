"""F3001: register only the existing read-only security lookups."""

from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import monotonic
from typing import Annotated, TypedDict

from dotenv import load_dotenv
from langchain.tools import tool
from pydantic import Field

from api_validation import __main__ as providers


class ToolResult(TypedDict):
    check: str
    ok: bool
    outcome: str
    data: dict | None
    error: dict | None


def build_tools():
    load_dotenv(providers.ENV_PATH)
    google_cache: OrderedDict[str, tuple[float, ToolResult]] = OrderedDict()
    cache_lock = Lock()

    @tool
    def google_safe_browsing(url: str) -> ToolResult:
        """Check the supplied public URL against Google's known threat lists."""
        with cache_lock:
            cached = google_cache.get(url)
            if cached and cached[0] > monotonic():
                google_cache.move_to_end(url)
                return deepcopy(cached[1])
            google_cache.pop(url, None)

        result = providers.run_check("google", url)
        if result["ok"]:
            try:
                duration = float(result["data"]["cache_duration"].removesuffix("s"))
            except ValueError:
                return {
                    "check": "google", "ok": False, "outcome": "INVALID_RESPONSE",
                    "data": None, "error": {"code": "INVALID_RESPONSE", "http_status": 200},
                }
            duration = min(duration, 1800 if result["outcome"] == "MATCH" else 86400)
            if duration > 0:
                with cache_lock:
                    google_cache[url] = (monotonic() + duration, deepcopy(result))
                    if len(google_cache) > 256:
                        google_cache.popitem(last=False)
        return result

    @tool
    def virustotal_url(url: str) -> ToolResult:
        """Read the existing VirusTotal report for the exact public URL."""
        return providers.run_check("vt-url", url)

    @tool
    def virustotal_domain(url: str) -> ToolResult:
        """Read the VirusTotal domain report when host-level evidence is useful."""
        return providers.run_check("vt-domain", url)

    @tool
    def urlscan_history(url: str, days: Annotated[int, Field(ge=1, le=30)]) -> ToolResult:
        """Find existing public scan observations for the supplied URL's host."""
        return providers.run_check("urlscan", url, days)

    return {
        entry.name: entry
        for entry in (google_safe_browsing, virustotal_url, virustotal_domain, urlscan_history)
    }
