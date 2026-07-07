from dataclasses import dataclass, field
from pathlib import Path

from phishing_analyzer.parser import load_email


@dataclass
class FileResult:
    path: Path
    status: str          # "parsed", "empty", or "error"
    detail: str = ""     # error text, or a note like "no From header"


@dataclass
class ScanSummary:
    results: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)


def scan_file(path: Path) -> FileResult:
    """Parse one file without ever raising. Returns a categorized result."""
    try:
        msg = load_email(path)
    except OSError as e:
        return FileResult(path, "error", f"could not read file: {e}")
    except Exception as e:  # parser choked on genuinely malformed input
        return FileResult(path, "error", f"{type(e).__name__}: {e}")

# The email parser is lenient: feed it garbage and it still returns an
# EmailMessage object, just with (almost) no headers. Treat a header-less 
# message as "empty" rather than pretending it parsed cleanly.
    if len(msg.keys()) == 0:
        return FileResult(path, "empty", "no headers found")

    if msg["from"] is None:
        return FileResult(path, "parsed", "no From header")

    return FileResult(path, "parsed")


def scan_directory(directory: Path) -> ScanSummary:
    """Recursively scan a directory of email files. Skips subdirs and hidden files."""
    summary = ScanSummary()
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        summary.results.append(scan_file(path))
    return summary


