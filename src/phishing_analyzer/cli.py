import argparse
from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers
from phishing_analyzer.corpus import scan_directory


def main():
    parser = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Analyze an email file for phishing indicators.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a .eml file, or a directory of emails to scan in batch",
    )
    parser.add_argument(
        "--all-headers",
        action="store_true",
        help="Also print every raw header (single-file mode only)",
    )
    args = parser.parse_args()

    if not args.path.exists():
        parser.error(f"Path not found: {args.path}")

    if args.path.is_dir():
        _run_batch(args.path)
    else:
        _run_single(args.path, show_all=args.all_headers)


def _run_batch(directory: Path):
    summary = scan_directory(directory)
    print(f"Scanned {summary.total} files in {directory}\n")
    print(f"  parsed: {summary.count('parsed')}")
    print(f"  empty:  {summary.count('empty')}")
    print(f"  error:  {summary.count('error')}")

    # Surface the problem files so failures are visible, not silently swallowed.
    problems = [r for r in summary.results if r.status != "parsed"]
    if problems:
        shown = min(len(problems), 10)
        print(f"\nFirst issues ({shown} of {len(problems)}):")
        for r in problems[:10]:
            print(f"  [{r.status}] {r.path.name}: {r.detail}")

    # Data-quality note: files that parsed but still had no From header.
    no_from = [r for r in summary.results if r.status == "parsed" and r.detail]
    if no_from:
        print(f"\nNote: {len(no_from)} parsed message(s) had no From header.")


def _run_single(path: Path, show_all: bool):
    try:
        msg = load_email(path)
    except Exception as e:
        print(f"Could not parse {path}: {type(e).__name__}: {e}")
        return

    if show_all:
        print(f"All headers in {path}:\n")
        for name, value in msg.items():
            print(f"{name}: {value}")
        print()

    headers = extract_headers(msg)
    print(f"Key headers in {path}:\n")
    _print_addresses("From", headers.from_addrs)
    _print_addresses("To", headers.to_addrs)
    _print_addresses("Reply-To", headers.reply_to)
    _print_addresses("Return-Path", headers.return_path)
    print(f"{'Subject:':<13} {headers.subject}")
    print(f"{'Date:':<13} {headers.date}")
    print(f"{'Message-ID:':<13} {headers.message_id}")


def _print_addresses(label, addresses):
    if not addresses:
        print(f"{label + ':':<13} (none)")
        return
    for addr in addresses:
        name = addr.display_name or "(no display name)"
        print(f"{label + ':':<13} {name}  <{addr.address}>  [domain: {addr.domain}]")


if __name__ == "__main__":
    main()