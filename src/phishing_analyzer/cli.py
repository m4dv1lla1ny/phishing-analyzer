import argparse
from pathlib import Path

from phishing_analyzer.parser import load_email
from phishing_analyzer.headers import extract_headers


def main():
    parser = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Analyze an email file for phishing indicators.",
    )
    parser.add_argument(
        "email_file",
        type=Path,
        help="Path to the .eml email file to analyze",
    )
    parser.add_argument(
        "--all-headers",
        action="store_true",
        help="Also print every raw header in the message, not just the parsed ones.",
    ) 
    args = parser.parse_args()

    if not args.email_file.exists():
        parser.error(f"File not found: {args.email_file}")

    msg = load_email(args.email_file)

    print(f"All headers in {args.email_file}:\n")
    for name, value in msg.items():
        print(f"{name}: {value}")
    print()

    headers = extract_headers(msg)
    print(f"Key headers in {args.email_file}:\n") 
    _print_addresses("From", headers.from_addrs)
    _print_addresses("To", headers.to_addrs)
    _print_addresses("Reply-To", headers.reply_to)
    _print_addresses("Return-Path", headers.return_path)
    print(f"{'Subject':<13}: {headers.subject}")
    print(f"{'Date':<13}: {headers.date}")
    print(f"{'Message-ID:':<13} {headers.message_id}")

def _print_addresses(label, addresses):
    if not addresses:
        print(f"{label + ':':<13} (none)")
        return
    for addr in addresses:
        name = addr.display_name or "(no display name)"
        print(f"{label + ':':<13} {name} <{addr.address}> [domain: {addr.domain}]")
        



if __name__ == "__main__":
    main()
