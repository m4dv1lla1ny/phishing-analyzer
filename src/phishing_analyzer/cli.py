import argparse
from pathlib import Path


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
    args = parser.parse_args()

    if not args.email_file.exists():
        parser.error(f"File not found: {args.email_file}")

    print(f"Received email file: {args.email_file}")
    print("(Parsing not implemented yet — that's Day 2.)")


if __name__ == "__main__":
    main()
