import argparse
from pathlib import Path

from phishing_analyzer.parser import load_email


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

    msg = load_email(args.email_file)

    print(f"All headers in {args.email_file}:\n")
    for name, value in msg.items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
