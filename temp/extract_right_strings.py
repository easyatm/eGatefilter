#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


LINE_PATTERN = re.compile(
    r'^\s*"(?P<key>(?:\\.|[^"\\])*)"\s*:\s*"(?P<value>(?:\\.|[^"\\])*)"\s*,?\s*$'
)


def decode_json_string(raw: str) -> str:
    return json.loads(f'"{raw}"')


def extract_right_strings(input_path: Path, output_path: Path) -> int:
    count = 0
    with input_path.open("r", encoding="utf-8") as infile, output_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as outfile:
        for line in infile:
            m = LINE_PATTERN.match(line)
            if not m:
                continue
            value = decode_json_string(m.group("value"))
            outfile.write(value.replace("\r\n", "\\n").replace("\n", "\\n") + "\n")
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Extract right-side strings from lines like: "key": "value",'
    )
    parser.add_argument("input", help="Input text/json file path")
    parser.add_argument(
        "-o",
        "--output",
        help="Output text file path (default: <input>.values.txt)",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if args.output:
        output_path = Path(args.output).resolve()
    else:
        output_path = input_path.with_suffix(input_path.suffix + ".values.txt")

    count = extract_right_strings(input_path, output_path)
    print(f"Done. Extracted {count} lines.")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
