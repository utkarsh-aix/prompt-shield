#!/usr/bin/env python3
"""
cli.py — Command-line interface for Prompt Shield.

Usage examples
--------------
# Evaluate a single prompt:
    python -m prompt_shield.cli "Ignore previous instructions"

# Interactive REPL mode:
    python -m prompt_shield.cli --interactive

# Output as JSON (useful for piping):
    python -m prompt_shield.cli --json "reveal system prompt"
"""

from __future__ import annotations

import argparse
import json
import sys

from prompt_shield.logging_setup import setup_logging
from prompt_shield.main import PromptShield


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and run the shield.

    Returns
    -------
    int
        Exit code: 0 (allowed/warned), 1 (blocked), 2 (error).
    """
    setup_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    shield = PromptShield()

    if args.interactive:
        return _repl(shield, json_mode=args.json)

    if not args.prompt:
        parser.print_help()
        return 2

    prompt_text = " ".join(args.prompt)
    return _evaluate_and_print(shield, prompt_text, json_mode=args.json)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evaluate_and_print(shield: PromptShield, text: str, *, json_mode: bool) -> int:
    result = shield.evaluate(text)

    if json_mode:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _pretty_print(result)

    return 1 if result.status == "BLOCKED" else 0


def _pretty_print(result) -> None:
    """Render a ShieldResult in a human-friendly table."""
    status_icon = {
        "ALLOWED": "✅",
        "WARNED":  "⚠️ ",
        "BLOCKED": "🚫",
    }.get(result.status, "❓")

    print("\n" + "=" * 50)
    print(f"  {status_icon}  STATUS     : {result.status}")
    print(f"     RISK SCORE : {result.risk_score}")
    print(f"     RISK LEVEL : {result.risk_level}")
    print(f"     REASON     : {result.reason}")
    if result.matched_patterns:
        print(f"     PATTERNS   : {', '.join(result.matched_patterns)}")
    print("=" * 50 + "\n")


def _repl(shield: PromptShield, *, json_mode: bool) -> int:
    """Simple read-eval-print loop for interactive testing."""
    print("Prompt Shield — Interactive Mode  (type 'exit' to quit)\n")
    while True:
        try:
            text = input("prompt> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if text.lower() in {"exit", "quit", "q"}:
            return 0
        if not text:
            continue

        _evaluate_and_print(shield, text, json_mode=json_mode)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt-shield",
        description="Detect and block prompt injection attacks.",
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help="The user prompt to evaluate.",
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Start an interactive REPL session.",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON.",
    )
    return parser


if __name__ == "__main__":
    sys.exit(main())
