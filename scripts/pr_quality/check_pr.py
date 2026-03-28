#!/usr/bin/env python3
"""
PR quality checks for Django pull requests.

Each check is an independent function that returns None on success, or an
error message on failure. All checks are run so that all issues are reported
in a single pass.

Usage:
    python check_pr.py --repo django/django --pr-number 1234

Environment variables:
    GITHUB_TOKEN  GitHub API token (required)
    PR_BODY       Pull request body text (optional, defaults to empty string)
"""

import argparse
import csv
import io
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

GITHUB_PER_PAGE = 100
MESSAGES_DIR = Path(__file__).parent / "messages"
MIN_WORDS = 5
SENTINEL = object()
TRAC_TIMEOUT_SECONDS = 15


def _setup_logging(logger):
    if not os.environ.get("GITHUB_ACTIONS"):
        return

    class GHAFormatter(logging.Formatter):
        _PREFIXES = {
            logging.DEBUG: "::debug::",
            logging.WARNING: "::warning::",
            logging.ERROR: "::error::",
        }

        def format(self, record):
            msg = super().format(record)
            prefix = self._PREFIXES.get(record.levelno, "")
            return f"{prefix}{msg}"

    handler = logging.StreamHandler()
    handler.setFormatter(GHAFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


logger = logging.getLogger(__name__)
_setup_logging(logger)


def load_message(filename: str, **kwargs) -> str:
    """Load a message file and substitute {variable} placeholders."""
    text = (MESSAGES_DIR / filename).read_text()
    return text.format_map(kwargs) if kwargs else text


def github_request(
    method: str,
    path: str,
    token: str,
    repo: str,
    data: dict | None = None,
) -> object:
    """Make an authenticated GitHub API request."""
    url = f"https://api.github.com/repos/{repo}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read())


def get_pr_files(pr_number: str, repo: str, token: str) -> list[str]:
    """Return all filenames changed in the PR, handling pagination."""
    files: list[str] = []
    page = 1
    while True:
        results = github_request(
            "GET",
            f"/pulls/{pr_number}/files?per_page={GITHUB_PER_PAGE}&page={page}",
            token,
            repo,
        )
        if not results:
            break
        files.extend(f["filename"] for f in results)
        if len(results) < GITHUB_PER_PAGE:
            break
        page += 1
    return files


def rewrite_ticket_links(pr_body: str) -> str:
    """Replace bare ticket-XXXXXX references with Markdown links.

    Already-linked references (e.g. [ticket-123](...)) are left untouched via
    a negative lookbehind that skips matches preceded by '['.
    """
    return re.sub(
        r"(?<!\[)\bticket-(\d+)\b",
        r"[ticket-\1](https://code.djangoproject.com/ticket/\1)",
        pr_body,
        flags=re.IGNORECASE,
    )


def check_trac_ticket(pr_body: str, pr_files: list[str]) -> str | None:
    """A Trac ticket must be referenced.

    Exceptions:
    - If the PR only touches files under docs/, no ticket is required.
    - If the ticket section contains "N/A", the PR is treated as trivial
      (e.g. a typo fix) and no ticket is required.
    """
    if pr_files and all(f.startswith("docs/") for f in pr_files):  # docs-only PR
        return None

    # Look for the ticket reference inside the Trac ticket number section.
    section_match = re.search(
        r"#### Trac ticket number[^\n]*\n(.*?)(?=\r?\n####|\Z)", pr_body, re.DOTALL
    )
    section = section_match.group(1) if section_match else pr_body

    # Strip HTML comments before checking -- the template itself contains "N/A"
    # inside a comment, which would otherwise trigger the N/A exemption below.
    section = re.sub(r"<!--.*?-->", "", section, flags=re.DOTALL)

    if re.search(r"\bticket-\d+\b", section, re.IGNORECASE):  # valid ticket found
        return None

    # N/A marks trivial non-docs PRs (e.g. typo fixes) that don't warrant a
    # Trac ticket, per Django's PR template ("N/A - typo").
    if re.search(r"\bN/A\b", section, re.IGNORECASE):
        return None

    return load_message("no_trac_ticket.txt")


def check_trac_status(pr_body: str) -> str | None:
    """The referenced Trac ticket must be in the 'Accepted' stage.

    Fetches ticket data via the public Trac CSV API. Network errors are
    treated as non-fatal so that a Trac outage doesn't block all PRs.
    """
    ticket_match = re.search(r"\bticket-(\d+)\b", pr_body, re.IGNORECASE)
    if not ticket_match:
        return None  # No ticket found; Check 1 already reported that.

    ticket_id = ticket_match.group(1)
    url = f"https://code.djangoproject.com/ticket/{ticket_id}?format=csv"

    try:
        with urllib.request.urlopen(url, timeout=TRAC_TIMEOUT_SECONDS) as response:
            text = response.read().decode()
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code == 404:
            return load_message(
                "invalid_trac_status.txt",
                ticket_id=ticket_id,
                stage="(ticket not found)",
            )
        logger.warning(
            "HTTP %s fetching ticket %s -- skipping Trac status check.",
            code,
            ticket_id,
        )
        return None
    except Exception as exc:
        logger.warning(
            "Could not fetch ticket %s: %s -- skipping Trac status check.",
            ticket_id,
            exc,
        )
        return None

    reader = csv.DictReader(io.StringIO(text))
    row = next(reader, None)
    if row is None:
        logger.warning("Empty CSV for ticket %s -- skipping status check.", ticket_id)
        return None

    stage = row.get("stage", "").strip()
    if stage == "Accepted":
        return None

    return load_message("invalid_trac_status.txt", ticket_id=ticket_id, stage=stage)


def check_trac_has_patch(
    pr_body: str,
    poll_interval: int = 15,
    poll_timeout: int = 600,
) -> str | None:
    """The referenced Trac ticket must have has_patch=1.

    Polls the Trac CSV API every poll_interval seconds for up to poll_timeout
    seconds. Network errors skip the check. If the flag is still unset after
    the timeout, the PR is closed.
    """
    ticket_match = re.search(r"\bticket-(\d+)\b", pr_body, re.IGNORECASE)
    if not ticket_match:
        return None  # No ticket found; Check 1 already reported that.

    ticket_id = ticket_match.group(1)
    url = f"https://code.djangoproject.com/ticket/{ticket_id}?format=csv"
    deadline = time.monotonic() + poll_timeout

    elapsed = 0
    while True:
        logger.info(
            "Checking has_patch flag for ticket-%s (elapsed: %ss) ...",
            ticket_id,
            elapsed,
        )
        try:
            with urllib.request.urlopen(url, timeout=TRAC_TIMEOUT_SECONDS) as response:
                text = response.read().decode()
            reader = csv.DictReader(io.StringIO(text))
            row = next(reader, None)
            if row is not None and row.get("has_patch", "0").strip() == "1":
                logger.info("ticket-%s has_patch flag is set.", ticket_id)
                return None
            logger.info(
                "  has_patch not yet set -- will retry in %ss.",
                poll_interval,
            )
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code == 404:
                return (
                    None  # Ticket not found -- already reported by check_trac_status.
                )
            logger.warning(
                "HTTP %s fetching ticket %s -- skipping has_patch check.",
                code,
                ticket_id,
            )
            return None
        except Exception as exc:
            logger.warning(
                "Could not fetch ticket %s: %s -- skipping has_patch check.",
                ticket_id,
                exc,
            )
            return None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sleep_time = min(poll_interval, remaining)
        time.sleep(sleep_time)
        elapsed += int(sleep_time)

    logger.warning(
        "ticket-%s has_patch flag was not set after %ss.",
        ticket_id,
        poll_timeout,
    )

    return load_message("no_patch_flag.txt", ticket_id=ticket_id)


def check_branch_description(pr_body: str) -> str | None:
    """The branch description must be present, non-placeholder, and at least
    5 words long.
    """
    placeholder = (
        "Provide a concise overview of the issue or rationale behind the"
        " proposed changes."
    )

    description_match = re.search(
        r"#### Branch description[ \t]*\r?\n(.*?)(?=\r?\n####|\Z)", pr_body, re.DOTALL
    )
    if not description_match:
        return load_message("missing_description.txt")

    # Strip HTML comments before evaluating content.
    cleaned = re.sub(
        r"<!--.*?-->", "", description_match.group(1), flags=re.DOTALL
    ).strip()

    if not cleaned or cleaned == placeholder or len(cleaned.split()) < MIN_WORDS:
        return load_message("missing_description.txt")

    return None


def check_ai_disclosure(pr_body: str) -> str | None:
    """Exactly one AI disclosure checkbox must be selected.

    If the "AI tools were used" option is checked, at least 5 words of
    additional description must be present in that section.
    """
    ai_match = re.search(
        r"#### AI Assistance Disclosure[^\n]*\n(.*?)(?=\r?\n####|\Z)",
        pr_body,
        re.DOTALL,
    )
    if not ai_match:
        return load_message("missing_ai_disclosure.txt")

    section = ai_match.group(1)
    no_ai_checked = bool(
        re.search(r"-\s*\[x\].*?No AI tools were used", section, re.IGNORECASE)
    )
    ai_used_checked = bool(
        re.search(r"-\s*\[x\].*?If AI tools were used", section, re.IGNORECASE)
    )

    # Must check exactly one option.
    if no_ai_checked == ai_used_checked:
        return load_message("missing_ai_disclosure.txt")

    if ai_used_checked:
        # Collect any text lines that are not checkboxes lines or comments.
        extra_lines = [
            line.strip()
            for line in section.splitlines()
            if line.strip()
            and not line.strip().startswith("- [")
            and not line.strip().startswith("<!--")
            and not line.strip().endswith("-->")
        ]
        # Ensure PR author includes at least 5 words about their AI use.
        if len(" ".join(extra_lines).split()) < MIN_WORDS:
            return load_message("missing_ai_description.txt")

    return None


def check_checklist(pr_body: str) -> str | None:
    """The first five items in the Checklist section must be checked."""
    checklist_match = re.search(
        r"#### Checklist[ \t]*\r?\n(.*?)(?=\r?\n####|\Z)", pr_body, re.DOTALL
    )
    if not checklist_match:
        return load_message("incomplete_checklist.txt")

    checkboxes = re.findall(r"-\s*\[(.)\]", checklist_match.group(1))

    if len(checkboxes) < 5 or not all(c.lower() == "x" for c in checkboxes[:5]):
        return load_message("incomplete_checklist.txt")

    return None


def write_job_summary(
    pr_number: str, results: list[tuple[str, str | None | object]]
) -> None:
    """Write a Markdown job summary to $GITHUB_STEP_SUMMARY (if available)."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    lines = [
        f"## PR #{pr_number} Quality Check Results\n",
        "| | Check | Result |",
        "| --- | --- | --- |",
    ]
    for name, result in results:
        if result is SENTINEL:
            icon, status = "⏭️", "SENTINEL"
        elif result is None:
            icon, status = "✅", "Passed"
        else:
            icon, status = "❌", "Failed"
        lines.append(f"| {icon} | {name} | {status} |")

    with open(summary_file, "a") as f:
        f.write("\n".join(lines) + "\n")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub repository (owner/name)")
    parser.add_argument("--pr-number", required=True, help="Pull request number")
    parser.add_argument(
        "--patch-poll-interval",
        type=int,
        default=15,
        help="Seconds between has_patch polls (default: 15)",
    )
    parser.add_argument(
        "--patch-poll-timeout",
        type=int,
        default=60,
        help="Maximum seconds to wait for has_patch (default: 60)",
    )
    args = parser.parse_args(argv)

    token = os.environ["GITHUB_TOKEN"]
    pr_body = os.environ.get("PR_BODY", "")

    pr_files = get_pr_files(args.pr_number, args.repo, token)

    # Docs-only PRs are exempt from all quality checks.
    if pr_files and all(f.startswith("docs/") for f in pr_files):
        logger.info("PR #%s only touches docs/ -- skipping all checks.", args.pr_number)
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            with open(summary_file, "a") as f:
                f.write(f"## PR #{args.pr_number} Quality Check Results\n\n")
                f.write("> Docs-only PR -- all quality checks SENTINEL.\n")
        return

    # Rewrite bare ticket references to Markdown links.
    rewritten = rewrite_ticket_links(pr_body)
    if rewritten != pr_body:
        logger.info(
            "Updating PR #%s body to linkify ticket references.", args.pr_number
        )
        github_request(
            "PATCH", f"/pulls/{args.pr_number}", token, args.repo, {"body": rewritten}
        )
        pr_body = rewritten

    ticket_result = check_trac_ticket(pr_body, pr_files)
    if ticket_result is None:
        status_result = check_trac_status(pr_body)
        has_patch_result = check_trac_has_patch(
            pr_body,
            poll_interval=args.patch_poll_interval,
            poll_timeout=args.patch_poll_timeout,
        )
    else:
        logger.info("No Trac ticket -- skipping status and has_patch checks.")
        status_result = SENTINEL
        has_patch_result = SENTINEL

    results = [
        ("Trac ticket referenced", ticket_result),
        ("Trac ticket status is Accepted", status_result),
        ("Trac ticket has_patch flag set", has_patch_result),
        ("Branch description provided", check_branch_description(pr_body)),
        ("AI disclosure completed", check_ai_disclosure(pr_body)),
        ("Checklist completed", check_checklist(pr_body)),
    ]
    write_job_summary(args.pr_number, results)

    failures = [msg for _, msg in results if msg is not None and msg is not SENTINEL]

    if not failures:
        logger.info("PR #%s passed all quality checks.", args.pr_number)
        return

    logger.warning(
        "PR #%s failed %s check(s). Commenting and closing.",
        args.pr_number,
        len(failures),
    )

    header = load_message("closing_header.txt")
    footer = load_message("closing_footer.txt")
    separator = "\n\n---\n\n"
    comment_body = separator.join([header, *failures, footer])

    github_request(
        "POST",
        f"/issues/{args.pr_number}/comments",
        token,
        args.repo,
        {"body": comment_body},
    )
    github_request(
        "PATCH", f"/pulls/{args.pr_number}", token, args.repo, {"state": "closed"}
    )


if __name__ == "__main__":
    main()
