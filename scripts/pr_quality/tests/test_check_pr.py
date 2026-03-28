"""Tests for the PR quality checks in check_pr.py."""

import logging
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import check_pr

# Set dummy env vars required by check_pr at import time.
os.environ.setdefault("GITHUB_TOKEN", "test-token")
os.environ.setdefault("PR_BODY", "")

logger = logging.getLogger("check_pr")


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        null_handler = logging.NullHandler()
        logger.addHandler(null_handler)
        self.addCleanup(logger.removeHandler, null_handler)


NON_DOCS_FILES = ["django/template/base.py", "tests/template_tests/test_base.py"]
DOCS_ONLY_FILES = ["docs/topics/templates.txt", "docs/ref/templates/api.txt"]
MIXED_FILES = ["django/template/base.py", "docs/topics/templates.txt"]


def make_pr_body(
    ticket="ticket-36991",
    description=(
        "Fix regression in template rendering where nested blocks were"
        " incorrectly evaluated."
    ),
    no_ai_checked=True,
    ai_used_checked=False,
    ai_description="",
    checked_items=5,
):
    no_ai_box = "[x]" if no_ai_checked else "[ ]"
    ai_used_box = "[x]" if ai_used_checked else "[ ]"
    ai_extra = f"\n{ai_description}" if ai_description else ""

    checklist_items = [
        "This PR follows the [contribution guidelines]"
        "(https://docs.djangoproject.com/en/stable/internals/contributing/"
        "writing-code/submitting-patches/).",
        "This PR **does not** disclose a security vulnerability"
        " (see [vulnerability reporting]"
        "(https://docs.djangoproject.com/en/stable/internals/security/)).",
        "This PR targets the `main` branch.",
        "The commit message is written in past tense, mentions the ticket"
        " number, and ends with a period (see [guidelines]"
        "(https://docs.djangoproject.com/en/dev/internals/contributing/"
        "committing-code/#committing-guidelines)).",
        "I have not requested, and will not request, an automated AI review"
        " for this PR.",
        'I have checked the "Has patch" ticket flag in the Trac system.',
        "I have added or updated relevant tests.",
        "I have added or updated relevant docs, including release notes if"
        " applicable.",
        "I have attached screenshots in both light and dark modes for any UI"
        " changes.",
    ]
    checklist_lines = "\n".join(
        f"- [x] {item}" if i < checked_items else f"- [ ] {item}"
        for i, item in enumerate(checklist_items)
    )

    # GitHub PR bodies are plain markdown with no leading spaces.
    return (
        f"#### Trac ticket number\n"
        f"<!-- Replace XXXXX with the corresponding Trac ticket number. -->\n"
        f'<!-- Or delete the line and write "N/A - typo" for typo fixes. -->\n'
        f"{ticket}\n"
        f"\n"
        f"#### Branch description\n"
        f"{description}\n"
        f"\n"
        f"#### AI Assistance Disclosure (REQUIRED)\n"
        f"<!-- Please select exactly ONE of the following: -->\n"
        f"- {no_ai_box} **No AI tools were used** in preparing this PR.\n"
        f"- {ai_used_box} **If AI tools were used**, I have disclosed which"
        f" ones, and fully reviewed and verified their output.{ai_extra}\n"
        f"\n"
        f"#### Checklist\n"
        f"{checklist_lines}\n"
    )


VALID_PR_BODY = make_pr_body()


def make_trac_csv(
    ticket_id="36991",
    stage="Accepted",
    has_patch="0",
    needs_docs="0",
    needs_tests="0",
    needs_better_patch="0",
):
    header = (
        "id,summary,reporter,owner,description,type,status,component,version,"
        "severity,resolution,keywords,cc,stage,has_patch,needs_docs,needs_tests,"
        "needs_better_patch,easy,ui_ux"
    )
    row = (
        f"{ticket_id},Some summary,reporter,,description,Bug,new,core,5.0,"
        f"Normal,,,,{stage},{has_patch},{needs_docs},{needs_tests},"
        f"{needs_better_patch},0,0"
    )
    return header + "\n" + row + "\n"


def mock_urlopen(csv_text):
    mock_resp = MagicMock()
    mock_resp.read.return_value = csv_text.encode()
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp
    return MagicMock(return_value=mock_cm)


def make_http_error(status_code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://example.com",
        code=status_code,
        msg="Error",
        hdrs=None,
        fp=None,
    )


class TestRewriteTicketLinks(BaseTestCase):
    def test_plain_reference(self):
        result = check_pr.rewrite_ticket_links("See ticket-12345 for details.")
        self.assertEqual(
            result,
            "See [ticket-12345](https://code.djangoproject.com/ticket/12345)"
            " for details.",
        )

    def test_already_linked_unchanged(self):
        body = (
            "See [ticket-12345](https://code.djangoproject.com/ticket/12345)"
            " for details."
        )
        self.assertEqual(check_pr.rewrite_ticket_links(body), body)

    def test_multiple_references(self):
        body = "Fixes ticket-100 and ticket-200."
        result = check_pr.rewrite_ticket_links(body)
        self.assertIn("[ticket-100](https://code.djangoproject.com/ticket/100)", result)
        self.assertIn("[ticket-200](https://code.djangoproject.com/ticket/200)", result)

    def test_case_insensitive(self):
        result = check_pr.rewrite_ticket_links("See TICKET-99 for details.")
        self.assertIn("https://code.djangoproject.com/ticket/99", result)

    def test_no_ticket_unchanged(self):
        body = "No ticket references here."
        self.assertEqual(check_pr.rewrite_ticket_links(body), body)

    def test_mixed_linked_and_plain(self):
        body = (
            "Already [ticket-1](https://code.djangoproject.com/ticket/1)"
            " and plain ticket-2."
        )
        result = check_pr.rewrite_ticket_links(body)
        self.assertEqual(result.count("ticket-1"), 1)  # not double-linked
        self.assertIn("[ticket-2](https://code.djangoproject.com/ticket/2)", result)


class TestCheckTracTicket(BaseTestCase):
    def test_valid_non_docs_passes(self):
        self.assertIsNone(check_pr.check_trac_ticket(VALID_PR_BODY, NON_DOCS_FILES))

    def test_valid_docs_only_passes(self):
        self.assertIsNone(check_pr.check_trac_ticket(VALID_PR_BODY, DOCS_ONLY_FILES))

    def test_docs_only_no_ticket_passes(self):
        body = make_pr_body(ticket="")
        self.assertIsNone(check_pr.check_trac_ticket(body, DOCS_ONLY_FILES))

    def test_placeholder_fails(self):
        body = make_pr_body(ticket="ticket-XXXXX")
        self.assertIsNotNone(check_pr.check_trac_ticket(body, NON_DOCS_FILES))

    def test_missing_fails(self):
        body = make_pr_body(ticket="")
        self.assertIsNotNone(check_pr.check_trac_ticket(body, NON_DOCS_FILES))

    def test_na_passes(self):
        body = make_pr_body(ticket="N/A - typo")
        self.assertIsNone(check_pr.check_trac_ticket(body, NON_DOCS_FILES))

    def test_na_bare_passes(self):
        body = make_pr_body(ticket="N/A")
        self.assertIsNone(check_pr.check_trac_ticket(body, NON_DOCS_FILES))

    def test_mixed_files_requires_ticket(self):
        body = make_pr_body(ticket="")
        self.assertIsNotNone(check_pr.check_trac_ticket(body, MIXED_FILES))

    def test_mixed_files_with_ticket_passes(self):
        self.assertIsNone(check_pr.check_trac_ticket(VALID_PR_BODY, MIXED_FILES))

    def test_empty_file_list_requires_ticket(self):
        body = make_pr_body(ticket="")
        self.assertIsNotNone(check_pr.check_trac_ticket(body, []))

    def test_various_ticket_lengths_pass(self):
        for ticket in ["ticket-1", "ticket-123", "ticket-999999"]:
            with self.subTest(ticket=ticket):
                body = make_pr_body(ticket=ticket)
                self.assertIsNone(check_pr.check_trac_ticket(body, NON_DOCS_FILES))


class TestCheckTracStatus(BaseTestCase):
    def test_no_ticket_skips_check(self):
        self.assertIsNone(check_pr.check_trac_status("No ticket here."))

    def test_accepted_passes(self):
        csv_text = make_trac_csv(stage="Accepted", has_patch="0")
        with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))

    def test_non_accepted_stages_fail(self):
        for stage in ["Unreviewed", "Ready for Checkin", "Someday/Maybe"]:
            with self.subTest(stage=stage):
                csv_text = make_trac_csv(stage=stage, has_patch="0")
                with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
                    self.assertIsNotNone(check_pr.check_trac_status("ticket-36991"))

    def test_failure_message_contains_ticket_id(self):
        csv_text = make_trac_csv(ticket_id="12345", stage="Unreviewed", has_patch="0")
        with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
            result = check_pr.check_trac_status("ticket-12345")
        self.assertIn("12345", result)

    def test_failure_message_contains_current_stage(self):
        csv_text = make_trac_csv(stage="Unreviewed", has_patch="0")
        with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
            result = check_pr.check_trac_status("ticket-36991")
        self.assertIn("Unreviewed", result)

    def test_http_404_fails(self):
        with patch("urllib.request.urlopen", side_effect=make_http_error(404)):
            self.assertIsNotNone(check_pr.check_trac_status("ticket-99999"))

    def test_network_error_skips_check(self):
        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))

    def test_http_500_skips_check(self):
        with patch("urllib.request.urlopen", side_effect=make_http_error(500)):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))


class TestCheckTracHasPatch(BaseTestCase):
    def test_no_ticket_skips_check(self):
        self.assertIsNone(check_pr.check_trac_has_patch("No ticket here."))

    def test_already_set_passes(self):
        csv_text = make_trac_csv(has_patch="1")
        with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_not_set_times_out_fails(self):
        with (
            patch("urllib.request.urlopen", mock_urlopen(make_trac_csv(has_patch="0"))),
            patch("time.sleep"),
        ):
            result = check_pr.check_trac_has_patch(
                VALID_PR_BODY, poll_timeout=0, poll_interval=0
            )
        self.assertIsNotNone(result)

    def test_failure_message_contains_ticket_id(self):
        with (
            patch(
                "urllib.request.urlopen",
                mock_urlopen(make_trac_csv(ticket_id="36991", has_patch="0")),
            ),
            patch("time.sleep"),
        ):
            result = check_pr.check_trac_has_patch(
                VALID_PR_BODY, poll_timeout=0, poll_interval=0
            )
        self.assertIn("36991", result)

    def test_set_on_second_poll_passes(self):
        responses = [make_trac_csv(has_patch="0"), make_trac_csv(has_patch="1")]
        call_count = [0]

        def mock_urlopen_fn(url, timeout=None):
            mock_resp = MagicMock()
            mock_resp.read.return_value = responses[
                min(call_count[0], len(responses) - 1)
            ].encode()
            call_count[0] += 1
            mock_cm = MagicMock()
            mock_cm.__enter__.return_value = mock_resp
            return mock_cm

        with (
            patch("urllib.request.urlopen", mock_urlopen_fn),
            patch("time.sleep"),
        ):
            self.assertIsNone(
                check_pr.check_trac_has_patch(
                    VALID_PR_BODY, poll_timeout=60, poll_interval=0
                )
            )

    def test_network_error_skips_check(self):
        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_http_500_skips_check(self):
        with patch("urllib.request.urlopen", side_effect=make_http_error(500)):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_http_404_skips_check(self):
        # 404 means ticket not found -- already reported by check_trac_status.
        with patch("urllib.request.urlopen", side_effect=make_http_error(404)):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))


class TestCheckBranchDescription(BaseTestCase):
    def test_valid_passes(self):
        self.assertIsNone(check_pr.check_branch_description(VALID_PR_BODY))

    def test_placeholder_fails(self):
        body = make_pr_body(
            description=(
                "Provide a concise overview of the issue or rationale behind"
                " the proposed changes."
            )
        )
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_empty_fails(self):
        body = make_pr_body(description="")
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_too_short_fails(self):
        body = make_pr_body(description="Fix bug.")
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_exactly_five_words_passes(self):
        body = make_pr_body(description="Fix the template rendering bug.")
        self.assertIsNone(check_pr.check_branch_description(body))

    def test_html_comment_only_fails(self):
        body = make_pr_body(
            description="<!-- Provide a concise overview of the issue -->"
        )
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_html_comment_words_not_counted(self):
        body = make_pr_body(description="<!-- this has five words --> fix")
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_missing_section_header_fails(self):
        body = VALID_PR_BODY.replace("#### Branch description\n", "")
        self.assertIsNotNone(check_pr.check_branch_description(body))

    def test_multiline_passes(self):
        body = make_pr_body(
            description=(
                "This PR fixes a bug in the ORM.\n"
                "The issue affects queries with multiple joins."
            )
        )
        self.assertIsNone(check_pr.check_branch_description(body))

    def test_crlf_line_endings_pass(self):
        body = make_pr_body().replace("\n", "\r\n")
        self.assertIsNone(check_pr.check_branch_description(body))


class TestCheckAIDisclosure(BaseTestCase):
    def test_no_ai_checked_passes(self):
        self.assertIsNone(check_pr.check_ai_disclosure(VALID_PR_BODY))

    def test_ai_used_with_description_passes(self):
        body = make_pr_body(
            no_ai_checked=False,
            ai_used_checked=True,
            ai_description=(
                "Used GitHub Copilot for autocomplete, all output manually reviewed."
            ),
        )
        self.assertIsNone(check_pr.check_ai_disclosure(body))

    def test_neither_option_checked_fails(self):
        body = make_pr_body(no_ai_checked=False, ai_used_checked=False)
        self.assertIsNotNone(check_pr.check_ai_disclosure(body))

    def test_both_options_checked_fails(self):
        body = make_pr_body(no_ai_checked=True, ai_used_checked=True)
        self.assertIsNotNone(check_pr.check_ai_disclosure(body))

    def test_ai_used_no_description_fails(self):
        body = make_pr_body(
            no_ai_checked=False, ai_used_checked=True, ai_description=""
        )
        self.assertIsNotNone(check_pr.check_ai_disclosure(body))

    def test_ai_used_short_description_fails(self):
        body = make_pr_body(
            no_ai_checked=False, ai_used_checked=True, ai_description="Used Copilot."
        )
        self.assertIsNotNone(check_pr.check_ai_disclosure(body))

    def test_ai_used_exactly_five_word_description_passes(self):
        body = make_pr_body(
            no_ai_checked=False,
            ai_used_checked=True,
            ai_description="Used Claude for code review.",
        )
        self.assertIsNone(check_pr.check_ai_disclosure(body))

    def test_missing_section_fails(self):
        body = VALID_PR_BODY.replace("#### AI Assistance Disclosure (REQUIRED)\n", "")
        self.assertIsNotNone(check_pr.check_ai_disclosure(body))

    def test_uppercase_x_in_checkbox_passes(self):
        body = VALID_PR_BODY.replace(
            "- [x] **No AI tools were used**", "- [X] **No AI tools were used**"
        )
        self.assertIsNone(check_pr.check_ai_disclosure(body))


class TestCheckChecklist(BaseTestCase):
    def test_first_five_checked_passes(self):
        self.assertIsNone(check_pr.check_checklist(VALID_PR_BODY))

    def test_all_nine_checked_passes(self):
        body = make_pr_body(checked_items=9)
        self.assertIsNone(check_pr.check_checklist(body))

    def test_none_checked_fails(self):
        body = make_pr_body(checked_items=0)
        self.assertIsNotNone(check_pr.check_checklist(body))

    def test_four_of_five_checked_fails(self):
        body = make_pr_body(checked_items=4)
        self.assertIsNotNone(check_pr.check_checklist(body))

    def test_three_of_five_checked_fails(self):
        body = make_pr_body(checked_items=3)
        self.assertIsNotNone(check_pr.check_checklist(body))

    def test_missing_section_fails(self):
        body = VALID_PR_BODY.replace("#### Checklist\n", "")
        self.assertIsNotNone(check_pr.check_checklist(body))

    def test_uppercase_x_passes(self):
        body = VALID_PR_BODY.replace("- [x]", "- [X]")
        self.assertIsNone(check_pr.check_checklist(body))

    def test_crlf_line_endings_pass(self):
        body = make_pr_body().replace("\n", "\r\n")
        self.assertIsNone(check_pr.check_checklist(body))


class TestIntegration(BaseTestCase):
    def test_fully_valid_pr_passes_all_checks(self):
        csv_text = make_trac_csv(stage="Accepted", has_patch="1")
        for label, body in [
            ("LF line endings", VALID_PR_BODY),
            ("CRLF line endings", VALID_PR_BODY.replace("\n", "\r\n")),
        ]:
            with self.subTest(label=label):
                with patch("urllib.request.urlopen", mock_urlopen(csv_text)):
                    results = [
                        check_pr.check_trac_ticket(body, NON_DOCS_FILES),
                        check_pr.check_trac_status(body),
                        check_pr.check_trac_has_patch(body),
                        check_pr.check_branch_description(body),
                        check_pr.check_ai_disclosure(body),
                        check_pr.check_checklist(body),
                    ]
                failures = [r for r in results if r is not None]
                self.assertEqual(
                    failures,
                    [],
                    f"Expected no failures ({label}), got:\n"
                    + "\n---\n".join(failures),
                )

    def test_blank_body_fails_non_status_checks(self):
        results = [
            check_pr.check_trac_ticket("", NON_DOCS_FILES),
            check_pr.check_branch_description(""),
            check_pr.check_ai_disclosure(""),
            check_pr.check_checklist(""),
        ]
        for i, result in enumerate(results, 1):
            self.assertIsNotNone(result, f"Check {i} should have failed on empty body")

    def test_unedited_template_fails_all_checks(self):
        template_path = (
            Path(__file__).parents[3] / ".github" / "pull_request_template.md"
        )
        with open(template_path) as f:
            raw_template = f.read()
        results = [
            check_pr.check_trac_ticket(raw_template, NON_DOCS_FILES),
            check_pr.check_branch_description(raw_template),
            check_pr.check_ai_disclosure(raw_template),
            check_pr.check_checklist(raw_template),
        ]
        for i, result in enumerate(results, 1):
            self.assertIsNotNone(
                result, f"Check {i} should have failed on raw template"
            )

    def test_docs_only_pr_skips_all_checks(self):
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "test-token", "PR_BODY": ""}),
            patch.object(check_pr, "get_pr_files", return_value=DOCS_ONLY_FILES),
            patch.object(
                check_pr,
                "github_request",
                MagicMock(side_effect=AssertionError("should not call github_request")),
            ),
            self.assertLogs(logger, level="INFO") as logs,
        ):
            check_pr.main(["--repo", "test/repo", "--pr-number", "42"])
        output = "\n".join(logs.output)
        self.assertIn("docs/", output)
        self.assertIn("skipping", output.lower())

    def test_no_ticket_skips_trac_status_and_has_patch(self):
        with (
            patch.dict(
                os.environ,
                {"GITHUB_TOKEN": "test-token", "PR_BODY": ""},
                clear=False,
            ),
            patch.object(check_pr, "get_pr_files", return_value=NON_DOCS_FILES),
            patch.object(check_pr, "github_request", MagicMock()),
            self.assertLogs(logger, level="INFO") as logs,
        ):
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
            check_pr.main(["--repo", "test/repo", "--pr-number", "10"])
        self.assertIn(
            "No Trac ticket -- skipping status and has_patch checks.",
            "\n".join(logs.output),
        )

    def test_no_ticket_results_include_skipped_sentinels(self):
        body = make_pr_body(ticket="")
        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "test-token", "PR_BODY": body}),
            patch.object(check_pr, "get_pr_files", return_value=NON_DOCS_FILES),
            patch.object(check_pr, "write_job_summary") as mock_write,
            patch.object(check_pr, "github_request", MagicMock()),
            self.assertLogs(logger, level="INFO"),
        ):
            check_pr.main(["--repo", "test/repo", "--pr-number", "10"])

        _, results = mock_write.call_args.args
        result_map = dict(results)
        self.assertIs(result_map["Trac ticket status is Accepted"], check_pr.SENTINEL)
        self.assertIs(result_map["Trac ticket has_patch flag set"], check_pr.SENTINEL)


class TestWriteJobSummary(BaseTestCase):
    def test_no_env_var_does_nothing(self):
        with patch.dict(os.environ):
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
            check_pr.write_job_summary(
                "99", [("Some check", None), ("Other check", "failure")]
            )

    def test_all_passed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                results = [
                    ("Trac ticket referenced", None),
                    ("Branch description provided", None),
                ]
                check_pr.write_job_summary("7", results)
            content = summary.read_text()
        self.assertIn("## PR #7 Quality Check Results", content)
        self.assertIn("✅", content)
        self.assertNotIn("❌", content)
        self.assertIn("Trac ticket referenced", content)
        self.assertIn("Branch description provided", content)

    def test_with_failures(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                results = [
                    ("Trac ticket referenced", None),
                    ("Branch description provided", "Missing description"),
                    ("Checklist completed", "Incomplete checklist"),
                ]
                check_pr.write_job_summary("12", results)
            content = summary.read_text()
        self.assertIn("## PR #12 Quality Check Results", content)
        self.assertEqual(content.count("✅"), 1)
        self.assertEqual(content.count("❌"), 2)
        self.assertIn("Passed", content)
        self.assertIn("Failed", content)

    def test_appends_to_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            summary.write_text("## Previous step\n\nSome content.\n")
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                check_pr.write_job_summary("5", [("Checklist completed", None)])
            content = summary.read_text()
        self.assertIn("## Previous step", content)
        self.assertIn("## PR #5 Quality Check Results", content)

    def test_SENTINEL_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                results = [
                    ("Trac ticket referenced", "No ticket found"),
                    ("Trac ticket status is Accepted", check_pr.SENTINEL),
                    ("Trac ticket has_patch flag set", check_pr.SENTINEL),
                ]
                check_pr.write_job_summary("3", results)
            content = summary.read_text()
        self.assertEqual(content.count("⏭️"), 2)
        self.assertEqual(content.count("SENTINEL"), 2)
        self.assertIn("❌", content)
