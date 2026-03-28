"""Tests for the PR quality checks in check_pr.py."""

import logging
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from pr_quality import check_pr

logger = logging.getLogger("pr_quality.check_pr")


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
        "This PR targets the `main` branch."
        " <!-- Backports will be evaluated and done by mergers, when necessary. -->",
        "The commit message is written in past tense, mentions the ticket"
        " number, and ends with a period (see [guidelines]"
        "(https://docs.djangoproject.com/en/dev/internals/contributing/"
        "committing-code/#committing-guidelines)).",
        "I have not requested, and will not request, an automated AI review"
        " for this PR."
        " <!-- You are welcome to do so in your own fork. -->",
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
        f"\n"
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


def patch_urlopen(csv_responses=(), status_code=200):
    side_effects = []
    if status_code == 200:
        for csv_text in csv_responses:
            mock_response = mock.MagicMock()
            mock_response.read.return_value = csv_text.encode()
            mock_cm = mock.MagicMock()
            mock_cm.__enter__.return_value = mock_response
            side_effects.append(mock_cm)
    else:
        error = urllib.error.HTTPError(
            url="https://example.com",
            code=status_code,
            msg="Error",
            hdrs=None,
            fp=None,
        )
        side_effects.append(error)
    return mock.patch("urllib.request.urlopen", side_effect=side_effects)


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        null_handler = logging.NullHandler()
        logger.addHandler(null_handler)
        self.addCleanup(logger.removeHandler, null_handler)

    def call_main(
        self,
        pr_body="",
        total_changes=check_pr.LARGE_PR_THRESHOLD,
        is_recent_contributor=False,
        repo="test/repo",
        pr_number="10",
        pr_author="trusted",
        token="test-token",
    ):
        with (
            mock.patch.object(
                check_pr, "get_pr_total_changes", return_value=total_changes
            ),
            mock.patch.object(
                check_pr, "is_recent_contributor", return_value=is_recent_contributor
            ),
            mock.patch.object(check_pr, "write_job_summary") as mock_summary,
            mock.patch.object(check_pr, "github_request", mock.MagicMock()) as mock_gh,
        ):
            result = check_pr.main(
                repo=repo,
                pr_number=pr_number,
                pr_author=pr_author,
                token=token,
                pr_body=pr_body,
                gha_formatter=False,
            )
        return result, mock_summary, mock_gh


class TestCheckTracTicket(BaseTestCase):
    def test_valid_ticket_small_pr_passes(self):
        self.assertIsNone(
            check_pr.check_trac_ticket(VALID_PR_BODY, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_valid_ticket_large_pr_passes(self):
        self.assertIsNone(
            check_pr.check_trac_ticket(VALID_PR_BODY, check_pr.LARGE_PR_THRESHOLD)
        )

    def test_placeholder_fails(self):
        body = make_pr_body(ticket="ticket-XXXXX")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_missing_small_pr_fails(self):
        body = make_pr_body(ticket="")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_missing_large_pr_fails(self):
        body = make_pr_body(ticket="")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD)
        )

    def test_na_small_pr_passes(self):
        body = make_pr_body(ticket="N/A - typo")
        self.assertIsNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_na_bare_small_pr_passes(self):
        body = make_pr_body(ticket="N/A")
        self.assertIsNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_na_large_pr_fails(self):
        body = make_pr_body(ticket="N/A - typo")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD)
        )

    def test_na_at_threshold_fails(self):
        body = make_pr_body(ticket="N/A")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD)
        )

    def test_na_just_below_threshold_passes(self):
        body = make_pr_body(ticket="N/A")
        self.assertIsNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_ticket_na_format_fails(self):
        body = make_pr_body(ticket="ticket-N/A")
        self.assertIsNotNone(
            check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD - 1)
        )

    def test_various_ticket_lengths_pass(self):
        for ticket in ["ticket-1", "ticket-123", "ticket-999999"]:
            with self.subTest(ticket=ticket):
                body = make_pr_body(ticket=ticket)
                self.assertIsNone(
                    check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD)
                )


class TestCheckTracStatus(BaseTestCase):
    def test_no_ticket_skips_check(self):
        self.assertIsNone(check_pr.check_trac_status("No ticket here."))

    def test_accepted_passes(self):
        csv_text = make_trac_csv(stage="Accepted", has_patch="0")
        with patch_urlopen([csv_text]):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))

    def test_non_accepted_stages_fail(self):
        for stage in ["Unreviewed", "Ready for Checkin", "Someday/Maybe"]:
            with self.subTest(stage=stage):
                csv_text = make_trac_csv(stage=stage, has_patch="0")
                with patch_urlopen([csv_text]):
                    self.assertIsNotNone(check_pr.check_trac_status("ticket-36991"))

    def test_failure_message_contains_ticket_id(self):
        csv_text = make_trac_csv(ticket_id="12345", stage="Unreviewed", has_patch="0")
        with patch_urlopen([csv_text]):
            result = check_pr.check_trac_status("ticket-12345")
        self.assertIn("12345", result)

    def test_failure_message_contains_current_stage(self):
        csv_text = make_trac_csv(stage="Unreviewed", has_patch="0")
        with patch_urlopen([csv_text]):
            result = check_pr.check_trac_status("ticket-36991")
        self.assertIn("Unreviewed", result)

    def test_http_404_fails(self):
        with patch_urlopen(status_code=404):
            self.assertIsNotNone(check_pr.check_trac_status("ticket-99999"))

    def test_network_error_skips_check(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=OSError("Connection refused")
        ):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))

    def test_http_500_skips_check(self):
        with patch_urlopen(status_code=500):
            self.assertIsNone(check_pr.check_trac_status("ticket-36991"))


class TestCheckTracHasPatch(BaseTestCase):
    def test_no_ticket_skips_check(self):
        self.assertIsNone(check_pr.check_trac_has_patch("No ticket here."))

    def test_already_set_passes(self):
        with patch_urlopen([make_trac_csv(has_patch="1")]):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_not_set_times_out_fails(self):
        with (
            patch_urlopen([make_trac_csv(has_patch="0")]),
            mock.patch("time.sleep"),
        ):
            result = check_pr.check_trac_has_patch(
                VALID_PR_BODY, poll_timeout=0, poll_interval=0
            )
        self.assertIsNotNone(result)

    def test_failure_message_contains_ticket_id(self):
        with (
            patch_urlopen([make_trac_csv(ticket_id="36991", has_patch="0")]),
            mock.patch("time.sleep"),
        ):
            result = check_pr.check_trac_has_patch(
                VALID_PR_BODY, poll_timeout=0, poll_interval=0
            )
        self.assertIn("36991", result)

    def test_set_on_second_poll_passes(self):
        with (
            patch_urlopen([make_trac_csv(has_patch="0"), make_trac_csv(has_patch="1")]),
            mock.patch("time.sleep"),
        ):
            self.assertIsNone(
                check_pr.check_trac_has_patch(
                    VALID_PR_BODY, poll_timeout=60, poll_interval=0
                )
            )

    def test_network_error_skips_check(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=OSError("Connection refused")
        ):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_http_500_skips_check(self):
        with patch_urlopen(status_code=500):
            self.assertIsNone(check_pr.check_trac_has_patch(VALID_PR_BODY))

    def test_http_404_skips_check(self):
        # 404 means ticket not found -- already reported by check_trac_status.
        with patch_urlopen(status_code=404):
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

    def test_placeholder_with_appended_text_fails(self):
        body = make_pr_body(
            description=(
                "Provide a concise overview of the issue or rationale behind"
                " the proposed changes. Yes."
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
                with patch_urlopen([csv_text]):
                    results = [
                        check_pr.check_trac_ticket(body, check_pr.LARGE_PR_THRESHOLD),
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
            check_pr.check_trac_ticket("", check_pr.LARGE_PR_THRESHOLD),
            check_pr.check_branch_description(""),
            check_pr.check_ai_disclosure(""),
            check_pr.check_checklist(""),
        ]
        for i, result in enumerate(results, 1):
            self.assertIsNotNone(result, f"Check {i} should have failed on empty body")

    def test_make_pr_body_matches_template(self):
        template_path = (
            Path(__file__).parents[3] / ".github" / "pull_request_template.md"
        )
        with open(template_path) as f:
            raw_template = f.read()
        blank_body = make_pr_body(
            ticket="ticket-XXXXX",
            description=(
                "Provide a concise overview of the issue or rationale behind"
                " the proposed changes."
            ),
            no_ai_checked=False,
            ai_used_checked=False,
            checked_items=0,
        )
        self.assertEqual(blank_body, raw_template)

    def test_unedited_template_fails_all_checks(self):
        template_path = (
            Path(__file__).parents[3] / ".github" / "pull_request_template.md"
        )
        with open(template_path) as f:
            raw_template = f.read()
        results = [
            check_pr.check_trac_ticket(raw_template, check_pr.LARGE_PR_THRESHOLD),
            check_pr.check_branch_description(raw_template),
            check_pr.check_ai_disclosure(raw_template),
            check_pr.check_checklist(raw_template),
        ]
        for i, result in enumerate(results, 1):
            self.assertIsNotNone(
                result, f"Check {i} should have failed on raw template"
            )

    def test_no_ticket_skips_trac_status_and_has_patch(self):
        with self.assertLogs(logger, level="INFO") as logs:
            self.call_main()
        self.assertIn(
            "No Trac ticket -- skipping status and has_patch checks.",
            "\n".join(logs.output),
        )

    def test_no_ticket_results_include_skipped_sentinels(self):
        body = make_pr_body(ticket="")
        _, mock_summary, _ = self.call_main(pr_body=body)
        _, results, _ = mock_summary.call_args.args
        result_map = dict(results)
        self.assertIs(result_map["Trac ticket status is Accepted"], check_pr.SENTINEL)
        self.assertIs(result_map["Trac ticket has_patch flag set"], check_pr.SENTINEL)

    def test_trusted_author_all_pass_no_github_requests(self):
        result, _, mock_gh = self.call_main(
            pr_body=VALID_PR_BODY, is_recent_contributor=True
        )
        self.assertIsNone(result)
        mock_gh.assert_not_called()

    def test_trusted_author_failures_posts_comment_does_not_close(self):
        body = make_pr_body(ticket="", checked_items=0)
        result, _, mock_gh = self.call_main(pr_body=body, is_recent_contributor=True)
        self.assertEqual(result, 1)
        mock_gh.assert_called_once_with(
            "POST", "/issues/10/comments", "test-token", "test/repo", mock.ANY
        )

    def test_untrusted_author_failures_posts_comment_and_closes(self):
        body = make_pr_body(ticket="", checked_items=0)
        result, _, mock_gh = self.call_main(pr_body=body, is_recent_contributor=False)
        self.assertEqual(result, 1)
        self.assertEqual(
            mock_gh.mock_calls,
            [
                mock.call(
                    "POST", "/issues/10/comments", "test-token", "test/repo", mock.ANY
                ),
                mock.call(
                    "PATCH", "/pulls/10", "test-token", "test/repo", {"state": "closed"}
                ),
            ],
        )

    def test_missing_pr_author_treated_as_untrusted(self):
        body = make_pr_body(ticket="", checked_items=0)
        result, _, mock_gh = self.call_main(
            pr_body=body,
            pr_author="",
            is_recent_contributor=False,
        )
        self.assertEqual(result, 1)
        self.assertEqual(
            mock_gh.mock_calls,
            [
                mock.call(
                    "POST", "/issues/10/comments", "test-token", "test/repo", mock.ANY
                ),
                mock.call(
                    "PATCH", "/pulls/10", "test-token", "test/repo", {"state": "closed"}
                ),
            ],
        )


class TestWriteJobSummary(BaseTestCase):
    def test_no_summary_file_does_nothing(self):
        check_pr.write_job_summary(
            "99", [("Some check", None), ("Other check", "failure")]
        )

    def test_all_passed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            results = [
                ("Trac ticket referenced", None),
                ("Branch description provided", None),
            ]
            check_pr.write_job_summary("7", results, str(summary))
            content = summary.read_text()
        self.assertIn("## PR #7 Quality Check Results", content)
        self.assertIn("✅", content)
        self.assertNotIn("❌", content)
        self.assertIn("Trac ticket referenced", content)
        self.assertIn("Branch description provided", content)

    def test_with_failures(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            results = [
                ("Trac ticket referenced", None),
                ("Branch description provided", "Missing description"),
                ("Checklist completed", "Incomplete checklist"),
            ]
            check_pr.write_job_summary("12", results, str(summary))
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
            check_pr.write_job_summary(
                "5", [("Checklist completed", None)], str(summary)
            )
            content = summary.read_text()
        self.assertIn("## Previous step", content)
        self.assertIn("## PR #5 Quality Check Results", content)

    def test_SENTINEL_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary = Path(tmpdir) / "summary.md"
            results = [
                ("Trac ticket referenced", "No ticket found"),
                ("Trac ticket status is Accepted", check_pr.SENTINEL),
                ("Trac ticket has_patch flag set", check_pr.SENTINEL),
            ]
            check_pr.write_job_summary("3", results, str(summary))
            content = summary.read_text()
        self.assertEqual(content.count("⏭️"), 2)
        self.assertEqual(content.count("Skipped"), 2)
        self.assertIn("❌", content)


class TestIsRecentContributor(BaseTestCase):
    def _make_github_request_mock(self, commits):
        return mock.patch.object(check_pr, "github_request", return_value=commits)

    def test_author_with_recent_commits_is_trusted(self):
        with self._make_github_request_mock([{"sha": "abc123"}]):
            self.assertIs(
                check_pr.is_recent_contributor("someuser", "django/django", "token"),
                True,
            )

    def test_author_with_no_recent_commits_is_not_trusted(self):
        with self._make_github_request_mock([]):
            self.assertIs(
                check_pr.is_recent_contributor("newuser", "django/django", "token"),
                False,
            )

    def test_since_date_is_passed_to_api(self):
        with mock.patch.object(check_pr, "github_request", return_value=[]) as mock_gh:
            check_pr.is_recent_contributor("someuser", "django/django", "token")
        path = mock_gh.call_args.args[1]
        self.assertIn("author=someuser", path)
        self.assertIn("since=", path)
        self.assertIn("per_page=1", path)
