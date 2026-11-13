"""A cut-short AWS answer is retried, and a long exception text never floods the page."""

from botocore.parsers import ResponseParserError

from exitrisk.aws_session import is_transient, is_transient_code, with_backoff
from exitrisk.issues import MAX_MESSAGE, Issue, describe_exception


def test_parser_error_is_transient_and_retried():
    exc = ResponseParserError("Unable to parse response (unclosed token) " + "<x/>" * 2000)
    assert is_transient(exc) and is_transient_code("ResponseParserError")
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 2:
            raise exc
        return "ok"

    assert with_backoff(flaky, transient=True, sleep=lambda _s: None) == "ok"
    code, msg, _hint = describe_exception(exc)
    assert code == "ResponseParserError" and len(msg) < 60


def test_issue_message_is_capped():
    i = Issue("error", "assurance", "x" * 5000)
    assert len(i.message) == MAX_MESSAGE and i.message.endswith("…")
