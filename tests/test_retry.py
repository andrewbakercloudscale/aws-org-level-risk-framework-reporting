"""Transient failures (throttling, timeouts, 408, 5xx) are retried, refusals are not."""

import threading

from botocore.exceptions import ClientError, EndpointConnectionError

from exitrisk import aws_session, healthcheck
from exitrisk.collectors import healthcheck as hc


def _err(code: str, status: int, message: str = "") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Op"
    )


def test_a_408_with_an_empty_body_is_transient():
    assert aws_session.is_transient(_err("408", 408))
    assert aws_session.is_transient(_err("RequestTimeoutException", 400))
    assert aws_session.is_transient(_err("InternalError", 500))
    assert not aws_session.is_transient(_err("AccessDeniedException", 403))
    assert not aws_session.is_transient(_err("InvalidRequestException", 400))


def test_issue_codes_that_a_second_read_can_clear():
    for code in (
        "408",
        "503",
        "ReadTimeoutError",
        "EndpointConnection",
        "ThrottlingException, TooManyRequestsException",
    ):
        assert aws_session.is_transient_code(code), code
    for code in ("AccessDeniedException", "InvalidRequestException", "404", "", None):
        assert not aws_session.is_transient_code(code), code


def test_an_endpoint_with_no_dns_name_is_not_retried(monkeypatch):
    """A service not offered in a region has no endpoint: retrying it only wastes time."""
    exc = EndpointConnectionError(endpoint_url="https://nothing.invalid")
    assert not aws_session.is_transient(exc)
    monkeypatch.setattr(aws_session.socket, "getaddrinfo", lambda *a: [("ok",)])
    assert aws_session.is_transient(exc)


def test_with_backoff_retries_a_408_then_answers():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _err("408", 408)
        return "ok"

    assert aws_session.with_backoff(fn, transient=True, sleep=lambda _s: None) == "ok"
    assert calls["n"] == 3


class _Ctx:
    def __init__(self):
        self._lock = threading.Lock()
        self.gaps = []
        self.ran = 0


def test_health_check_runs_a_transient_gap_again_and_drops_it():
    ctx = _Ctx()
    ctx.gaps = [
        {"region": "eu-west-1", "check": hc.CHECK_LABELS.get("x", "x"), "code": "408"},
        {"region": "eu-west-1", "check": hc.CHECK_LABELS.get("y", "y"), "code": "AccessDeniedException"},
    ]
    ctx.ran = 2
    tasks = [(ctx, "eu-west-1", "x", None), (ctx, "eu-west-1", "y", None)]
    ran = []

    class Job:
        id, cancelled, total = "t", False, 2

    def one(task):
        ran.append(task[2])
        task[0].ran += 1

    healthcheck._retry_transient(Job(), tasks, one, pauses=(0, 0), sleep=lambda _s: None)
    assert ran == ["x"]
    assert [g["code"] for g in ctx.gaps] == ["AccessDeniedException"]
    assert ctx.ran == 2


def test_a_check_run_twice_keeps_one_of_each_signal():
    a = {"title": "t", "region": "r", "n": 1}
    assert hc._unique([a, dict(a), {**a, "n": 2}]) == [a, {**a, "n": 2}]
