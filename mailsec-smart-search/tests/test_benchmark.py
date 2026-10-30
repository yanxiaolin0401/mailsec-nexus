from datetime import datetime, timezone
import pytest

from scripts.benchmark import BenchmarkFilters, benchmark, write_report


class FakeRepository:
    def __init__(self, *, fail=False):
        self.searches = []
        self.statistics = []
        self.fail = fail

    def search_summaries(self, query):
        self.searches.append(query)
        if self.fail and query.body_contains is not None:
            raise TimeoutError("secret diagnostic with mail content")
        return [{"mail_id": "example"}]

    def stats(self, query):
        self.statistics.append(query)
        return {"total": 100_000, "with_attachment": 1, "parse_failed": 0}


def filters():
    return BenchmarkFilters(
        sender_domain="enron.com", subject_term="meeting", body_term="http",
        attachment_suffix="pdf",
        from_time=datetime(2000, 1, 1, tzinfo=timezone.utc),
        to_time=datetime(2002, 12, 31, tzinfo=timezone.utc),
    )


def test_benchmark_cases_warmup_concurrency_and_no_sensitive_values():
    repository = FakeRepository(fail=True)
    report = benchmark(repository, filters(), iterations=3, warmups=2,
                       concurrency_levels=(1, 4), min_rows=100_000,
                       server_version="26.8.1")
    assert report["dataset_rows"] == 100_000
    assert report["machine"]["clickhouse"] == "26.8.1"
    assert len(report["results"]) == 12
    assert {row["concurrency"] for row in report["results"]} == {1, 4}
    for row in report["results"]:
        assert row["runs"] == 3
        assert row["warmups"] == 2
        assert 0 <= row["errors"] <= 3
        if row["errors"] < 3:
            assert 0 <= row["p50_ms"] <= row["p95_ms"] <= row["max_ms"]
        else:
            assert row["p50_ms"] is None
    assert sum(row["errors"] for row in report["results"] if row["scenario"] == "body") == 6
    assert any(query.sender_domain == "enron.com" for query in repository.searches)
    assert any(query.body_contains == "http" for query in repository.searches)
    assert len(repository.searches) + len(repository.statistics) == 1 + 6 * 2 * 5
    serialized = str(report)
    assert "secret diagnostic" not in serialized
    assert "meeting" not in serialized
    assert "enron.com" not in serialized
    assert "http" not in serialized


def test_minimum_rows_and_arguments():
    repository = FakeRepository()
    with pytest.raises(ValueError, match="minimum"):
        benchmark(repository, filters(), iterations=1, warmups=1, min_rows=100_001)
    with pytest.raises(ValueError):
        benchmark(repository, filters(), iterations=0)
    with pytest.raises(ValueError):
        benchmark(repository, filters(), concurrency_levels=(0,))


def test_report_write_is_atomic_and_path_is_file(tmp_path):
    target = tmp_path / "reports" / "query.json"
    write_report(target, {"results": []})
    assert target.read_text().startswith("{")
    assert not list(target.parent.glob(".query-*"))
