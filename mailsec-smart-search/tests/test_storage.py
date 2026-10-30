"""Storage SQL is exercised without requiring a live ClickHouse service."""

from datetime import datetime, timezone
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import threading
import time
import unittest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import AttachmentInfo, MailRecord, SearchQuery
from mailsec_smart_search.storage import ClickHouseRepository, _MAIL_COLUMNS


class FakeClient:
    def __init__(self):
        self.commands = []
        self.inserts = []
        self.queries = []
        self.result = SimpleNamespace(column_names=[], result_rows=[])

    def command(self, sql):
        self.commands.append(sql)

    def insert(self, table, rows, column_names):
        self.inserts.append((table, rows, column_names))

    def query(self, sql, parameters, settings):
        self.queries.append((sql, parameters, settings))
        return self.result


def sample_mail():
    return MailRecord(
        mail_id="a" * 64, raw_sha256="a" * 64, raw_path="sha256/aa/raw.eml",
        source="fixture", ingested_at=datetime(2026, 10, 13, tzinfo=timezone.utc),
        sender="a@example.org", recipients=["b@example.org"], subject="Invoice",
        headers=[("Received", "first"), ("Received", "second")],
        attachments=[AttachmentInfo("bill.PDF", "application/pdf", 3, "b" * 64)],
    )


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.repo = ClickHouseRepository(Settings(), client=self.client)

    def test_schema_and_identifier_whitelist(self):
        with self.assertRaises(ValueError):
            ClickHouseRepository(Settings(clickhouse_database="mailsec; DROP DATABASE default"), self.client)
        self.repo.ensure_schema()
        self.assertEqual(len(self.client.commands), 3)
        self.assertIn("ReplacingMergeTree", self.client.commands[1])
        self.assertIn("cityHash64(mail_id) % 16", self.client.commands[1])
        self.assertIn("analysis_events", self.client.commands[2])

    def test_constructing_repository_does_not_connect(self):
        repository = ClickHouseRepository(Settings())
        self.assertIsNone(repository._client)

    def test_lazy_client_connects_once_across_threads(self):
        repository = ClickHouseRepository(Settings())
        calls = []

        def connect(_):
            time.sleep(0.02)
            calls.append(1)
            return self.client

        with patch.object(ClickHouseRepository, "_connect", side_effect=connect):
            with ThreadPoolExecutor(max_workers=12) as pool:
                clients = list(pool.map(lambda _: repository.client, range(40)))
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(client is self.client for client in clients))

    def test_connection_disables_shared_session_id(self):
        with patch("clickhouse_connect.get_client", return_value=self.client) as factory:
            result = ClickHouseRepository._connect(Settings())
        self.assertIs(result, self.client)
        self.assertIs(factory.call_args.kwargs["autogenerate_session_id"], False)

    def test_insert_and_round_trip_preserve_ordered_headers(self):
        mail = sample_mail()
        self.assertEqual(self.repo.insert_batch([]), 0)
        self.assertEqual(self.repo.insert_batch([mail]), 1)
        table, rows, columns = self.client.inserts[0]
        self.assertEqual(table, "mailsec.mail_records")
        self.assertEqual(columns, list(_MAIL_COLUMNS))
        self.assertEqual(rows[0][columns.index("headers_json")], '[["Received", "first"], ["Received", "second"]]')
        self.assertEqual(rows[0][columns.index("attachment_suffixes")], ["pdf"])
        self.client.result = SimpleNamespace(column_names=columns, result_rows=rows)
        self.assertEqual(self.repo.get_mail(mail.mail_id).headers, mail.headers)
        self.assertEqual(self.repo.get_mail(mail.mail_id).attachments, mail.attachments)
        self.assertIn(" FINAL ", self.client.queries[0][0])
        self.assertEqual(self.client.queries[0][1], {"mail_id": mail.mail_id})

    def test_search_uses_only_fixed_sql_and_bound_values(self):
        malicious = "x' OR 1=1 --"
        query = SearchQuery(
        from_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sender=malicious, recipient="r@example.org", subject_contains="a%_'",
        has_attachment=True, attachment_suffix=".PDF", limit=20, offset=5,
        )
        self.assertEqual(self.repo.search(query), [])
        sql, params, settings = self.client.queries[-1]
        self.assertNotIn(malicious, sql)
        self.assertEqual(params["sender"], malicious)
        self.assertEqual(params["attachment_suffix"], "pdf")
        self.assertIn("FINAL", sql)
        self.assertIn("{limit:UInt16}", sql)
        self.assertEqual(settings["max_execution_time"], 5)
        self.assertGreater(settings["max_memory_usage"], 0)
        with self.assertRaises(ValueError):
            self.repo.search(SearchQuery(limit=201))
        with self.assertRaises(ValueError):
            self.repo.search(SearchQuery(offset=-1))

    def test_search_summaries_projects_only_bounded_fields(self):
        columns = ["mail_id", "sender", "sender_domain", "subject", "sent_at", "ingested_at",
                   "attachment_count", "parse_status", "body_preview"]
        values = ["a" * 64, "a@example.org", "example.org", "Invoice", None,
                  datetime(2026, 10, 13, tzinfo=timezone.utc), 1, "ok", "short"]
        self.client.result = SimpleNamespace(column_names=columns, result_rows=[values])
        result = self.repo.search_summaries(SearchQuery(subject_contains="x' OR 1=1", limit=5))
        self.assertEqual(result, [dict(zip(columns, values))])
        sql, params, settings = self.client.queries[-1]
        self.assertIn("substringUTF8(body_text, 1, 200) AS body_preview", sql)
        self.assertIn("substringUTF8(subject, 1, 512) AS subject", sql)
        self.assertNotIn("headers_json", sql)
        self.assertNotIn("raw_path", sql)
        self.assertNotIn("attachments_json", sql)
        self.assertIn("FINAL", sql)
        self.assertEqual(params["subject_contains"], "x' OR 1=1")
        self.assertEqual(settings["max_execution_time"], 5)
        with self.assertRaises(ValueError):
            self.repo.search_summaries(SearchQuery(limit=201))

    def test_sop_candidates_project_bounded_match_fields_only(self):
        columns = ["mail_id", "raw_sha256", "raw_path", "source", "ingested_at",
                   "sent_at", "sender", "sender_domain", "subject", "body_text",
                   "attachments_json", "claimed_spf", "parse_status"]
        values = ["a" * 64, "a" * 64, "dataset://mail", "test",
                  datetime(2026, 10, 13, tzinfo=timezone.utc), None,
                  "sender@example.org", "example.org", "Invoice", "body",
                  '[{"name":"report.pdf.exe","content_type":"application/octet-stream","size":1,"sha256":"abc"}]',
                  "fail", "ok"]
        self.client.result = SimpleNamespace(column_names=columns, result_rows=[values])
        rows = self.repo.search_candidates(SearchQuery(limit=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].subject, "Invoice")
        self.assertEqual(rows[0].headers, [])
        self.assertEqual(rows[0].recipients, [])
        self.assertEqual(rows[0].urls, [])
        self.assertEqual(rows[0].attachments[0].name, "report.pdf.exe")
        sql, params, _ = self.client.queries[-1]
        self.assertIn("substringUTF8(body_text, 1, 1000) AS body_text", sql)
        self.assertIn("substringUTF8(subject, 1, 300) AS subject", sql)
        self.assertNotIn("headers_json", sql)
        self.assertNotIn("parse_errors", sql)
        self.assertEqual(params["limit"], 10)
        with self.assertRaises(ValueError):
            self.repo.search_candidates(SearchQuery(limit=201))

    def test_historical_sent_at_is_masked_in_every_mail_projection(self):
        self.repo.get_mail("missing")
        self.repo.search(SearchQuery())
        self.repo.search_summaries(SearchQuery())
        self.repo.search_candidates(SearchQuery())
        for sql, _, _ in self.client.queries:
            self.assertIn("toUnixTimestamp64Milli(sent_at) >= -2208988800000", sql)
            self.assertIn("toUnixTimestamp64Milli(sent_at) < 10413792000000", sql)
            self.assertIn("sent_at, NULL) AS sent_at", sql)
        self.client.result = SimpleNamespace(column_names=["total"], result_rows=[(0,)])
        self.repo.stats(SearchQuery(from_time=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        sql, _, _ = self.client.queries[-1]
        self.assertIn("sent_at >= {from_time:DateTime64(3)}", sql)

    def test_stats_and_append_only_analysis(self):
        mail = sample_mail()
        self.client.result = SimpleNamespace(
        column_names=["total", "with_attachment", "parse_failed"],
        result_rows=[(10, 3, 1)],
        )
        self.assertEqual(self.repo.stats(SearchQuery(sender_domain="example.org")), {
        "total": 10, "with_attachment": 3, "parse_failed": 1,
        })
        sql, params, _ = self.client.queries[-1]
        self.assertIn("FINAL", sql)
        self.assertEqual(params, {"sender_domain": "example.org"})
        event_id = self.repo.save_analysis(mail.mail_id, {"rule": {"score": 4}, "model": {"status": "timeout"}})
        table, rows, columns = self.client.inserts[-1]
        self.assertEqual(table, "mailsec.analysis_events")
        self.assertEqual(rows[0][0], event_id)
        self.assertEqual(columns, ["event_id", "mail_id", "created_at", "analysis_json"])
        self.client.result = SimpleNamespace(column_names=columns, result_rows=rows)
        self.assertEqual(self.repo.get_analyses(mail.mail_id)[0]["analysis"]["model"]["status"], "timeout")
        self.assertEqual(self.client.queries[-1][1], {"mail_id": mail.mail_id})

    def test_ping(self):
        self.client.result = SimpleNamespace(column_names=["1"], result_rows=[(1,)])
        self.assertTrue(self.repo.ping())
        self.client.result = SimpleNamespace(column_names=["1"], result_rows=[])
        self.assertFalse(self.repo.ping())

    def test_body_queries_share_one_slot_other_queries_remain_parallel(self):
        class ConcurrentClient(FakeClient):
            def __init__(self):
                super().__init__()
                self.lock = threading.Lock()
                self.active = 0
                self.peak = 0

            def query(self, sql, parameters, settings):
                with self.lock:
                    self.active += 1
                    self.peak = max(self.peak, self.active)
                try:
                    time.sleep(0.03)
                    if "count() AS total" in sql:
                        return SimpleNamespace(column_names=["total", "with_attachment", "parse_failed"],
                                               result_rows=[(1, 0, 0)])
                    return SimpleNamespace(column_names=[], result_rows=[])
                finally:
                    with self.lock:
                        self.active -= 1

        client = ConcurrentClient()
        repo = ClickHouseRepository(Settings(), client=client)
        methods = (repo.search, repo.search_candidates, repo.search_summaries, repo.stats)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda method: method(SearchQuery(body_contains="needle")), methods))
        self.assertEqual(client.peak, 1)
        client.peak = 0
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda method: method(SearchQuery(subject_contains="needle")), methods))
        self.assertGreater(client.peak, 1)

    def test_body_slot_timeout_and_no_leak(self):
        with self.repo._body_scan_slot():
            with patch("mailsec_smart_search.storage._BODY_SCAN_WAIT_SECONDS", 0.01):
                with self.assertRaisesRegex(TimeoutError, "admission timed out"):
                    self.repo.search_summaries(SearchQuery(body_contains="needle"))
            self.assertEqual(self.repo.search_summaries(SearchQuery(subject_contains="needle")), [])
            self.assertIsNone(self.repo.get_mail("missing"))
            self.assertEqual(len(self.repo._body_waiters), 0)
        self.assertEqual(self.repo.search_summaries(SearchQuery(body_contains="needle")), [])

    def test_body_scan_fifo_prevents_busy_worker_starvation(self):
        started = threading.Event()
        release_first = threading.Event()

        class OrderedClient(FakeClient):
            def __init__(self):
                super().__init__()
                self.order = []

            def query(self, sql, parameters, settings):
                label = parameters["body_contains"]
                self.order.append(label)
                if label == "hog1":
                    started.set()
                    if not release_first.wait(2):
                        raise TimeoutError("test gate timed out")
                return SimpleNamespace(column_names=[], result_rows=[])

        client = OrderedClient()
        repo = ClickHouseRepository(Settings(), client=client)

        def hog():
            repo.search_summaries(SearchQuery(body_contains="hog1"))
            repo.search_summaries(SearchQuery(body_contains="hog2"))

        def queued(count):
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with repo._body_condition:
                    if len(repo._body_waiters) == count:
                        return
                time.sleep(0.001)
            self.fail("waiter did not enter FIFO queue")

        with ThreadPoolExecutor(max_workers=3) as pool:
            first = pool.submit(hog)
            self.assertTrue(started.wait(2))
            second = pool.submit(repo.search_summaries, SearchQuery(body_contains="waiter_a"))
            queued(1)
            third = pool.submit(repo.search_summaries, SearchQuery(body_contains="waiter_b"))
            queued(2)
            release_first.set()
            first.result(timeout=5)
            second.result(timeout=5)
            third.result(timeout=5)
        self.assertEqual(client.order, ["hog1", "waiter_a", "waiter_b", "hog2"])
