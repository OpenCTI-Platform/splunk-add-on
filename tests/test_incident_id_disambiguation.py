"""
Tests for same-second incident ID disambiguation (#44).

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest
from datetime import datetime, timezone

APP_BIN = os.path.join(os.path.dirname(__file__), "..", "TA-opencti-add-on", "bin", "ta_opencti_add_on")
sys.path.insert(0, os.path.abspath(os.path.join(APP_BIN, "aob_py3")))
sys.path.insert(0, os.path.abspath(APP_BIN))

from utils import disambiguate_created, event_identity_key  # noqa: E402
from stix_converter import convert_to_incident, convert_to_incident_response  # noqa: E402

ALERT_PARAMS = {
    "name": "Suspicious login",
    "description": "test",
    "type": "alert",
    "severity": "high",
    "priority": "P2",
    "labels": [],
    "tlp": "tlp_clear",
    "observables_extraction": "none",
}
WHOLE_SECOND = "1727000000"


def _date(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc)


def _object(bundle_json, stix_type):
    return next(o for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type)


def _raw_event(n, **extra):
    ev = {
        "_time": WHOLE_SECOND,
        "_raw": "Failed password for user%d from 10.0.0.%d" % (n, n),
        "_cd": "12:%d" % (1000 + n),
        "_bkt": "main~12~6F2A7B1C-0000-0000-0000-000000000001",
        "index": "main",
        "splunk_server": "idx01",
        "host": "splunk01",
    }
    ev.update(extra)
    return ev


def _run_view(ev, sid, rid):
    """Same event as returned by a different scheduled run."""
    out = dict(ev)
    out.update({
        "rid": str(rid),
        "_serial": str(rid),
        "_sid": sid,
        "info_sid": sid,
        "info_search_time": sid.rsplit("_", 1)[-1],
        "info_min_time": "1726999100.000",
        "info_max_time": sid.rsplit("_", 1)[-1] + ".000",
    })
    return out


class EventIdentityKeyTest(unittest.TestCase):
    def test_prefers_bkt_and_cd(self):
        self.assertTrue(event_identity_key(_raw_event(1)).startswith("cd|main~12~"))

    def test_cd_without_bkt_uses_index_and_server(self):
        ev = _raw_event(1)
        del ev["_bkt"]
        self.assertEqual(event_identity_key(ev), "cd|main|idx01|12:1001")

    def test_bkt_key_is_stable_across_cluster_peers(self):
        a = _raw_event(1, splunk_server="idx01")
        b = _raw_event(1, splunk_server="idx02")
        self.assertEqual(event_identity_key(a), event_identity_key(b))

    def test_falls_back_to_raw(self):
        ev = {"_time": WHOLE_SECOND, "_raw": "hello"}
        self.assertEqual(event_identity_key(ev), "raw|hello")

    def test_transforming_search_row_has_no_identity(self):
        row = {"_time": WHOLE_SECOND, "user": "bob", "count": "12"}
        self.assertEqual(event_identity_key(row), "")
        self.assertEqual(event_identity_key(_run_view(row, "scheduler__a_at_1727000100", 0)), "")

    def test_empty_row(self):
        self.assertEqual(event_identity_key({"_time": WHOLE_SECOND, "rid": "0"}), "")


class DisambiguateCreatedTest(unittest.TestCase):
    def test_overlapping_scheduled_runs_keep_same_created(self):
        """Romain's scenario: every 5m over the last 15m -> same event in 3 runs."""
        ev = _raw_event(7)
        runs = [
            _run_view(ev, "scheduler__admin__search__RMD5abc_at_1727000100", 3),
            _run_view(ev, "scheduler__admin__search__RMD5abc_at_1727000400", 0),
            _run_view(ev, "scheduler__admin__search__RMD5abc_at_1727000700", 11),
        ]
        dates = {disambiguate_created(_date(WHOLE_SECOND), r) for r in runs}
        self.assertEqual(len(dates), 1)

    def test_distinct_same_second_events_split(self):
        dates = {disambiguate_created(_date(WHOLE_SECOND), _raw_event(i)) for i in range(2)}
        self.assertEqual(len(dates), 2)

    def test_distinct_events_mostly_unique(self):
        # hash into 999 slots: 20 events -> ~17% chance of >=1 collision, so
        # assert near-uniqueness rather than perfection
        dates = {disambiguate_created(_date(WHOLE_SECOND), _raw_event(i)) for i in range(20)}
        self.assertGreaterEqual(len(dates), 18)

    def test_offset_is_between_1_and_999_ms(self):
        for i in range(200):
            delta = disambiguate_created(_date(WHOLE_SECOND), _raw_event(i)) - _date(WHOLE_SECOND)
            ms = delta.total_seconds() * 1000
            self.assertGreaterEqual(round(ms), 1)
            self.assertLessEqual(round(ms), 999)

    def test_subsecond_time_is_untouched(self):
        ev = _raw_event(1, _time="1727000000.123")
        date = _date(ev["_time"])
        self.assertEqual(disambiguate_created(date, ev), date)

    def test_transforming_search_row_keeps_legacy_created(self):
        row = {"_time": WHOLE_SECOND, "user": "bob", "count": "12"}
        self.assertEqual(disambiguate_created(_date(WHOLE_SECOND), row), _date(WHOLE_SECOND))

    def test_missing_time_or_identity_is_untouched(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(disambiguate_created(now, {"_raw": "x"}), now)
        self.assertEqual(disambiguate_created(_date(WHOLE_SECOND), {"_time": WHOLE_SECOND, "rid": "0"}),
                         _date(WHOLE_SECOND))


class ConverterTest(unittest.TestCase):
    def test_incident_same_event_across_runs_same_id(self):
        ev = _raw_event(3)
        a = _object(convert_to_incident(ALERT_PARAMS, _run_view(ev, "scheduler__a_at_1727000100", 0)), "incident")
        b = _object(convert_to_incident(ALERT_PARAMS, _run_view(ev, "scheduler__a_at_1727000400", 4)), "incident")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(a["created"], b["created"])

    def test_incident_ids_differ_and_first_seen_keeps_real_time(self):
        incidents = [_object(convert_to_incident(ALERT_PARAMS, _raw_event(i)), "incident") for i in range(2)]
        self.assertNotEqual(incidents[0]["id"], incidents[1]["id"])
        self.assertTrue(all(inc["first_seen"].startswith("2024-09-22T10:13:20") for inc in incidents))

    def test_case_incident_same_event_across_runs_same_id(self):
        ev = _raw_event(3)
        a = _object(convert_to_incident_response(ALERT_PARAMS, _run_view(ev, "scheduler__a_at_1727000100", 0)), "case-incident")
        b = _object(convert_to_incident_response(ALERT_PARAMS, _run_view(ev, "scheduler__a_at_1727000400", 9)), "case-incident")
        self.assertEqual(a["id"], b["id"])

    def test_case_incident_ids_differ(self):
        ids = {_object(convert_to_incident_response(ALERT_PARAMS, _raw_event(i)), "case-incident")["id"] for i in range(2)}
        self.assertEqual(len(ids), 2)

    def test_stats_row_upserts_across_runs_even_when_count_changes(self):
        """Overlapping windows over `stats count by _time, user`: count grows
        between runs, but the incident must keep one ID (legacy name + _time)."""
        a = _run_view({"_time": WHOLE_SECOND, "user": "bob", "count": "3"}, "scheduler__a_at_1727000100", 0)
        b = _run_view({"_time": WHOLE_SECOND, "user": "bob", "count": "7"}, "scheduler__a_at_1727000400", 2)
        ia = _object(convert_to_incident(ALERT_PARAMS, a), "incident")
        ib = _object(convert_to_incident(ALERT_PARAMS, b), "incident")
        self.assertEqual(ia["id"], ib["id"])
        self.assertTrue(ia["created"].startswith("2024-09-22T10:13:20.000"))

    def test_no_identity_keeps_legacy_created(self):
        ev = {"_time": WHOLE_SECOND, "rid": "0"}
        inc = _object(convert_to_incident(ALERT_PARAMS, ev), "incident")
        self.assertTrue(inc["created"].startswith("2024-09-22T10:13:20.000"))


if __name__ == "__main__":
    unittest.main()
