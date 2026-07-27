import datetime
import os
import sys
import unittest


CURRENT_DIR = os.path.dirname(__file__)
PACKAGE_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
AOB_PY3_DIR = os.path.join(PACKAGE_DIR, "aob_py3")
if AOB_PY3_DIR not in sys.path:
    sys.path.insert(0, AOB_PY3_DIR)
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

from utils import generate_case_incident_id, generate_incident_id


class IncidentRidIdTests(unittest.TestCase):
    def setUp(self):
        self.name = "Example Alert"
        self.created = datetime.datetime(2026, 7, 27, 12, 30, 1, tzinfo=datetime.timezone.utc)

    def test_different_rid_produces_different_ids(self):
        for generator in (generate_incident_id, generate_case_incident_id):
            with self.subTest(generator=generator.__name__):
                id_one = generator(self.name, self.created, "0")
                id_two = generator(self.name, self.created, "1")
                self.assertNotEqual(id_one, id_two)

    def test_same_inputs_are_idempotent(self):
        for generator in (generate_incident_id, generate_case_incident_id):
            with self.subTest(generator=generator.__name__):
                first = generator(self.name, self.created, "42")
                second = generator(self.name, self.created, "42")
                self.assertEqual(first, second)

    def test_missing_rid_falls_back_to_empty_string_deterministically(self):
        event = {}
        rid = event.get("rid") or ""

        for generator in (generate_incident_id, generate_case_incident_id):
            with self.subTest(generator=generator.__name__):
                from_fallback = generator(self.name, self.created, rid)
                explicit_empty = generator(self.name, self.created, "")
                self.assertEqual(from_fallback, explicit_empty)
                self.assertEqual(from_fallback, generator(self.name, self.created, rid))


if __name__ == "__main__":
    unittest.main()
