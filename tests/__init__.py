"""Tests use synthetic, scrubbed alert fixtures only.

Most window and DST fixtures in this suite were written against Australia/Sydney, a zone whose
daylight-saving changes fall in both halves of the year, so they exercise 23- and 25-hour report
days. The suite therefore runs with SOC_THIEF_TIMEZONE set to it unless the caller already set
one. Tests of the UTC default and of other zones patch the environment themselves
(tests/test_zone.py).
"""

import os

os.environ.setdefault("SOC_THIEF_TIMEZONE", "Australia/Sydney")
