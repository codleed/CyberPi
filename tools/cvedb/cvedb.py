#!/usr/bin/env python3
"""Offline CVE intelligence backend for CyberPi.

This module mirrors three public vulnerability data sets into a local SQLite
database and answers the queries the ``cyber_cve_*`` tools ask for:

* the NVD 2.0 CVE API (``https://services.nvd.nist.gov/rest/json/cves/2.0``),
* the CISA Known Exploited Vulnerabilities catalog,
* FIRST EPSS scores (``epss_scores-current.csv.gz``).

Only the Python standard library is used, so the backend runs anywhere
Python 3.11+ is installed.

Every command prints exactly one JSON object on stdout, which lets the
harness parse the result without scraping human readable text.  Operational
failures (no network, missing database, bad arguments) are reported as a JSON
object carrying ``"ok": false`` and a readable ``"error"`` message instead of
a traceback; the exit status is 1 in that case.

Usage::

    cvedb.py sync [--full] [--no-kev] [--no-epss]
    cvedb.py get <cve-id> [--json]
    cvedb.py search --product <name> [--cpe <cpe>] [--cwe <cwe>]
                    [--cvss-min <n>] [--cvss-max <n>] [--kev]
                    [--keyword <text>] [--limit <n>] [--json]
    cvedb.py by-cpe <cpe> [--limit <n>] [--json]
    cvedb.py kev [--limit <n>] [--json]
    cvedb.py stats [--json]

The ``--json`` flag is accepted by every read command and is the default
behaviour: the output is always a JSON object.

The database lives in ``$CYBERPI_CVE_DB`` when that variable is set, in
``$CYBERPI_HOME/cve.db`` when it is set, and in ``~/.cyberpi/cve.db``
otherwise.

``sync`` downloads the whole catalogue the first time it runs and every later
run only fetches the CVEs that were modified since the previous one, using
the ``lastModStartDate`` and ``lastModEndDate`` parameters of the NVD API.
The watermark is kept in the ``meta`` table and is advanced after every
finished window, so an interrupted sync is resumed instead of restarted and
the writes are idempotent (``INSERT OR REPLACE`` inside a transaction).  The
first full sync downloads the complete NVD and takes a while; set
``CYBERPI_NVD_API_KEY`` to raise the request rate from 5 to 50 requests per
30 seconds.  The KEV catalog and the EPSS scores are refreshed on every run
unless ``--no-kev`` or ``--no-epss`` is given, and a failed EPSS download
only leaves the previous scores in place.

Schema::

    cves(id, published, modified, lastModified, description, cvss_score,
         cvss_vector, severity, cwes, products, refs_json)
    cve_cpe(cve_id, cpe, vulnerable)
    kev(cve_id, vendor, product, vuln_name, date_added, due_date, ransomware)
    epss(cve_id, score, percentile, date)
    meta(key, value)

``cves.modified`` records when the local row was last written, while
``cves.lastModified`` keeps the timestamp published by the NVD.
``cves.cwes`` and ``cves.products`` hold JSON arrays, ``cves.refs_json`` holds
the reference list published by the NVD.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import http.client
import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterator, Sequence

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

USER_AGENT = "CyberPi/1.0 (offline CVE intelligence backend)"

#: NVD serves at most 2000 records per request and a date range of at most
#: 120 consecutive days.
NVD_RESULTS_PER_PAGE = 2000
NVD_MIN_PAGE_SIZE = 200
NVD_MAX_RANGE_DAYS = 120

#: The NVD allows 5 requests per 30 seconds without an API key and 50 with
#: one.  The interval keeps the sync polite.
NVD_MIN_INTERVAL = 6.0
NVD_MIN_INTERVAL_WITH_KEY = 0.6

#: Default number of rows returned by the read commands.
DEFAULT_LIMIT = 50

#: Hard ceiling so a stray ``--limit`` cannot dump the whole database.
MAX_LIMIT = 5000

#: Fallback start of the incremental window when no watermark exists.
NVD_EPOCH = datetime(2002, 1, 1, tzinfo=timezone.utc)

SCHEMA_VERSION = "1"

SCHEMA_STATEMENTS = (
	"""CREATE TABLE IF NOT EXISTS cves (
		id TEXT PRIMARY KEY,
		published TEXT,
		modified TEXT,
		lastModified TEXT,
		description TEXT,
		cvss_score REAL,
		cvss_vector TEXT,
		severity TEXT,
		cwes TEXT,
		products TEXT,
		refs_json TEXT
	)""",
	"""CREATE TABLE IF NOT EXISTS cve_cpe (
		cve_id TEXT NOT NULL,
		cpe TEXT NOT NULL,
		vulnerable INTEGER NOT NULL DEFAULT 1,
		PRIMARY KEY (cve_id, cpe)
	)""",
	"""CREATE TABLE IF NOT EXISTS kev (
		cve_id TEXT PRIMARY KEY,
		vendor TEXT,
		product TEXT,
		vuln_name TEXT,
		date_added TEXT,
		due_date TEXT,
		ransomware TEXT
	)""",
	"""CREATE TABLE IF NOT EXISTS epss (
		cve_id TEXT PRIMARY KEY,
		score REAL,
		percentile REAL,
		date TEXT
	)""",
	"""CREATE TABLE IF NOT EXISTS meta (
		key TEXT PRIMARY KEY,
		value TEXT
	)""",
	"CREATE INDEX IF NOT EXISTS idx_cves_published ON cves (published DESC)",
	"CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves (cvss_score)",
	"CREATE INDEX IF NOT EXISTS idx_cve_cpe_cpe ON cve_cpe (cpe)",
	"CREATE INDEX IF NOT EXISTS idx_kev_date ON kev (date_added DESC)",
)


class CvedbError(Exception):
	"""An operational failure that must be reported as a JSON error object."""


class CvedbHttpError(CvedbError):
	"""An HTTP failure returned by one of the upstream services."""

	def __init__(self, message: str, status: int) -> None:
		super().__init__(message)
		self.status = status


class CvedbTruncatedError(CvedbError):
	"""A response that ended before the whole body was transferred."""


# ---------------------------------------------------------------------------
# configuration helpers
# ---------------------------------------------------------------------------


def database_path(explicit: str | None = None) -> str:
	"""Resolve the location of the CVE database."""
	if explicit:
		return os.path.abspath(os.path.expanduser(explicit))
	env = os.environ.get("CYBERPI_CVE_DB")
	if env:
		return os.path.abspath(os.path.expanduser(env))
	home = os.environ.get("CYBERPI_HOME")
	if home:
		return os.path.abspath(os.path.join(os.path.expanduser(home), "cve.db"))
	return os.path.abspath(os.path.join(os.path.expanduser("~"), ".cyberpi", "cve.db"))


def nvd_api_key() -> str | None:
	"""Return the optional NVD API key used to raise the request rate."""
	key = os.environ.get("CYBERPI_NVD_API_KEY") or os.environ.get("NVD_API_KEY")
	return key if key else None


def log(message: str) -> None:
	"""Write a progress line to stderr so stdout stays pure JSON."""
	sys.stderr.write(f"[cvedb] {message}\n")
	sys.stderr.flush()


# ---------------------------------------------------------------------------
# database helpers
# ---------------------------------------------------------------------------


def connect(path: str, readonly: bool = False) -> sqlite3.Connection:
	"""Open the CVE database with explicit transaction control."""
	if readonly:
		if not os.path.exists(path):
			raise CvedbError(
				f"CVE database not found at {path}. Run 'cvedb.py sync' to build it."
			)
		uri = "file:" + urllib.parse.quote(path.replace("\\", "/")) + "?mode=ro"
		try:
			conn = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
		except sqlite3.Error as exc:
			raise CvedbError(f"cannot open CVE database at {path}: {exc}") from exc
	else:
		parent = os.path.dirname(path)
		if parent:
			try:
				os.makedirs(parent, exist_ok=True)
			except OSError as exc:
				raise CvedbError(f"cannot create directory {parent}: {exc}") from exc
		try:
			conn = sqlite3.connect(path, timeout=30, isolation_level=None)
		except sqlite3.Error as exc:
			raise CvedbError(f"cannot open CVE database at {path}: {exc}") from exc
	conn.row_factory = sqlite3.Row
	try:
		conn.execute("PRAGMA journal_mode=WAL")
		conn.execute("PRAGMA synchronous=NORMAL")
	except sqlite3.Error:
		pass
	return conn


def init_schema(conn: sqlite3.Connection) -> None:
	"""Create every table and index the backend needs."""
	for statement in SCHEMA_STATEMENTS:
		conn.execute(statement)
	meta_set(conn, "schema_version", SCHEMA_VERSION)


def meta_get(conn: sqlite3.Connection, key: str) -> str | None:
	row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
	return None if row is None else row["value"]


def meta_set(conn: sqlite3.Connection, key: str, value: str) -> None:
	conn.execute(
		"INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, str(value))
	)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
	"""Run a block inside one transaction, rolling back on any failure."""
	conn.execute("BEGIN")
	try:
		yield conn
	except BaseException:
		try:
			conn.execute("ROLLBACK")
		except sqlite3.Error:
			pass
		raise
	conn.execute("COMMIT")


def json1_available(conn: sqlite3.Connection) -> bool:
	"""Check whether the SQLite build exposes the JSON1 extension."""
	try:
		conn.execute("SELECT json_valid('[1]')").fetchone()
	except sqlite3.Error:
		return False
	return True


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _retry_after_seconds(value: str | None) -> float | None:
	"""Turn a ``Retry-After`` header into a delay in seconds."""
	if not value:
		return None
	value = value.strip()
	try:
		return max(0.0, float(value))
	except ValueError:
		pass
	try:
		when = parsedate_to_datetime(value)
	except (TypeError, ValueError):
		return None
	if when is None:
		return None
	if when.tzinfo is None:
		when = when.replace(tzinfo=timezone.utc)
	delay = (when - datetime.now(timezone.utc)).total_seconds()
	return max(0.0, delay)


def http_get(
	url: str, timeout: int = 120, retries: int = 3, headers: dict[str, str] | None = None
) -> tuple[bytes, dict[str, str]]:
	"""Fetch a URL and return the body together with the response headers."""
	request = urllib.request.Request(url, method="GET")
	request.add_header("User-Agent", USER_AGENT)
	request.add_header("Accept", "*/*")
	if headers:
		for name, value in headers.items():
			request.add_header(name, value)

	last_error: Exception | None = None
	for attempt in range(1, retries + 1):
		try:
			with urllib.request.urlopen(request, timeout=timeout) as response:
				return response.read(), {k.lower(): v for k, v in response.headers.items()}
		except urllib.error.HTTPError as exc:
			last_error = exc
			body = ""
			try:
				body = exc.read().decode("utf-8", "replace")[:400]
			except Exception:  # noqa: BLE001 - the body is best effort
				body = ""
			delay = _retry_after_seconds(
				exc.headers.get("Retry-After") if exc.headers else None
			)
			if exc.code in (403, 429, 500, 502, 503, 504) and attempt < retries:
				if delay is None:
					delay = float(2 ** attempt)
				log(f"HTTP {exc.code} from {url}, retrying in {delay:.0f}s")
				time.sleep(min(delay, 120.0))
				continue
			raise CvedbHttpError(
				f"HTTP {exc.code} from {url}: {body.strip() or exc.reason}", exc.code
			) from exc
		except urllib.error.URLError as exc:
			last_error = exc
			if attempt < retries:
				delay = float(2 ** attempt)
				log(f"network error contacting {url}, retrying in {delay:.0f}s")
				time.sleep(delay)
				continue
			raise CvedbError(
				f"network error contacting {url}: {exc.reason}. "
				"Check the network connection and try again."
			) from exc
		except http.client.HTTPException as exc:
			# A truncated body is not worth retrying at the same size: the
			# caller shrinks the page and asks again.
			raise CvedbTruncatedError(
				f"truncated response from {url}: {type(exc).__name__}: {exc}. "
				"Check the network connection and try again."
			) from exc
		except (TimeoutError, OSError) as exc:
			last_error = exc
			if attempt < retries:
				delay = float(2 ** attempt)
				log(f"network error contacting {url}, retrying in {delay:.0f}s")
				time.sleep(delay)
				continue
			raise CvedbError(f"network error contacting {url}: {exc}") from exc
	raise CvedbError(f"network error contacting {url}: {last_error}")


class RateLimiter:
	"""Keep at least ``min_interval`` seconds between two requests."""

	def __init__(self, min_interval: float) -> None:
		self.min_interval = max(0.0, min_interval)
		self.last_request = 0.0

	def wait(self) -> None:
		now = time.monotonic()
		elapsed = now - self.last_request
		if elapsed < self.min_interval:
			time.sleep(self.min_interval - elapsed)
		self.last_request = time.monotonic()


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------


def nvd_timestamp(value: datetime) -> str:
	"""Format a datetime the way the NVD API expects it."""
	return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_timestamp(value: str | None) -> datetime | None:
	"""Parse an ISO-8601 or RFC 2822 timestamp, assuming UTC when naive."""
	if not value:
		return None
	text = value.strip()
	if text.endswith("Z"):
		text = text[:-1] + "+00:00"
	parsed: datetime | None = None
	try:
		parsed = datetime.fromisoformat(text)
	except ValueError:
		parsed = None
	if parsed is None:
		try:
			parsed = parsedate_to_datetime(text)
		except (TypeError, ValueError):
			return None
	if parsed is None:
		return None
	if parsed.tzinfo is None:
		parsed = parsed.replace(tzinfo=timezone.utc)
	return parsed.astimezone(timezone.utc)


def parse_cpe(criteria: str) -> tuple[str, str] | None:
	"""Split a CPE into its vendor and product components."""
	if not criteria:
		return None
	if criteria.startswith("cpe:2.3:"):
		parts = criteria.split(":")
		if len(parts) < 5:
			return None
		vendor = parts[3]
		product = parts[4]
	elif criteria.startswith("cpe:/"):
		parts = criteria.split(":")
		if len(parts) < 4:
			return None
		vendor = parts[2]
		product = parts[3]
	else:
		return None
	vendor = vendor.replace("\\", "").strip()
	product = product.replace("\\", "").strip()
	if vendor in ("*", "-"):
		vendor = ""
	if product in ("*", "-"):
		product = ""
	return vendor, product


def extract_description(cve: dict[str, Any]) -> str:
	"""Return the English description of a CVE."""
	descriptions = cve.get("descriptions") or []
	fallback = ""
	for entry in descriptions:
		value = str(entry.get("value") or "").strip()
		if not value:
			continue
		if str(entry.get("lang") or "").lower() == "en":
			return value
		if not fallback:
			fallback = value
	return fallback


def extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
	"""Return the base score, vector and severity of a CVE.

	CVSS v3.1 is preferred over v3.0, then v4.0 and finally the v2 score, so
	that the ``--cvss-min`` filter compares like with like.
	"""
	metrics = cve.get("metrics") or {}
	for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
		entries = metrics.get(key)
		if not entries:
			continue
		chosen: dict[str, Any] | None = None
		for entry in entries:
			if not isinstance(entry, dict):
				continue
			if str(entry.get("type") or "").lower() == "primary":
				chosen = entry
				break
		if chosen is None:
			chosen = next((e for e in entries if isinstance(e, dict)), None)
		if chosen is None:
			continue
		data = chosen.get("cvssData") or {}
		score = data.get("baseScore")
		if score is None:
			continue
		vector = data.get("vectorString")
		severity = data.get("baseSeverity") or chosen.get("baseSeverity")
		return (
			float(score),
			str(vector) if vector else None,
			str(severity).upper() if severity else None,
		)
	return None, None, None


def extract_cwes(cve: dict[str, Any]) -> list[str]:
	"""Return the weakness identifiers of a CVE, normalised to ``CWE-N``."""
	found: list[str] = []
	for weakness in cve.get("weaknesses") or []:
		for entry in weakness.get("description") or []:
			value = str(entry.get("value") or "").strip().upper()
			if value.startswith("CWE-") and value not in found:
				found.append(value)
	return sorted(found)


def extract_cpes(cve: dict[str, Any]) -> list[tuple[str, int]]:
	"""Return the ``(cpe, vulnerable)`` pairs configured for a CVE."""
	seen: dict[str, int] = {}
	for configuration in cve.get("configurations") or []:
		for node in configuration.get("nodes") or []:
			for match in node.get("cpeMatch") or []:
				criteria = str(match.get("criteria") or "").strip()
				if not criteria:
					continue
				vulnerable = 1 if match.get("vulnerable", True) else 0
				seen[criteria] = vulnerable
	return sorted(seen.items())


def extract_products(cve: dict[str, Any]) -> list[dict[str, str]]:
	"""Return the distinct vendor/product pairs configured for a CVE."""
	products: list[dict[str, str]] = []
	seen: set[tuple[str, str]] = set()
	for criteria, _vulnerable in extract_cpes(cve):
		parsed = parse_cpe(criteria)
		if parsed is None:
			continue
		vendor, product = parsed
		if not product:
			continue
		key = (vendor.lower(), product.lower())
		if key in seen:
			continue
		seen.add(key)
		products.append({"vendor": vendor, "product": product})
	return sorted(products, key=lambda item: (item["vendor"], item["product"]))


def extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
	"""Return the reference list published for a CVE."""
	references: list[dict[str, Any]] = []
	for reference in cve.get("references") or []:
		url = str(reference.get("url") or "").strip()
		if not url:
			continue
		tags = [str(tag) for tag in (reference.get("tags") or [])]
		references.append(
			{"url": url, "source": reference.get("source"), "tags": tags}
		)
	return references


def parse_cve(cve: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, int]]]:
	"""Turn an NVD CVE object into a database row and its CPE list."""
	score, vector, severity = extract_cvss(cve)
	products = extract_products(cve)
	row = {
		"id": str(cve.get("id") or "").upper(),
		"published": cve.get("published"),
		"modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
		"lastModified": cve.get("lastModified"),
		"description": extract_description(cve),
		"cvss_score": score,
		"cvss_vector": vector,
		"severity": severity,
		"cwes": json.dumps(extract_cwes(cve), separators=(",", ":")),
		"products": json.dumps(products, separators=(",", ":"), sort_keys=True),
		"refs_json": json.dumps(extract_references(cve), separators=(",", ":")),
	}
	return row, extract_cpes(cve)


def store_cve(
	conn: sqlite3.Connection, row: dict[str, Any], cpes: Sequence[tuple[str, int]]
) -> None:
	"""Insert or replace one CVE and its CPE list."""
	conn.execute(
		"""INSERT OR REPLACE INTO cves
			(id, published, modified, lastModified, description, cvss_score,
			 cvss_vector, severity, cwes, products, refs_json)
			VALUES (:id, :published, :modified, :lastModified, :description,
			        :cvss_score, :cvss_vector, :severity, :cwes, :products, :refs_json)""",
		row,
	)
	conn.execute("DELETE FROM cve_cpe WHERE cve_id = ?", (row["id"],))
	if cpes:
		conn.executemany(
			"INSERT OR REPLACE INTO cve_cpe (cve_id, cpe, vulnerable) VALUES (?, ?, ?)",
			[(row["id"], cpe, vulnerable) for cpe, vulnerable in cpes],
		)


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------


def nvd_fetch(
	params: dict[str, Any], limiter: RateLimiter
) -> dict[str, Any]:
	"""Query the NVD API for one page of results."""
	headers: dict[str, str] = {}
	key = nvd_api_key()
	if key:
		headers["apiKey"] = key
	url = NVD_API_URL + "?" + urllib.parse.urlencode(params)
	limiter.wait()
	body, _response_headers = http_get(url, timeout=180, headers=headers)
	try:
		payload = json.loads(body.decode("utf-8", "replace"))
	except json.JSONDecodeError as exc:
		raise CvedbError(f"the NVD API returned invalid JSON: {exc}") from exc
	if not isinstance(payload, dict):
		raise CvedbError("the NVD API returned an unexpected payload")
	return payload


def _write_page(
	conn: sqlite3.Connection, vulnerabilities: Sequence[dict[str, Any]]
) -> tuple[int, int]:
	"""Store one page of NVD vulnerabilities, returning CVE and CPE counts."""
	cve_count = 0
	cpe_count = 0
	for entry in vulnerabilities:
		cve = entry.get("cve") if isinstance(entry, dict) else None
		if not isinstance(cve, dict):
			continue
		row, cpes = parse_cve(cve)
		if not row["id"]:
			continue
		store_cve(conn, row, cpes)
		cve_count += 1
		cpe_count += len(cpes)
	return cve_count, cpe_count


def sync_nvd(
	conn: sqlite3.Connection, full: bool, limiter: RateLimiter
) -> dict[str, Any]:
	"""Download CVE records from the NVD, incrementally when possible."""
	stats: dict[str, Any] = {
		"pages": 0,
		"cves": 0,
		"cpes": 0,
		"mode": "full" if full else "incremental",
		"from": None,
		"to": None,
		"watermark": None,
	}
	now = datetime.now(timezone.utc).replace(microsecond=0)
	watermark_text = meta_get(conn, "nvd_last_modified")
	watermark = parse_timestamp(watermark_text)

	if full or watermark is None:
		if not full:
			log("no previous sync watermark found, performing a full NVD sync")
			stats["mode"] = "full"
		return _sync_nvd_full(conn, limiter, stats, now)

	# Restart a little before the watermark so records modified exactly on
	# the boundary are not missed; the write is idempotent.
	start = watermark - timedelta(minutes=1)
	end = now
	stats["from"] = nvd_timestamp(start)
	stats["to"] = nvd_timestamp(end)
	log(f"incremental NVD sync from {stats['from']} to {stats['to']}")
	_sync_nvd_incremental(conn, limiter, stats, start, end)

	meta_set(conn, "nvd_last_sync", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
	return stats


def _sync_nvd_incremental(
	conn: sqlite3.Connection,
	limiter: RateLimiter,
	stats: dict[str, Any],
	start: datetime,
	end: datetime,
) -> None:
	"""Download the CVEs modified in a window, in NVD sized slices.

	The watermark is advanced after every finished slice, so an interrupted
	sync resumes where it stopped instead of starting over.  When the NVD
	rejects a slice the window is halved and retried; every other failure is
	propagated so a broken network never advances the watermark.
	"""
	while start < end:
		chunk_end = min(start + timedelta(days=NVD_MAX_RANGE_DAYS - 1), end)
		params = {
			"lastModStartDate": nvd_timestamp(start),
			"lastModEndDate": nvd_timestamp(chunk_end),
			"resultsPerPage": NVD_RESULTS_PER_PAGE,
			"startIndex": 0,
		}
		try:
			cves, cpes = _sync_nvd_window(conn, limiter, params, stats)
			log(
				f"window {params['lastModStartDate']} .. {params['lastModEndDate']}: "
				f"{cves} CVEs"
			)
		except CvedbHttpError as exc:
			span = chunk_end - start
			if exc.status != 400 or span <= timedelta(hours=12):
				raise
			middle = start + span / 2
			log(
				f"the NVD rejected the window {params['lastModStartDate']} .. "
				f"{params['lastModEndDate']}, retrying in two smaller windows"
			)
			_sync_nvd_incremental(conn, limiter, stats, start, middle)
			_sync_nvd_incremental(conn, limiter, stats, middle, end)
			return
		meta_set(conn, "nvd_last_modified", nvd_timestamp(chunk_end))
		stats["watermark"] = nvd_timestamp(chunk_end)
		start = chunk_end


def _download_pages(
	conn: sqlite3.Connection,
	limiter: RateLimiter,
	stats: dict[str, Any],
	params: dict[str, Any],
) -> tuple[int, int]:
	"""Download every page of an NVD query and store it.

	The NVD cuts off very large responses, so the page size is halved and
	the page is requested again when the transfer is truncated.
	"""
	page_size = int(params.get("resultsPerPage", NVD_RESULTS_PER_PAGE))
	start_index = 0
	total_cves = 0
	total_cpes = 0
	while True:
		query = dict(params)
		query["resultsPerPage"] = page_size
		query["startIndex"] = start_index
		try:
			payload = nvd_fetch(query, limiter)
		except CvedbTruncatedError as exc:
			if page_size <= NVD_MIN_PAGE_SIZE:
				raise
			page_size = max(NVD_MIN_PAGE_SIZE, page_size // 2)
			log(
				f"the NVD response was truncated ({exc}); "
				f"retrying with {page_size} records per page"
			)
			continue
		vulnerabilities = payload.get("vulnerabilities") or []
		total = int(payload.get("totalResults") or 0)
		with transaction(conn):
			cves, cpes = _write_page(conn, vulnerabilities)
		stats["pages"] += 1
		total_cves += cves
		total_cpes += cpes
		stats["cves"] += cves
		stats["cpes"] += cpes
		log(
			f"page {stats['pages']}: {cves} CVEs "
			f"({start_index + len(vulnerabilities)}/{total or '?'} in this query)"
		)
		if not vulnerabilities:
			break
		start_index += len(vulnerabilities)
		if start_index >= total:
			break
	return total_cves, total_cpes


def _sync_nvd_window(
	conn: sqlite3.Connection,
	limiter: RateLimiter,
	params: dict[str, Any],
	stats: dict[str, Any],
) -> tuple[int, int]:
	"""Download every page of one NVD date window."""
	return _download_pages(conn, limiter, stats, params)


def _sync_nvd_full(
	conn: sqlite3.Connection,
	limiter: RateLimiter,
	stats: dict[str, Any],
	now: datetime,
) -> dict[str, Any]:
	"""Download the whole NVD catalogue, page by page."""
	log("full NVD sync starting (this takes a while)")
	try:
		_download_pages(conn, limiter, stats, {"resultsPerPage": NVD_RESULTS_PER_PAGE})
	except CvedbError as exc:
		log(f"full sync failed ({exc}); falling back to date windows")
		stats.update({"pages": 0, "cves": 0, "cpes": 0})
		return _sync_nvd_windows(conn, limiter, stats, now, NVD_EPOCH)
	meta_set(conn, "nvd_last_modified", nvd_timestamp(now))
	meta_set(conn, "nvd_last_sync", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
	stats["watermark"] = nvd_timestamp(now)
	stats["from"] = nvd_timestamp(NVD_EPOCH)
	stats["to"] = nvd_timestamp(now)
	return stats


def _sync_nvd_windows(
	conn: sqlite3.Connection,
	limiter: RateLimiter,
	stats: dict[str, Any],
	now: datetime,
	start: datetime,
) -> dict[str, Any]:
	"""Download the catalogue in date windows, oldest first."""
	end = now
	stats["from"] = nvd_timestamp(start)
	stats["to"] = nvd_timestamp(end)
	_sync_nvd_incremental(conn, limiter, stats, start, end)
	meta_set(conn, "nvd_last_sync", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
	return stats


def sync_kev(conn: sqlite3.Connection) -> dict[str, Any]:
	"""Refresh the CISA Known Exploited Vulnerabilities catalog."""
	stats: dict[str, Any] = {"updated": False, "entries": 0}
	try:
		body, _headers = http_get(KEV_URL, timeout=180)
		payload = json.loads(body.decode("utf-8", "replace"))
	except CvedbError:
		raise
	except json.JSONDecodeError as exc:
		raise CvedbError(f"the KEV catalog is not valid JSON: {exc}") from exc
	if not isinstance(payload, dict):
		raise CvedbError("the KEV catalog has an unexpected structure")
	entries = payload.get("vulnerabilities") or []
	rows = []
	for entry in entries:
		if not isinstance(entry, dict):
			continue
		cve_id = str(entry.get("cveID") or "").strip().upper()
		if not cve_id:
			continue
		rows.append(
			(
				cve_id,
				entry.get("vendorProject"),
				entry.get("product"),
				entry.get("vulnerabilityName"),
				entry.get("dateAdded"),
				entry.get("dueDate"),
				str(entry.get("knownRansomwareCampaignUse") or "Unknown"),
			)
		)
	with transaction(conn):
		conn.execute("DELETE FROM kev")
		conn.executemany(
			"""INSERT OR REPLACE INTO kev
				(cve_id, vendor, product, vuln_name, date_added, due_date, ransomware)
				VALUES (?, ?, ?, ?, ?, ?, ?)""",
			rows,
		)
		meta_set(conn, "kev_last_sync", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
		if payload.get("catalogVersion"):
			meta_set(conn, "kev_catalog_version", str(payload["catalogVersion"]))
		if payload.get("dateReleased"):
			meta_set(conn, "kev_date_released", str(payload["dateReleased"]))
	stats["updated"] = True
	stats["entries"] = len(rows)
	return stats


def epss_score_date(metadata: Sequence[str], headers: dict[str, str]) -> str:
	"""Work out the date the EPSS scores were computed for.

	The published file starts with a metadata row such as
	``#model_version:v2024.03.01,score_date:2024-03-01T00:00:00+0000``; the
	``Last-Modified`` header of the download is used as a fallback.
	"""
	for chunk in metadata:
		if "score_date:" in chunk:
			raw = chunk.split("score_date:", 1)[1].split(",")[0].strip()
			parsed = parse_timestamp(raw)
			if parsed is not None:
				return parsed.strftime("%Y-%m-%d")
	modified = headers.get("last-modified")
	if modified:
		parsed = parse_timestamp(modified)
		if parsed is not None:
			return parsed.strftime("%Y-%m-%d")
	return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sync_epss(conn: sqlite3.Connection) -> dict[str, Any]:
	"""Refresh the FIRST EPSS scores, degrading gracefully on failure."""
	stats: dict[str, Any] = {"updated": False, "entries": 0, "error": None}
	try:
		body, headers = http_get(EPSS_URL, timeout=300)
		text = gzip.decompress(body).decode("utf-8", "replace")
	except Exception as exc:  # noqa: BLE001 - EPSS is optional
		stats["error"] = f"{type(exc).__name__}: {exc}"
		log(f"EPSS download failed, keeping the previous scores: {exc}")
		return stats

	reader = csv.reader(io.StringIO(text))
	metadata: list[str] = []
	columns: list[str] = []
	for row in reader:
		if not row:
			continue
		first = str(row[0]).strip()
		if first.startswith("#"):
			metadata.append(",".join(str(field) for field in row))
			continue
		columns = [str(name).strip().lower() for name in row]
		break
	if not columns:
		stats["error"] = "the EPSS download has no readable header"
		return stats

	score_date = epss_score_date(metadata, headers)
	try:
		cve_index = columns.index("cve")
		score_index = columns.index("epss")
	except ValueError:
		cve_index, score_index = 0, 1
	percentile_index = columns.index("percentile") if "percentile" in columns else None

	rows: list[tuple[str, float, float | None, str]] = []
	for record in reader:
		if not record or len(record) <= max(cve_index, score_index):
			continue
		cve_id = record[cve_index].strip().upper()
		try:
			score = float(record[score_index].strip())
		except (TypeError, ValueError):
			continue
		percentile: float | None = None
		if percentile_index is not None and len(record) > percentile_index:
			try:
				percentile = float(record[percentile_index].strip())
			except (TypeError, ValueError):
				percentile = None
		if not cve_id:
			continue
		rows.append((cve_id, score, percentile, score_date))

	with transaction(conn):
		conn.execute("DELETE FROM epss")
		conn.executemany(
			"INSERT OR REPLACE INTO epss (cve_id, score, percentile, date) VALUES (?, ?, ?, ?)",
			rows,
		)
		meta_set(
			conn, "epss_last_sync", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
		)
		meta_set(conn, "epss_date", score_date)
	stats["updated"] = True
	stats["entries"] = len(rows)
	stats["date"] = score_date
	return stats


def cmd_sync(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""Refresh the local mirror of the vulnerability data sets."""
	started = time.monotonic()
	interval = NVD_MIN_INTERVAL_WITH_KEY if nvd_api_key() else NVD_MIN_INTERVAL
	limiter = RateLimiter(interval)

	result: dict[str, Any] = {
		"ok": True,
		"command": "sync",
		"mode": "full" if args.full else "incremental",
		"database": database_path(args.db),
	}
	nvd_stats = sync_nvd(conn, args.full, limiter)
	result["nvd"] = nvd_stats
	result["mode"] = nvd_stats.get("mode", result["mode"])

	if args.no_kev:
		result["kev"] = {"updated": False, "skipped": True}
	else:
		try:
			result["kev"] = sync_kev(conn)
		except CvedbError as exc:
			result["kev"] = {"updated": False, "error": str(exc)}
			log(f"KEV sync failed: {exc}")

	if args.no_epss:
		result["epss"] = {"updated": False, "skipped": True}
	else:
		result["epss"] = sync_epss(conn)

	result["counts"] = database_counts(conn)
	result["duration_seconds"] = round(time.monotonic() - started, 2)
	result["finished_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	return result


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def cve_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
	"""Turn a result row into the JSON shape used by every command."""
	keys = row.keys()
	epss: dict[str, Any] | None = None
	if "epss_score" in keys and row["epss_score"] is not None:
		epss = {
			"score": row["epss_score"],
			"percentile": row["epss_percentile"],
			"date": row["epss_date"],
		}
	return {
		"id": row["id"],
		"published": row["published"],
		"modified": row["modified"],
		"lastModified": row["lastModified"],
		"description": row["description"],
		"cvss_score": row["cvss_score"],
		"cvss_vector": row["cvss_vector"],
		"severity": row["severity"],
		"cwes": json.loads(row["cwes"] or "[]"),
		"products": json.loads(row["products"] or "[]"),
		"references": json.loads(row["refs_json"] or "[]"),
		"kev": bool(row["kev_cve_id"]) if "kev_cve_id" in keys else False,
		"epss": epss,
	}


SELECT_COLUMNS = (
	"c.id, c.published, c.modified, c.lastModified, c.description, "
	"c.cvss_score, c.cvss_vector, c.severity, c.cwes, c.products, c.refs_json, "
	"k.cve_id AS kev_cve_id, e.score AS epss_score, e.percentile AS epss_percentile, "
	"e.date AS epss_date"
)

FROM_CVES = (
	"FROM cves c "
	"LEFT JOIN kev k ON k.cve_id = c.id "
	"LEFT JOIN epss e ON e.cve_id = c.id"
)


def normalise_limit(value: int | None, default: int = DEFAULT_LIMIT) -> int:
	"""Clamp the requested number of rows."""
	if value is None:
		return default
	if value <= 0:
		return 0
	return min(value, MAX_LIMIT)


def normalise_cve_id(value: str) -> str:
	"""Normalise a CVE identifier to its canonical upper case form."""
	text = value.strip().upper()
	if text.startswith("CVE-"):
		return text
	if text.replace("-", "").isdigit():
		return "CVE-" + text
	return text


def normalise_cwe(value: str) -> str:
	"""Normalise a weakness identifier to the ``CWE-N`` form."""
	text = value.strip().upper()
	if text.isdigit():
		return "CWE-" + text
	if not text.startswith("CWE-"):
		return "CWE-" + text
	return text


def escape_like(term: str) -> str:
	"""Escape the LIKE wildcards of a user supplied term."""
	return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def cpe_prefix_pattern(cpe: str) -> tuple[str, str]:
	"""Return the exact and prefix patterns used to match a CPE."""
	text = cpe.strip().lower()
	if text.endswith(":*"):
		text = text[:-2]
	elif text.endswith(":"):
		text = text[:-1]
	return text, escape_like(text) + ":%"


def cmd_get(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""Return one CVE with its KEV and EPSS annotations."""
	cve_id = normalise_cve_id(args.cve_id)
	row = conn.execute(
		"""SELECT c.*, k.cve_id AS kev_cve_id, k.vendor AS kev_vendor,
		          k.product AS kev_product, k.vuln_name AS kev_name,
		          k.date_added AS kev_date_added, k.due_date AS kev_due_date,
		          k.ransomware AS kev_ransomware,
		          e.score AS epss_score, e.percentile AS epss_percentile,
		          e.date AS epss_date
			FROM cves c
			LEFT JOIN kev k ON k.cve_id = c.id
			LEFT JOIN epss e ON e.cve_id = c.id
			WHERE c.id = ?""",
		(cve_id,),
	).fetchone()
	if row is None:
		# The CVE record itself is not mirrored yet, but the KEV catalog and
		# the EPSS scores may still know about it.
		annotations = kev_epss_annotations(conn, cve_id)
		return {
			"ok": True,
			"command": "get",
			"found": False,
			"cve": None,
			"message": f"{cve_id} is not in the local CVE database. Run 'cvedb.py sync'.",
			**annotations,
		}
	entry = cve_row_to_dict(row)
	if row["kev_cve_id"]:
		entry["kev_entry"] = {
			"vendor": row["kev_vendor"],
			"product": row["kev_product"],
			"vuln_name": row["kev_name"],
			"date_added": row["kev_date_added"],
			"due_date": row["kev_due_date"],
			"ransomware": row["kev_ransomware"],
		}
	return {"ok": True, "command": "get", "found": True, "cve": entry}


def kev_epss_annotations(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any]:
	"""Return the KEV flag and the EPSS score of a CVE, when they are known."""
	annotations: dict[str, Any] = {}
	kev_row = conn.execute("SELECT * FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
	epss_row = conn.execute("SELECT * FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
	if kev_row is not None:
		annotations["kev"] = True
		annotations["kev_entry"] = {
			"vendor": kev_row["vendor"],
			"product": kev_row["product"],
			"vuln_name": kev_row["vuln_name"],
			"date_added": kev_row["date_added"],
			"due_date": kev_row["due_date"],
			"ransomware": kev_row["ransomware"],
		}
	if epss_row is not None:
		annotations["epss"] = {
			"score": epss_row["score"],
			"percentile": epss_row["percentile"],
			"date": epss_row["date"],
		}
	return annotations


def build_search_query(
	conn: sqlite3.Connection, args: argparse.Namespace
) -> tuple[str, list[Any], dict[str, Any]]:
	"""Build the WHERE clause of the search command."""
	clauses: list[str] = []
	params: list[Any] = []
	use_json = json1_available(conn)

	if args.cpe:
		exact, prefix = cpe_prefix_pattern(args.cpe)
		clauses.append(
			"EXISTS (SELECT 1 FROM cve_cpe cc WHERE cc.cve_id = c.id "
			"AND (lower(cc.cpe) = ? OR lower(cc.cpe) LIKE ? ESCAPE '\\'))"
		)
		params.extend([exact, prefix + "%"])

	if args.product:
		term = escape_like(args.product.strip().lower())
		if use_json:
			clauses.append(
				"EXISTS (SELECT 1 FROM json_each(COALESCE(c.products, '[]')) p "
				"WHERE lower(json_extract(p.value, '$.vendor')) LIKE ? ESCAPE '\\' "
				"OR lower(json_extract(p.value, '$.product')) LIKE ? ESCAPE '\\')"
			)
			params.extend(["%" + term + "%", "%" + term + "%"])
		else:
			clauses.append("lower(COALESCE(c.products, '')) LIKE ? ESCAPE '\\'")
			params.append("%" + term + "%")

	if args.cwe:
		cwe = normalise_cwe(args.cwe).lower()
		if use_json:
			clauses.append(
				"EXISTS (SELECT 1 FROM json_each(COALESCE(c.cwes, '[]')) w "
				"WHERE lower(w.value) = ?)"
			)
			params.append(cwe)
		else:
			clauses.append("lower(COALESCE(c.cwes, '')) LIKE ? ESCAPE '\\'")
			params.append('%"' + escape_like(cwe) + '"%')

	if args.cvss_min is not None:
		clauses.append("c.cvss_score >= ?")
		params.append(float(args.cvss_min))

	if args.cvss_max is not None:
		clauses.append("c.cvss_score <= ?")
		params.append(float(args.cvss_max))

	if args.kev:
		clauses.append("EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = c.id)")

	if args.keyword:
		clauses.append("lower(COALESCE(c.description, '')) LIKE ? ESCAPE '\\'")
		params.append("%" + escape_like(args.keyword.strip().lower()) + "%")

	where = " WHERE " + " AND ".join(clauses) if clauses else ""
	filters = {
		"product": args.product,
		"cpe": args.cpe,
		"cwe": args.cwe,
		"cvss_min": args.cvss_min,
		"cvss_max": args.cvss_max,
		"kev": bool(args.kev),
		"keyword": args.keyword,
	}
	return where, params, filters


def cmd_search(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""Search the local CVE database."""
	where, params, filters = build_search_query(conn, args)
	limit = normalise_limit(args.limit)

	total_row = conn.execute(
		"SELECT COUNT(*) AS total FROM cves c" + where, params
	).fetchone()
	total = int(total_row["total"]) if total_row else 0

	sql = f"SELECT {SELECT_COLUMNS} {FROM_CVES}{where} ORDER BY c.published DESC, c.id DESC"
	if limit:
		sql += " LIMIT ?"
		results = conn.execute(sql, params + [limit]).fetchall()
	else:
		results = conn.execute(sql, params).fetchall()

	return {
		"ok": True,
		"command": "search",
		"filters": filters,
		"total": total,
		"count": len(results),
		"limit": limit,
		"results": [cve_row_to_dict(row) for row in results],
	}


def cmd_by_cpe(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""List the CVEs configured for a CPE."""
	exact, prefix = cpe_prefix_pattern(args.cpe)
	limit = normalise_limit(args.limit)
	params = [exact, prefix + "%"]
	where = (
		" WHERE EXISTS (SELECT 1 FROM cve_cpe cc WHERE cc.cve_id = c.id "
		"AND (lower(cc.cpe) = ? OR lower(cc.cpe) LIKE ? ESCAPE '\\'))"
	)
	total_row = conn.execute("SELECT COUNT(*) AS total FROM cves c" + where, params).fetchone()
	total = int(total_row["total"]) if total_row else 0

	sql = f"SELECT {SELECT_COLUMNS} {FROM_CVES}{where} ORDER BY c.published DESC, c.id DESC"
	if limit:
		rows = conn.execute(sql + " LIMIT ?", params + [limit]).fetchall()
	else:
		rows = conn.execute(sql, params).fetchall()

	return {
		"ok": True,
		"command": "by-cpe",
		"cpe": args.cpe,
		"total": total,
		"count": len(rows),
		"limit": limit,
		"results": [cve_row_to_dict(row) for row in rows],
	}


def cmd_kev(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""List the Known Exploited Vulnerabilities catalog."""
	limit = normalise_limit(args.limit)
	total_row = conn.execute("SELECT COUNT(*) AS total FROM kev").fetchone()
	total = int(total_row["total"]) if total_row else 0

	sql = (
		"SELECT cve_id, vendor, product, vuln_name, date_added, due_date, ransomware "
		"FROM kev ORDER BY date_added DESC, cve_id DESC"
	)
	if limit:
		rows = conn.execute(sql + " LIMIT ?", (limit,)).fetchall()
	else:
		rows = conn.execute(sql).fetchall()

	results = []
	for row in rows:
		item = dict(row)
		item["kev"] = True
		results.append(item)
	return {
		"ok": True,
		"command": "kev",
		"total": total,
		"count": len(results),
		"limit": limit,
		"results": results,
	}


def database_counts(conn: sqlite3.Connection) -> dict[str, int]:
	"""Count the rows of every table."""
	counts: dict[str, int] = {}
	for table in ("cves", "cve_cpe", "kev", "epss"):
		row = conn.execute(f"SELECT COUNT(*) AS total FROM {table}").fetchone()
		counts[table] = int(row["total"]) if row else 0
	return counts


def cmd_stats(conn: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
	"""Summarise the content of the local database."""
	counts = database_counts(conn)
	severity: dict[str, int] = {}
	for row in conn.execute(
		"SELECT COALESCE(severity, 'UNKNOWN') AS severity, COUNT(*) AS total "
		"FROM cves GROUP BY severity ORDER BY total DESC"
	):
		severity[row["severity"]] = int(row["total"])
	top_cwes: list[dict[str, Any]] = []
	if json1_available(conn):
		for row in conn.execute(
			"SELECT lower(w.value) AS cwe, COUNT(*) AS total "
			"FROM cves c, json_each(COALESCE(c.cwes, '[]')) w "
			"GROUP BY lower(w.value) ORDER BY total DESC LIMIT 10"
		):
			top_cwes.append({"cwe": row["cwe"], "count": int(row["total"])})

	path = database_path(args.db)
	try:
		size = os.path.getsize(path)
	except OSError:
		size = 0

	return {
		"ok": True,
		"command": "stats",
		"database": {"path": path, "exists": os.path.exists(path), "size_bytes": size},
		"counts": counts,
		"severity": severity,
		"top_cwes": top_cwes,
		"last_sync": {
			"nvd": meta_get(conn, "nvd_last_sync"),
			"nvd_watermark": meta_get(conn, "nvd_last_modified"),
			"kev": meta_get(conn, "kev_last_sync"),
			"kev_catalog_version": meta_get(conn, "kev_catalog_version"),
			"epss": meta_get(conn, "epss_last_sync"),
			"epss_date": meta_get(conn, "epss_date"),
		},
		"schema_version": meta_get(conn, "schema_version"),
	}


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------


class JsonArgumentParser(argparse.ArgumentParser):
	"""An argument parser that reports errors as JSON instead of text."""

	def error(self, message: str) -> None:  # type: ignore[override]
		raise CvedbError(f"argument error: {message}")


def build_parser() -> JsonArgumentParser:
	"""Build the command line parser."""
	common = argparse.ArgumentParser(add_help=False)
	common.add_argument(
		"--db",
		metavar="PATH",
		help="path of the SQLite database (defaults to $CYBERPI_CVE_DB or ~/.cyberpi/cve.db)",
	)

	parser = JsonArgumentParser(
		prog="cvedb.py",
		description="Offline CVE intelligence backend for CyberPi.",
	)
	subparsers = parser.add_subparsers(dest="command", metavar="command")

	sync_parser = subparsers.add_parser(
		"sync", parents=[common], help="refresh the local mirror of the CVE data sets"
	)
	sync_parser.add_argument(
		"--full", action="store_true", help="re-download the whole catalogue"
	)
	sync_parser.add_argument(
		"--no-kev", action="store_true", help="skip the CISA KEV catalog"
	)
	sync_parser.add_argument(
		"--no-epss", action="store_true", help="skip the FIRST EPSS scores"
	)

	get_parser = subparsers.add_parser(
		"get", parents=[common], help="show one CVE with its KEV and EPSS data"
	)
	get_parser.add_argument("cve_id", metavar="cve-id", help="identifier, e.g. CVE-2021-44228")
	get_parser.add_argument("--json", action="store_true", help="print JSON (default)")

	search_parser = subparsers.add_parser(
		"search", parents=[common], help="search the local CVE database"
	)
	search_parser.add_argument("--product", metavar="NAME", help="CPE vendor or product name")
	search_parser.add_argument("--cpe", metavar="CPE", help="CPE prefix to match")
	search_parser.add_argument("--cwe", metavar="CWE", help="weakness identifier, e.g. CWE-79")
	search_parser.add_argument("--cvss-min", dest="cvss_min", type=float, metavar="N")
	search_parser.add_argument("--cvss-max", dest="cvss_max", type=float, metavar="N")
	search_parser.add_argument(
		"--kev", action="store_true", help="only Known Exploited Vulnerabilities"
	)
	search_parser.add_argument("--keyword", metavar="TEXT", help="text to find in the description")
	search_parser.add_argument("--limit", type=int, metavar="N", help="maximum number of rows")
	search_parser.add_argument("--json", action="store_true", help="print JSON (default)")

	by_cpe_parser = subparsers.add_parser(
		"by-cpe", parents=[common], help="list the CVEs configured for a CPE"
	)
	by_cpe_parser.add_argument("cpe", metavar="cpe", help="CPE prefix, e.g. cpe:2.3:a:apache:log4j")
	by_cpe_parser.add_argument("--limit", type=int, metavar="N", help="maximum number of rows")
	by_cpe_parser.add_argument("--json", action="store_true", help="print JSON (default)")

	kev_parser = subparsers.add_parser(
		"kev", parents=[common], help="list the Known Exploited Vulnerabilities catalog"
	)
	kev_parser.add_argument("--limit", type=int, metavar="N", help="maximum number of rows")
	kev_parser.add_argument("--json", action="store_true", help="print JSON (default)")

	stats_parser = subparsers.add_parser(
		"stats", parents=[common], help="summarise the content of the database"
	)
	stats_parser.add_argument("--json", action="store_true", help="print JSON (default)")

	return parser


def run_command(args: argparse.Namespace) -> dict[str, Any]:
	"""Dispatch the parsed command."""
	command = args.command
	if command == "sync":
		conn = connect(database_path(args.db))
		try:
			init_schema(conn)
			return cmd_sync(conn, args)
		finally:
			conn.close()

	conn = connect(database_path(args.db), readonly=True)
	try:
		if command == "get":
			return cmd_get(conn, args)
		if command == "search":
			return cmd_search(conn, args)
		if command == "by-cpe":
			return cmd_by_cpe(conn, args)
		if command == "kev":
			return cmd_kev(conn, args)
		if command == "stats":
			return cmd_stats(conn, args)
		raise CvedbError(f"unknown command: {command}")
	finally:
		conn.close()


def main(argv: Sequence[str] | None = None) -> int:
	"""Entry point: run one command and print its JSON result."""
	parser = build_parser()
	try:
		args = parser.parse_args(list(argv) if argv is not None else None)
	except CvedbError as exc:
		print(json.dumps({"ok": False, "error": str(exc)}))
		return 1
	if not args.command:
		print(json.dumps({"ok": False, "error": "a command is required"}))
		parser.print_help(sys.stderr)
		return 1

	try:
		result = run_command(args)
	except CvedbError as exc:
		print(json.dumps({"ok": False, "command": args.command, "error": str(exc)}))
		return 1
	except KeyboardInterrupt:
		print(
			json.dumps(
				{
					"ok": False,
					"command": args.command,
					"error": "interrupted, the database was left consistent and the sync can be re-run",
				}
			)
		)
		return 130
	except sqlite3.Error as exc:
		print(json.dumps({"ok": False, "command": args.command, "error": f"database error: {exc}"}))
		return 1
	except Exception as exc:  # noqa: BLE001 - the CLI never shows a traceback
		print(
			json.dumps(
				{
					"ok": False,
					"command": args.command,
					"error": f"unexpected {type(exc).__name__}: {exc}",
				}
			)
		)
		return 1

	print(json.dumps(result, indent=2, sort_keys=False, default=str))
	return 0


if __name__ == "__main__":
	sys.exit(main())
