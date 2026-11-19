import os
import unittest
from unittest.mock import Mock, patch

import requests

from api_validation import __main__ as api


URL = "https://example.com/"
KEYS = dict.fromkeys(
    ("GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY"), "mock-key"
)
REPORT = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 0}, "last_analysis_date": 1700000000,
    "last_analysis_results": {"MockEngine": {"category": "undetected"}},
}}}


def response(payload=None, status=200):
    return Mock(status_code=status, headers={}, json=Mock(return_value=payload))


def scans(url):
    return {"results": [{"task": {
        "url": url, "uuid": "sample-scan", "time": "2026-11-17T12:00:00Z",
    }}]}


class ApiValidationTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, KEYS, clear=True)
        http = patch.object(api.requests, "get")
        environment.start()
        self.addCleanup(environment.stop)
        self.get = http.start()
        self.addCleanup(http.stop)

    def test_google_match_and_empty_result(self):
        self.get.side_effect = [
            response({"threats": [{"url": URL, "threatTypes": ["SOCIAL_ENGINEERING"]}],
                      "cacheDuration": "300s"}),
            response({"cacheDuration": "300s"}),
        ]
        self.assertEqual(api.google_check(URL).outcome, "MATCH")
        self.assertEqual(api.google_check(URL).outcome, "NO_MATCH")
        self.assertEqual(self.get.call_args.args, (api.GOOGLE,))
        self.assertEqual(self.get.call_args.kwargs["params"]["urls"], URL)

    def test_google_protobuf_match_and_empty_result(self):
        url = URL.encode("ascii")
        threat = bytes((10, len(url))) + url + b"\x12\x01\x02"
        duration = b"\x12\x03\x08\xac\x02"
        headers = {"Content-Type": "application/x-protobuf"}
        self.get.side_effect = [
            Mock(status_code=200, headers=headers, content=bytes((10, len(threat))) + threat + duration),
            Mock(status_code=200, headers=headers, content=duration),
            Mock(status_code=200, headers=headers, content=b"\x12\x05\x08"),
        ]
        self.assertEqual(api.google_check(URL).data, {
            "matches": [{"threat_types": ["SOCIAL_ENGINEERING"], "literal_url_match": True}],
            "cache_duration": "300s",
        })
        self.assertEqual(api.google_check(URL).outcome, "NO_MATCH")
        self.assertEqual(api.run_check("google", URL)["outcome"], "INVALID_RESPONSE")

    def test_vt_url_and_domain_use_separate_endpoints(self):
        self.get.return_value = response(REPORT)
        self.assertEqual(api.vt_check(URL).outcome, "REPORT")
        self.assertTrue(self.get.call_args.args[0].endswith("/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8"))
        self.assertEqual(api.vt_check(URL, domain=True).data["scope"], "domain")
        self.assertTrue(self.get.call_args.args[0].endswith("/domains/example.com"))

    def test_urlscan_results_and_empty_results(self):
        self.get.side_effect = [response(scans(URL)), response({"results": []})]
        result = api.urlscan_check(URL)
        self.assertEqual(result.data["candidates"][0]["scope"], "exact_url")
        self.assertEqual(api.urlscan_check(URL).outcome, "NO_CANDIDATES")
        self.assertIn("now-7d", self.get.call_args.kwargs["params"]["q"])
        self.assertIn("task.visibility:public", self.get.call_args.kwargs["params"]["q"])

    def test_partial_vt_report_uses_common_error_envelope(self):
        self.get.return_value = response({"data": {"attributes": {"last_analysis_date": 1700000000}}})
        result = api.run_check("vt-url", URL)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], {"code": "INCOMPLETE_REPORT", "http_status": 200})
        self.assertIsNone(result["data"]["engine_categories"])

    def test_public_search_excludes_nonpublic_records(self):
        payload = scans(URL)
        payload["results"][0]["task"]["visibility"] = "unlisted"
        self.get.return_value = response(payload)
        self.assertEqual(api.urlscan_check(URL).outcome, "NO_CANDIDATES")

    def test_candidate_search_adds_one_page_and_prioritizes_exact_url(self):
        first = scans("https://example.com/related")
        first["total"] = 30
        first["results"][0]["sort"] = [1000, "scan"]
        exact = scans("https://EXAMPLE.com:443")
        exact["results"][0]["task"]["uuid"] = "exact-scan"
        second = {"results": first["results"] + exact["results"]}
        self.get.side_effect = [response(first), response(second)]
        result = api.urlscan_check(URL)
        self.assertEqual([candidate["scope"] for candidate in result.data["candidates"]],
                         ["exact_url", "same_host"])
        self.assertEqual(result.data["pages_searched"], 2)
        self.assertTrue(result.data["additional_results_available"])
        self.assertEqual(self.get.call_args.kwargs["params"]["search_after"], "1000,scan")
        self.assertEqual(self.get.call_count, 2)

    def test_optional_page_error_preserves_first_page_and_reports_effective_scope(self):
        first = scans("https://example.com/related")
        first.update(total=30, search_date_limit_days=7)
        first["results"][0]["sort"] = [1000, "scan"]
        self.get.side_effect = [response(first), response(status=429)]
        result = api.urlscan_check(URL, days=30)
        self.assertEqual(result.outcome, "CANDIDATES")
        self.assertEqual(result.data["effective_days"], 7)
        self.assertEqual(result.data["supplement_error"], "RATE_LIMIT")
        self.assertEqual(len(result.data["candidates"]), 1)

    def test_vt_candidate_identifier_requires_a_matching_report_url(self):
        payload = {"data": {"id": "report-id", "attributes": {
            "url": "https://EXAMPLE.COM:443", "last_analysis_date": 1,
            "last_analysis_stats": {"harmless": 1},
            "last_analysis_results": {"engine": {"category": "harmless"}},
        }}}
        self.get.return_value = response(payload)
        self.assertEqual(api.vt_check(URL).data["exact_candidate_id"], "report-id")
        payload["data"]["attributes"]["url"] = "https://example.com/other"
        self.assertNotIn("exact_candidate_id", api.vt_check(URL).data)

    def test_no_chain_candidate_is_not_success(self):
        self.get.return_value = response({"results": []})
        result = api.run_check("chain", URL)
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "NO_CHAIN_CANDIDATE")
        self.get.assert_called_once()

    def test_chain_passes_candidate_url_to_vt(self):
        self.get.side_effect = [response(scans(URL)), response(REPORT)]
        result = api.chain_check("https://example.com/requested")
        self.assertEqual(result.outcome, "CHAIN_VERIFIED")
        self.assertEqual(result.data["scan_id"], "sample-scan")
        self.assertEqual(result.data["candidate_scope"], "same_host")
        self.assertEqual(self.get.call_args_list[0].args, (api.URLSCAN,))
        self.assertTrue(self.get.call_args_list[1].args[0].endswith("/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8"))

    def test_chain_reports_missing_detail(self):
        self.get.side_effect = [response(scans(URL)), response(status=404)]
        result = api.chain_check(URL)
        self.assertEqual(result.outcome, "DETAIL_UNAVAILABLE")
        self.assertEqual(result.data["detail_outcome"], "NO_RECORD")

    def test_chain_does_not_forward_other_historical_paths(self):
        self.get.return_value = response(scans("https://example.com/other"))
        self.assertEqual(api.chain_check(URL).outcome, "CANDIDATE_REVIEW_REQUIRED")
        self.get.assert_called_once()

    def test_missing_keys_skip_network(self):
        with patch.dict(os.environ, {}, clear=True):
            for check in (api.google_check, api.vt_check, api.urlscan_check):
                with self.subTest(check=check.__name__), self.assertRaises(api.CheckError) as error:
                    check(URL)
                self.assertEqual(error.exception.code, "MISSING_KEY")
        self.get.assert_not_called()

    def test_http_errors_for_each_provider(self):
        for check in (api.google_check, api.vt_check, api.urlscan_check):
            for status, code in ((400, "REQUEST_REJECTED"), (403, "AUTH_ERROR"),
                                 (429, "RATE_LIMIT"), (503, "UPSTREAM_ERROR")):
                self.get.return_value = response(status=status)
                with self.subTest(check=check.__name__, status=status):
                    with self.assertRaises(api.CheckError) as error:
                        check(URL)
                    self.assertEqual((error.exception.code, error.exception.status), (code, status))
        self.assertFalse(self.get.call_args.kwargs["allow_redirects"])

    def test_timeout_and_invalid_json(self):
        self.get.side_effect = requests.Timeout
        with self.assertRaises(api.CheckError) as timed_out:
            api.google_check(URL)
        self.assertEqual(timed_out.exception.code, "TIMEOUT")
        self.get.side_effect = None
        self.get.return_value = Mock(status_code=200, json=Mock(side_effect=ValueError))
        with self.assertRaises(api.CheckError) as invalid:
            api.urlscan_check(URL)
        self.assertEqual(invalid.exception.code, "INVALID_RESPONSE")

    def test_sensitive_or_invalid_url_is_rejected_before_request(self):
        for url in ("https://example.com/?token=value", "https://user@example.com/",
                    "http://127.0.0.1/", "https://example.com/#token", "https://test.local/"):
            with self.subTest(url=url), self.assertRaises(api.CheckError) as error:
                api.google_check(url)
            self.assertEqual(error.exception.code, "INVALID_INPUT")
        self.get.assert_not_called()
