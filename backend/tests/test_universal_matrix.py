"""
PhishGuard AI V7 — Universal Website Fetching Test Matrix
=========================================================
Executes Requirement 26 test suite across 15 website categories:
  TEST 1: Simple HTML
  TEST 2: React website
  TEST 3: Next.js website
  TEST 4: Vue/Angular website
  TEST 5: Slow website
  TEST 6: Website with many images
  TEST 7: Website with external scripts
  TEST 8: Redirecting website
  TEST 9: Multi-page website
  TEST 10: Website with failed third-party resources
  TEST 11: Website returning HTTP 403
  TEST 12: Website returning HTTP 404
  TEST 13: Website returning HTTP 500
  TEST 14: SSRF/private IP test
  TEST 15: Invalid URL test
"""

import sys
import time
import json
import urllib.request
import urllib.error

TEST_CASES = [
    ("TEST 1: Simple HTML", "https://example.com/"),
    ("TEST 2: React website", "https://react.dev/"),
    ("TEST 3: Next.js website", "https://nextjs.org/"),
    ("TEST 4: Vue/Angular website", "https://vuejs.org/"),
    ("TEST 5: Slow website", "https://httpbin.org/delay/2"),
    ("TEST 6: Website with many images", "https://wikimedia.org/"),
    ("TEST 7: Website with external scripts", "https://www.wikipedia.org/"),
    ("TEST 8: Redirecting website", "http://github.com/"),
    ("TEST 9: Multi-page website", "https://example.com/"),
    ("TEST 10: Website with failed subresources", "https://hdhub4u.fast/"),
    ("TEST 11: Website returning HTTP 403", "https://httpbin.org/status/403"),
    ("TEST 12: Website returning HTTP 404", "https://httpbin.org/status/404"),
    ("TEST 13: Website returning HTTP 500", "https://httpbin.org/status/500"),
    ("TEST 14: SSRF/private IP test", "http://127.0.0.1:8080/admin"),
    ("TEST 15: Invalid URL test", "htp://invalid-url-with-spaces and bad protocol"),
]

def run_single_test(test_name: str, target_url: str) -> dict:
    print(f"\n=======================================================")
    print(f"RUNNING {test_name}: {target_url}")
    print(f"=======================================================")
    t0 = time.perf_counter()

    # Pre-test DNS lookup for report
    dns_status = "N/A"
    try:
        import socket
        from urllib.parse import urlparse
        host = urlparse(target_url).hostname
        if host:
            ip = socket.gethostbyname(host)
            dns_status = f"RESOLVED ({ip})"
        else:
            dns_status = "INVALID_HOST"
    except Exception as e:
        dns_status = f"FAILED ({e})"

    # Dispatch to Safe View Analysis API
    payload = json.dumps({"url": target_url, "discover_pages": True}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:5000/safe-view/analyze",
        data=payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        res = urllib.request.urlopen(req, timeout=90)
        data = json.loads(res.read().decode("utf-8"))
        elapsed_s = round(time.perf_counter() - t0, 2)
        sid = data.get("session_id")
        root_page_id = data.get("root_page_id") or "p_root"

        # Fetch page representation
        page_data = {}
        if sid:
            try:
                page_req = urllib.request.Request(f"http://127.0.0.1:5000/safe-view/session/{sid}/page/{root_page_id}")
                with urllib.request.urlopen(page_req, timeout=10) as pres:
                    page_data = json.loads(pres.read().decode("utf-8"))
            except Exception:
                pass

        http_status = page_data.get("http_status") or data.get("http_status") or 200
        nav_time_ms = page_data.get("load_time_ms") or round(elapsed_s * 1000, 1)
        dom_status = "READY" if (page_data.get("safe_html") or data.get("pages")) else "EMPTY"
        screenshot_status = "READY" if page_data.get("screenshot_b64") else ("READY" if page_data.get("screenshot_available") else "UNAVAILABLE")
        failed_res = len(page_data.get("failed_resources") or [])
        pages_disc = data.get("discovery_stats", {}).get("pages_discovered", len(data.get("pages", [])))
        final_status = page_data.get("scan_status") or data.get("status") or ("AVAILABLE" if dom_status == "READY" else "UNAVAILABLE")

        report = {
            "test": test_name,
            "url": target_url,
            "dns": dns_status,
            "http_status": http_status,
            "navigation_time": f"{nav_time_ms}ms",
            "dom_status": dom_status,
            "screenshot_status": screenshot_status,
            "failed_resources": failed_res,
            "pages_discovered": pages_disc,
            "final_status": final_status,
            "elapsed_seconds": elapsed_s,
        }
        _print_report(report)
        return report

    except urllib.error.HTTPError as he:
        elapsed_s = round(time.perf_counter() - t0, 2)
        err_body = he.read().decode("utf-8", errors="ignore")
        err_json = {}
        try:
            err_json = json.loads(err_body)
        except Exception:
            pass

        final_status = "BLOCKED" if (he.code in (400, 403, 422) and "SSRF" in err_body.upper()) else f"REJECTED ({he.code})"
        report = {
            "test": test_name,
            "url": target_url,
            "dns": dns_status,
            "http_status": he.code,
            "navigation_time": f"{round(elapsed_s * 1000, 1)}ms",
            "dom_status": "N/A",
            "screenshot_status": "N/A",
            "failed_resources": 0,
            "pages_discovered": 0,
            "final_status": final_status,
            "elapsed_seconds": elapsed_s,
            "error_detail": err_json.get("error") or err_body[:100],
        }
        _print_report(report)
        return report

    except Exception as exc:
        elapsed_s = round(time.perf_counter() - t0, 2)
        report = {
            "test": test_name,
            "url": target_url,
            "dns": dns_status,
            "http_status": "ERROR",
            "navigation_time": f"{round(elapsed_s * 1000, 1)}ms",
            "dom_status": "ERROR",
            "screenshot_status": "ERROR",
            "failed_resources": 0,
            "pages_discovered": 0,
            "final_status": "FAILED",
            "elapsed_seconds": elapsed_s,
            "error_detail": str(exc),
        }
        _print_report(report)
        return report

def _print_report(r: dict) -> None:
    print(f"  URL:                 {r['url']}", flush=True)
    print(f"  DNS:                 {r['dns']}", flush=True)
    print(f"  HTTP status:         {r['http_status']}", flush=True)
    print(f"  Navigation time:     {r['navigation_time']}", flush=True)
    print(f"  DOM status:          {r['dom_status']}", flush=True)
    print(f"  Screenshot status:   {r['screenshot_status']}", flush=True)
    print(f"  Failed resources:    {r['failed_resources']}", flush=True)
    print(f"  Pages discovered:    {r['pages_discovered']}", flush=True)
    print(f"  Final status:        {r['final_status']}", flush=True)


if __name__ == "__main__":
    reports = []
    print("\n=======================================================")
    print("PHISHGUARD AI V7 — UNIVERSAL WEBSITE FETCHING TEST MATRIX")
    print("=======================================================")

    for name, url in TEST_CASES:
        res = run_single_test(name, url)
        reports.append(res)

    print("\n" + "=" * 80)
    print("TEST MATRIX SUMMARY REPORT (15 / 15 TESTS)")
    print("=" * 80)
    print(f"{'TEST CASE':<36} | {'HTTP':<5} | {'DOM':<6} | {'FAILED RES':<10} | {'FINAL STATUS':<12}")
    print("-" * 80)
    for r in reports:
        print(f"{r['test']:<36} | {str(r['http_status']):<5} | {r['dom_status']:<6} | {str(r['failed_resources']):<10} | {r['final_status']:<12}")
    print("=" * 80)
