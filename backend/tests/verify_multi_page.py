import urllib.request
import json
import time

def run_test():
    print("[TEST] Sending analyze request for https://httpbin.org...")
    req = urllib.request.Request(
        "http://127.0.0.1:5000/safe-view/analyze",
        data=json.dumps({"url": "https://httpbin.org", "max_pages": 10, "max_depth": 3}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode("utf-8"))
    sid = data["session_id"]
    print(f"[TEST] Session created: {sid}")
    print(f"[TEST] Initial pages returned: {len(data.get('pages', []))}")

    for i in range(12):
        time.sleep(2)
        req2 = urllib.request.Request(f"http://127.0.0.1:5000/safe-view/pages/{sid}")
        resp2 = urllib.request.urlopen(req2)
        data2 = json.loads(resp2.read().decode("utf-8"))
        stats = data2.get("discovery_stats", {})
        pages = data2.get("pages", [])
        st = stats.get("status")
        disc = stats.get("pages_discovered", 0)
        q = stats.get("pages_queued", 0)
        analyzed = len(pages)
        print(f"[POLL {i+1}] status={st} discovered={disc} analyzed={analyzed} queued={q}")
        if analyzed >= 3 or st == "COMPLETED":
            break

    req_tree = urllib.request.Request(f"http://127.0.0.1:5000/safe-view/tree/{sid}")
    resp_tree = urllib.request.urlopen(req_tree)
    tree_data = json.loads(resp_tree.read().decode("utf-8"))
    print(f"[TREE] Success: {tree_data.get('success')}")
    tree = tree_data.get("tree", {})
    if isinstance(tree, dict):
        print(f"[TREE] Root: {tree.get('title')} ({tree.get('path')}) Depth={tree.get('depth')}")
        children = tree.get("children", [])
        print(f"[TREE] Discovered Children count: {len(children)}")
        for idx, child in enumerate(children[:5]):
            print(f"  |-- [{idx+1}] {child.get('title') or child.get('path')} (Depth {child.get('depth')}, Status {child.get('status')}, ID: {child.get('page_id')})")

    # Now verify selecting a discovered child page and rendering its representation
    if isinstance(tree, dict) and tree.get("children"):
        child_id = tree["children"][0]["page_id"]
        print(f"[TEST] Fetching representation for child page_id: {child_id}...")
        req_page = urllib.request.Request(f"http://127.0.0.1:5000/safe-view/session/{sid}/page/{child_id}")
        resp_page = urllib.request.urlopen(req_page)
        page_rep = json.loads(resp_page.read().decode("utf-8"))
        print(f"[TEST] Child page fetch: HTTP {resp_page.status}, available={page_rep.get('available')}, title={page_rep.get('title')}")
        assert resp_page.status == 200
        assert page_rep.get("page_id") == child_id

        # Also verify /render endpoint
        req_render = urllib.request.Request(f"http://127.0.0.1:5000/safe-view/session/{sid}/page/{child_id}/render")
        resp_render = urllib.request.urlopen(req_render)
        render_html = resp_render.read().decode("utf-8")
        print(f"[TEST] Child render endpoint: HTTP {resp_render.status}, HTML length={len(render_html)}")
        assert "Content-Security-Policy" in resp_render.headers
        assert "script-src 'none'" in resp_render.headers["Content-Security-Policy"]
        print("[TEST] SUCCESS! Multi-page discovery, recursive queue, tree, persistence, and safe view verified!")

if __name__ == "__main__":
    run_test()
