import argparse
import asyncio
import json
import re
from datetime import datetime
import httpx

HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection"
]

ORIGIN = "https://attacker.example.com"


async def get_spec(client, source):
    if source.startswith("http"):
        response = await client.get(source)
        response.raise_for_status()
        text = response.text
    else:
        with open(source, "r", encoding="utf-8") as f:
            text = f.read()

    return json.loads(text)


def get_endpoints(spec):
    endpoints = []
    paths = spec.get("paths", {})
    methods = {"get", "post", "put", "delete", "patch"}

    for path, items in paths.items():
        for m in items.keys():
            if m.lower() in methods:
                endpoints.append({"path": path, "method": m.upper()})

    return endpoints


def check_cors(headers):
    origin = headers.get("Access-Control-Allow-Origin", "")
    creds = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if origin == ORIGIN and creds:
        return True, "Reflected Origin with Credentials"
    if origin == "*":
        return True, "Wildcard '*' Origin allowed"
    if origin == ORIGIN:
        return True, "Arbitrary Origin allowed"

    return False, "OK"


def check_headers(headers):
    present = {}
    for header in HEADERS:
        present[header] = header in headers

    missing = 0
    for is_set in present.values():
        if not is_set:
            missing += 1

    total = len(HEADERS)
    return f"{total - missing}/{total}", present


async def scan_url(client, base_url, ep):
    clean_path = re.sub(r"\{[^}]+\}", "1", ep["path"])
    url = f"{base_url.rstrip('/')}{clean_path}"

    req_headers = {
        "Content-Type": "application/json",
        "Origin": ORIGIN,
    }

    try:
        res = await client.request(ep["method"], url, headers=req_headers)

        score, header_text = check_headers(res.headers)
        vuln, cors_text = check_cors(res.headers)

        status = "VULN" if vuln else "OK"
        print(f"[{ep['method']}] {clean_path} -> {res.status_code} (CORS: {status}, Headers: {score})")

        return {
            "endpoint": clean_path,
            "method": ep["method"],
            "status_code": res.status_code,
            "cors": {"vulnerable": vuln, "details": cors_text},
            "headers": {"score": score, "details": header_text}
        }

    except Exception as e:
        print(f"Error scanning {url}: {e}")
        return None


async def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", default="https://petstore.swagger.io/v2/swagger.json")
    parser.add_argument("--base-url", default="https://petstore.swagger.io/v2")
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        try:
            spec = await get_spec(client, args.spec)
        except Exception as e:
            print(f"Error loading spec: {e}")
            return

        endpoints = get_endpoints(spec)
        print(f"{len(endpoints)} endpoints:\n")

        tasks = []
        for ep in endpoints:
            task = scan_url(client, args.base_url, ep)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

    report = {
        "target": args.base_url,
        "timestamp": datetime.now().isoformat(),
        "scanned_count": len(results),
        "results": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(run())
