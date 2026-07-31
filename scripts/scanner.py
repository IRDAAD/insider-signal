#!/usr/bin/env python3
"""
INSIDER BUY SCANNER - SEC Form 4 open-market purchase detector.

  1. Pulls the SEC EDGAR daily index of all filings for a given day.
  2. Keeps only Form 4s (insider transaction reports).
  3. Fetches each Form 4's XML and parses every transaction.
  4. Keeps only TRANSACTION CODE "P" - open-market purchases with the
     insider's own money. (Ignores grants "A", sales "S", tax "F", gifts "G".)
  5. Scores what's left and writes alerts.json, ranked by signal.

    python3 scanner.py                 # scan yesterday
    python3 scanner.py 2026-07-30      # scan a specific day

SEC blocks requests without a proper User-Agent and full headers.
Rate limit: stay under 10 requests/sec.
"""

import gzip
import json
import os
import re
import sys
import time
import urllib.request
from datetime import date, datetime, timedelta
from xml.etree import ElementTree as ET

# ----------------------------------------------------------------------
CONTACT = os.environ.get("SEC_CONTACT", "Insider Signal diegoball2344@gmail.com")

# SEC returns 403 unless these headers are all present and well-formed.
UA = {
    "User-Agent": CONTACT,
    "Accept-Encoding": "gzip, deflate",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

MIN_DOLLARS = 100000         # ignore buys under this
SLEEP = 0.15                 # seconds between SEC requests (rate limit)
OUT = "alerts.json"
# ----------------------------------------------------------------------


def get(url, tries=3):
    """Fetch a URL with SEC-compliant headers, gzip handling, and retries."""
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except Exception as e:
            last = e
            time.sleep(2.0 * (attempt + 1))   # back off; SEC throttles hard
    raise last


def quarter(d):
    return "QTR%d" % ((d.month - 1) // 3 + 1)


def daily_form4_index(d):
    """Return [{cik, company, path}] for every Form 4 filed on date d."""
    url = ("https://www.sec.gov/Archives/edgar/daily-index/"
           "%d/%s/form.%s.idx" % (d.year, quarter(d), d.strftime("%Y%m%d")))
    print("  index: %s" % url)
    try:
        raw = get(url).decode("latin-1")
    except Exception as e:
        print("  could not fetch daily index: %s" % e)
        return []
    out = []
    for line in raw.splitlines():
        if not line.startswith("4 "):   # exactly form "4", not 4/A, 424 etc.
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 5:
            out.append({"company": parts[1], "cik": parts[2], "path": parts[4]})
    return out


def filing_xml_url(path):
    """Given the .txt path from the index, find the filing's primary XML."""
    m = re.match(r"edgar/data/(\d+)/([\d-]+)\.txt", path)
    if not m:
        return None
    cik, acc = m.group(1), m.group(2).replace("-", "")
    base = "https://www.sec.gov/Archives/edgar/data/%s/%s" % (cik, acc)
    try:
        listing = get(base + "/").decode("utf-8", "ignore")
    except Exception:
        return None
    xmls = re.findall(r'href="[^"]*/([^"/]+\.xml)"', listing)
    for x in xmls:
        if "index" not in x.lower():
            return "%s/%s" % (base, x)
    return None


def parse_form4(xml_bytes):
    """Extract issuer, insider, and every code-P open-market buy."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None

    def txt(el, tag):
        n = el.find(".//" + tag)
        return n.text.strip() if n is not None and n.text else ""

    issuer = root.find(".//issuer")
    owner = root.find(".//reportingOwner")
    if issuer is None or owner is None:
        return None

    rel = owner.find(".//reportingOwnerRelationship")
    title = ""
    is_ceo = is_officer = is_dir = is_ten = False
    if rel is not None:
        is_officer = txt(rel, "isOfficer") in ("1", "true")
        is_dir = txt(rel, "isDirector") in ("1", "true")
        is_ten = txt(rel, "isTenPercentOwner") in ("1", "true")
        title = txt(rel, "officerTitle")
        is_ceo = bool(re.search(r"\bC\.?E\.?O\.?\b|chief exec", title, re.I))

    buys = []
    for tr in root.findall(".//nonDerivativeTransaction"):
        code = txt(tr, "transactionCode")
        acq = txt(tr, "transactionAcquiredDisposedCode/value")
        if code != "P" or acq != "A":
            continue
        try:
            shares = float(txt(tr, "transactionShares/value") or 0)
            price = float(txt(tr, "transactionPricePerShare/value") or 0)
            after = float(txt(tr, "sharesOwnedFollowingTransaction/value") or 0)
        except ValueError:
            continue
        if shares and price:
            buys.append({"date": txt(tr, "transactionDate/value"),
                         "shares": shares, "price": price,
                         "value": round(shares * price),
                         "owned_after": after})
    if not buys:
        return None

    total = sum(b["value"] for b in buys)
    owned_after = max(b["owned_after"] for b in buys)
    bought = sum(b["shares"] for b in buys)
    prior = owned_after - bought
    stake_pct = round(bought / prior * 100, 1) if prior > 0 else 999.0

    return {
        "ticker": txt(issuer, "issuerTradingSymbol"),
        "company": txt(issuer, "issuerName"),
        "insider": txt(owner, "rptOwnerName"),
        "title": title or ("Director" if is_dir else
                           "10% owner" if is_ten else "Insider"),
        "is_ceo": is_ceo, "is_officer": is_officer,
        "is_director": is_dir, "is_ten_pct": is_ten,
        "total_value": total,
        "avg_price": round(sum(b["price"] * b["shares"] for b in buys) / bought, 2),
        "shares": int(bought),
        "stake_increase_pct": stake_pct,
        "transactions": buys,
    }


def score(a):
    """Rank the signal. Bigger conviction = higher score."""
    s = 0
    v = a["total_value"]
    if v >= 5000000:
        s += 40
    elif v >= 1000000:
        s += 30
    elif v >= 500000:
        s += 20
    elif v >= 250000:
        s += 10
    else:
        s += 5
    if a["is_ceo"]:
        s += 30                       # CEO buying own stock = top signal
    elif a["is_officer"]:
        s += 20                       # CFO knows the numbers
    elif a["is_director"]:
        s += 10
    inc = a["stake_increase_pct"]     # doubling a stake >> topping up 1%
    if inc >= 50:
        s += 20
    elif inc >= 20:
        s += 12
    elif inc >= 10:
        s += 6
    return s


def main():
    if len(sys.argv) > 1:
        d = datetime.strptime(sys.argv[1], "%Y-%m-%d").date()
    else:
        d = date.today() - timedelta(days=1)

    # SEC posts nothing on weekends/holidays. Walk back to the last weekday
    # that actually has an index, up to 5 days.
    idx = []
    for back in range(5):
        day = d - timedelta(days=back)
        if day.weekday() >= 5:        # Sat/Sun
            continue
        print("Scanning Form 4s filed %s ..." % day)
        idx = daily_form4_index(day)
        print("  %d Form 4 filings in the daily index" % len(idx))
        if idx:
            d = day
            break

    alerts = []
    for i, f in enumerate(idx):
        time.sleep(SLEEP)
        xml_url = filing_xml_url(f["path"])
        if not xml_url:
            continue
        time.sleep(SLEEP)
        try:
            parsed = parse_form4(get(xml_url))
        except Exception:
            continue
        if parsed and parsed["total_value"] >= MIN_DOLLARS:
            parsed["score"] = score(parsed)
            parsed["filing_url"] = xml_url
            alerts.append(parsed)
            print("  BUY  %-6s $%14s  %s" % (
                parsed["ticker"],
                "{:,}".format(parsed["total_value"]),
                parsed["insider"]))
        if (i + 1) % 100 == 0:
            print("  ... %d/%d scanned" % (i + 1, len(idx)))

    alerts.sort(key=lambda a: -a["score"])
    with open(OUT, "w") as fh:
        json.dump({"scan_date": str(d), "alerts": alerts}, fh, indent=2)
    print("\n%d qualifying buys -> %s" % (len(alerts), OUT))
    if alerts:
        top = alerts[0]
        print("Top signal: %s (%s) bought $%s of %s" % (
            top["insider"], top["title"],
            "{:,}".format(top["total_value"]), top["ticker"]))


if __name__ == "__main__":
    main()
