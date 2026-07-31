#!/usr/bin/env python3
"""
INSIDER BUY SCANNER - SEC Form 4 open-market purchase detector.

Finds insiders buying their own company's stock with their own money.

  1. Pulls recent Form 4 filings from EDGAR's "getcurrent" Atom feed.
     (NOTE: SEC returns 403 on the daily-index .idx files from cloud
     runners, but the Atom feed and the Archives XML both work fine.)
  2. Fetches each filing's XML.
  3. Keeps only TRANSACTION CODE "P" - open-market purchases.
     (Ignores grants "A", sales "S", tax withholding "F", gifts "G".)
  4. Scores what's left and writes alerts.json, ranked by conviction.

    python3 scanner.py            # scan the most recent filings

Rate limit: stay under 10 requests/sec.
"""

import gzip
import json
import os
import re
import sys
import time
import urllib.request
from datetime import date, datetime
from xml.etree import ElementTree as ET

# ----------------------------------------------------------------------
CONTACT = os.environ.get("SEC_CONTACT", "Insider Signal diegoball2344@gmail.com")

UA = {
    "User-Agent": CONTACT,
    "Accept-Encoding": "gzip, deflate",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

MIN_DOLLARS = 100000     # ignore buys under this
SLEEP = 0.15             # seconds between SEC requests (rate limit)
PAGE = 100               # filings per Atom page
MAX_PAGES = 12           # up to 1200 recent filings
OUT = "alerts.json"
# ----------------------------------------------------------------------


def get(url, tries=3):
    """Fetch with SEC-compliant headers, gzip handling, and retries."""
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
            time.sleep(2.0 * (attempt + 1))
    raise last


def recent_form4_filings():
    """Return filing directory URLs for recent Form 4s, via the Atom feed."""
    seen, dirs = set(), []
    for page in range(MAX_PAGES):
        url = ("https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent"
               "&type=4&company=&dateb=&owner=include&count=%d&start=%d"
               "&output=atom" % (PAGE, page * PAGE))
        try:
            raw = get(url).decode("utf-8", "ignore")
        except Exception as e:
            print("  feed page %d failed: %s" % (page, e))
            break

        # every filing links to .../data/<cik>/<accession>/<acc>-index.htm
        hrefs = re.findall(r'href="(https://www\.sec\.gov/Archives/edgar/data/'
                           r'\d+/\d+/[^"]*-index\.htm)"', raw)
        if not hrefs:
            break
        new = 0
        for h in hrefs:
            base = h.rsplit("/", 1)[0]
            if base not in seen:
                seen.add(base)
                dirs.append(base)
                new += 1
        print("  page %d: %d filings (%d new)" % (page + 1, len(hrefs), new))
        if new == 0:
            break
        time.sleep(SLEEP)
    return dirs


def filing_xml_url(base):
    """Find the primary Form 4 XML inside a filing directory."""
    try:
        listing = get(base + "/").decode("utf-8", "ignore")
    except Exception:
        return None
    for x in re.findall(r'href="[^"]*/([^"/]+\.xml)"', listing):
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
        if txt(tr, "transactionCode") != "P":
            continue
        if txt(tr, "transactionAcquiredDisposedCode/value") != "A":
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
    print("Pulling recent Form 4 filings from EDGAR ...")
    dirs = recent_form4_filings()
    print("  %d unique filings to check\n" % len(dirs))

    alerts = []
    for i, base in enumerate(dirs):
        time.sleep(SLEEP)
        xml_url = filing_xml_url(base)
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
                parsed["ticker"] or "?",
                "{:,}".format(parsed["total_value"]),
                parsed["insider"]))
        if (i + 1) % 100 == 0:
            print("  ... %d/%d scanned" % (i + 1, len(dirs)))

    alerts.sort(key=lambda a: -a["score"])
    with open(OUT, "w") as fh:
        json.dump({"scan_date": str(date.today()), "alerts": alerts},
                  fh, indent=2)
    print("\n%d qualifying buys -> %s" % (len(alerts), OUT))
    for a in alerts[:3]:
        print("  #%d  %s (%s) bought $%s of %s" % (
            a["score"], a["insider"], a["title"],
            "{:,}".format(a["total_value"]), a["ticker"] or "?"))


if __name__ == "__main__":
    main()
