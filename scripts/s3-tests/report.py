"""Turn an s3-tests junit file into results.csv and summary.md.

    report.py <junit.xml> <out-dir> [--commit SHA] [--s3tests-commit SHA]
              [--previous results.csv]

Each failure is labelled from known-failures.csv (next to this script): why
it fails, in one of these categories:

  not-implemented-by-design  left out on purpose (ACL grants, SigV2, IAM API...)
  aws-compatible-already     ObjectIO does what AWS does; the test expects RGW
  test-environment           the test can't pass on this setup
  gap                        a feature we lack and could add
  bug                        wrong behaviour to fix

A failure not in that file is "uncategorized": look at it, then add it.
With --previous, the summary lists tests whose outcome changed.
"""

import argparse
import collections
import csv
import os
import re
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
FAILED = ("failed", "error")


def parse(junit):
    rows = []
    for case in ET.parse(junit).iter("testcase"):
        test_file = case.get("classname", "").split(".")[-1]
        test_id = f"{test_file}::{case.get('name')}"
        outcome, message = "passed", ""
        for tag in ("failure", "error", "skipped"):
            el = case.find(tag)
            if el is not None:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
                text = (el.get("message") or "") + "\n" + (el.text or "")
                found = re.findall(
                    r"(?:botocore\.\S+: \([^)]*\)[^\n]{0,160}|AssertionError[^\n]{0,160}"
                    r"|assert [^\n]{0,160}|E\s+[^\n]{0,200})",
                    text,
                )
                message = " | ".join(dict.fromkeys(m.strip() for m in found[-3:]))
                if not message:
                    message = (el.get("message") or "").strip()
                message = message.replace("\n", " ")[:400]
                break
        rows.append({"test_id": test_id, "file": test_file, "outcome": outcome, "message": message})
    return rows


NOT_APPLICABLE = ("not-implemented-by-design", "test-environment", "aws-compatible-already")


def load_known():
    path = os.path.join(HERE, "known-failures.csv")
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        return {r["test_id"]: r for r in csv.DictReader(f)}


def normalize(test_id):
    """`test_s3::name` from either spelling: this script's, or the
    `s3tests/functional/test_s3.py::name` of earlier reports. Without it
    an earlier report matches nothing, and nothing looks changed."""
    path, _, name = test_id.partition("::")
    stem = path.rsplit("/", 1)[-1].removesuffix(".py")
    return f"{stem}::{name}"


def load_previous(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, newline="") as f:
        return {normalize(r["test_id"]): r["outcome"] for r in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("junit")
    ap.add_argument("out_dir")
    ap.add_argument("--commit", default="?")
    ap.add_argument("--s3tests-commit", default="?")
    ap.add_argument("--date", default="")
    ap.add_argument("--platform", default="?")
    ap.add_argument("--previous")
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    rows = parse(a.junit)
    known = load_known()
    previous = load_previous(a.previous)
    for r in rows:
        k = known.get(r["test_id"], {})
        if r["outcome"] in FAILED:
            r["category"] = k.get("category") or "uncategorized"
            r["note"] = k.get("note", "")
        else:
            r["category"], r["note"] = "", ""

    with open(os.path.join(a.out_dir, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["test_id", "file", "outcome", "category", "note", "message"])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["test_id"]))

    totals = collections.Counter(r["outcome"] for r in rows)
    by_file = collections.defaultdict(collections.Counter)
    for r in rows:
        by_file[r["file"]][r["outcome"]] += 1
    failures = [r for r in rows if r["outcome"] in FAILED]
    by_cat = collections.Counter(r["category"] for r in failures)
    # Applicable: what a test can fairly ask of ObjectIO. Not skipped, and
    # not failing for a reason that isn't ObjectIO's to fix (a feature left
    # out by design, the test environment, a test expecting RGW over AWS).
    not_applicable = sum(by_cat[c] for c in NOT_APPLICABLE) + totals["skipped"]
    applicable = len(rows) - not_applicable

    out = [
        "# ceph s3-tests results",
        "",
        f"- Date: {a.date}",
        f"- ObjectIO commit: `{a.commit}`",
        f"- s3-tests commit: `{a.s3tests_commit}`",
        f"- Platform: {a.platform}",
        "",
        f"**Passes {totals['passed']} of {applicable} applicable tests** "
        f"({len(rows)} in all; {not_applicable} not applicable: "
        f"{totals['skipped']} skipped, "
        + ", ".join(f"{by_cat[c]} {c}" for c in NOT_APPLICABLE)
        + ").",
        "",
        f"{len(rows)} tests: {totals['passed']} passed, {totals['failed']} failed, "
        f"{totals['error']} errors, {totals['skipped']} skipped.",
        "",
        "## By file",
        "",
        "| File | Passed | Failed | Error | Skipped |",
        "|---|---|---|---|---|",
    ]
    for name, c in sorted(by_file.items()):
        out.append(f"| {name} | {c['passed']} | {c['failed']} | {c['error']} | {c['skipped']} |")
    out += ["", "## Failures by reason", "", "| Category | Count |", "|---|---|"]
    for cat, n in by_cat.most_common():
        out.append(f"| {cat} | {n} |")
    for cat in ("bug", "gap", "uncategorized"):
        listed = [r for r in failures if r["category"] == cat]
        if not listed:
            continue
        out += ["", f"### {cat}", ""]
        for r in listed:
            why = r["note"] or r["message"]
            out.append(f"- `{r['test_id']}`: {why}")
    if previous:
        now = {r["test_id"]: r["outcome"] for r in rows}
        fixed = sorted(t for t, o in now.items() if o == "passed" and previous.get(t) in FAILED)
        broke = sorted(t for t, o in now.items() if o in FAILED and previous.get(t) == "passed")
        out += ["", "## Changed since the previous run", ""]
        out.append(f"Now passing ({len(fixed)}):")
        out += [f"- `{t}`" for t in fixed] or ["- none"]
        out.append("")
        out.append(f"Now failing ({len(broke)}):")
        out += [f"- `{t}`" for t in broke] or ["- none"]
    with open(os.path.join(a.out_dir, "summary.md"), "w") as f:
        f.write("\n".join(out) + "\n")
    print(dict(totals), "uncategorized:", by_cat.get("uncategorized", 0))


if __name__ == "__main__":
    main()
