"""Offline preprocessing only. Never fetch URLs; never print input records.

Deduplication is literal URL-string equality: no trimming, decoding, path,
query, fragment, scheme, or case normalization changes URL semantics.
Scheme-less values are parsed with // solely to locate their hostname.
Quarantine contains raw, potentially sensitive input and must remain private.
"""
import argparse
import collections
import csv
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
try:
    from offline_psl import OfflineDomainParser, LOCAL_PSL, PSL_SHA256
finally:
    sys.path.pop(0)

OUTPUT_ROOT = BACKEND / "ml/processed_data"
LABELS = {"benign": 0, "phishing": 1}
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_URL_LENGTH = 8192
MAX_ROWS = 1_000_000
MAX_CATEGORY_LENGTH = 64


def checked_path(path):
    """Reject traversal, device/UNC paths, aliases and existing reparse points.

    Intended for a local workspace controlled by the invoking user, not an
    adversarial concurrently writable filesystem (checks are not race-free).
    """
    text = os.fspath(path)
    if text.startswith(("\\\\", "//")):
        raise ValueError("Network/device paths are forbidden")
    parts = re.split(r"[/\\]", text)
    for i, part in enumerate(parts):
        if i == 0 and re.fullmatch(r"[A-Za-z]:", part):
            if len(text) < 3 or text[2] not in "/\\":
                raise ValueError("Drive-relative paths are forbidden")
            continue
        if part in (".", "..") or ":" in part or part.endswith((".", " ")) or re.search(r'[<>"|?*\x00-\x1f]', part):
            raise ValueError("Unsafe path component")
        if re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", part, re.I):
            raise ValueError("Reserved Windows path component")
    absolute = Path(os.path.abspath(text))
    for component in [*reversed(absolute.parents), absolute]:
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Symlinks/junctions/reparse points are forbidden")
    return absolute


def read_input(path):
    target = checked_path(path)
    info = target.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_INPUT_BYTES:
        raise ValueError("Input must be a bounded regular file without hard links")
    with target.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Input changed during opening")
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Input byte limit exceeded")
    return raw


def formula_cell(value):
    return isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))


def sensitive(url):
    """Conservative heuristics, not a guarantee that all secrets are detected."""
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL must be length-checked before sensitive detection")
    text = unquote(url)
    # Tokenize once, then fullmatch disjoint, bounded character runs. Avoid
    # unanchored nested/overlapping repetitions on attacker-controlled strings.
    keys = {"access_token", "auth_token", "api_key", "apikey", "password", "passwd", "secret", "sessionid", "session_id", "token", "email"}
    for item in re.split(r"[?&#]", text):
        key, separator, value = item.partition("=")
        if separator and key.lower() in keys and value and not value[0].isspace():
            return True
    if "@" in text:
        # Conservative superset of email-like indicators, including encoded text.
        return True
    # Fixed prefixes, bounded runs and disjoint literal separators preserve
    # previous substring indicators without nested ambiguous repetitions.
    if any(re.search(pattern, text, re.I) for pattern in (
        r"\beyJ[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,8192}\b",
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,8192}|sk-[A-Za-z0-9_-]{20,8192}|AIza[\w-]{30,8192})\b",
    )):
        return True
    return any(marker in text.upper() for marker in (
        "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"))


def validate_url(url, parser):
    reasons = set()
    if not isinstance(url, str) or not url:
        return {"missing_url", "missing_hostname"}, None
    if len(url) > MAX_URL_LENGTH:
        return {"url_length_limit", "malformed_url"}, None
    if formula_cell(url):
        return {"spreadsheet_formula", "malformed_url"}, None
    if sensitive(url):
        reasons.add("sensitive_indicator")
    if re.search(r"[\x00-\x20\x7f]", url) or "\\" in url or re.search(r"%(?![0-9a-fA-F]{2})", url):
        reasons.add("malformed_url")
    try:
        explicit = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
        # Recognize host:port as scheme-less, but reject other unsupported schemes.
        has_scheme = bool(explicit and not re.match(r"^[^/:]+:\d+(?:/|$)", url))
        parsed = urlsplit(url if has_scheme or url.startswith("//") else "//" + url)
        if has_scheme and parsed.scheme.lower() not in ("http", "https"):
            reasons.add("malformed_url")
        if parsed.username is not None or parsed.password is not None:
            reasons.add("sensitive_indicator")
        _ = parsed.port
        host = parsed.hostname
        if not host:
            reasons.add("missing_hostname")
            return reasons, None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
            if len(ascii_host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in ascii_host.split(".")):
                reasons.add("malformed_url")
                return reasons, None
            if re.fullmatch(r"[0-9.]+", ascii_host):
                reasons.add("malformed_url")
                return reasons, None
        try:
            group = parser.group(host)
        except (ValueError, UnicodeError):
            reasons.add("unrecognized_registrable_domain")
            group = None
        return reasons, group
    except (ValueError, UnicodeError):
        reasons.add("malformed_url")
        return reasons, None


def prepare(records, parser, seed=42, balance_train=False):
    """Pure in-memory preparation; callers must not log returned private rows."""
    bounded = []
    for row in records:
        if len(bounded) >= MAX_ROWS:
            raise ValueError("Row limit exceeded")
        if any(value is not None and not isinstance(value, str) for value in row.values()):
            raise ValueError("Input fields must be strings")
        if len(row.get("type") or "") > MAX_CATEGORY_LENGTH:
            raise ValueError("Category length limit exceeded")
        bounded.append(row)
    records = bounded
    seen_labels = collections.defaultdict(set)
    for row in records:
        seen_labels[row.get("url")].add(row.get("type"))
    conflicts = {url for url, labels in seen_labels.items() if len(labels) > 1}
    clean, quarantine, seen = [], [], set()
    exclusions = collections.Counter()
    for row in records:
        url, category = row.get("url"), row.get("type")
        if category not in LABELS:
            exclusions["excluded_category"] += 1
            continue
        reasons, group = validate_url(url, parser)
        if url in conflicts:
            reasons.add("conflicting_exact_url_labels")
        if reasons:
            quarantine.append({"url": url, "type": category, "reasons": ";".join(sorted(reasons))})
            exclusions.update(reasons)
            continue
        if url in seen:
            exclusions["duplicate_excess_rows"] += 1
            continue
        seen.add(url)
        clean.append({"url": url, "label": LABELS[category], "group": group})
    groups = sorted({row["group"] for row in clean})
    if len(groups) < 3:
        raise ValueError("At least three clean domain/IP groups are required; no split generated")
    random.Random(seed).shuffle(groups)
    ntest = max(1, int(len(groups) * 0.15))
    nvalidation = max(1, int(len(groups) * 0.15))
    membership = {group: ("test" if i < ntest else "validation" if i < ntest+nvalidation else "train") for i, group in enumerate(groups)}
    splits = {name: [] for name in ("train", "validation", "test")}
    for row in clean:
        splits[membership[row["group"]]].append(row)
    if any({row["label"] for row in rows} != {0, 1} for rows in splits.values()):
        raise ValueError("Each domain-disjoint split must contain both classes; chosen split is unsuitable")
    before_balance = len(splits["train"])
    if balance_train:
        bins = [[r for r in splits["train"] if r["label"] == label] for label in (0, 1)]
        if not all(bins):
            raise ValueError("Training split lacks a class; cannot balance")
        rng = random.Random(seed)
        size = min(map(len, bins))
        splits["train"] = [r for bucket in bins for r in rng.sample(bucket, size)]
    group_sets = {name: {r["group"] for r in rows} for name, rows in splits.items()}
    overlaps = {a+"_"+b: len(group_sets[a] & group_sets[b]) for a,b in (("train","validation"),("train","test"),("validation","test"))}
    if any(overlaps.values()):
        raise ValueError("Group overlap detected")
    manifest = {
        "input_rows": len(records), "accepted_before_balancing": len(clean),
        "input_accepted_category_counts": {category: sum(row.get("type") == category for row in records) for category in LABELS},
        "input_other_category_rows": sum(row.get("type") not in LABELS for row in records),
        "quarantined_rows": len(quarantine), "exclusions_overlapping": dict(exclusions),
        "label_mapping": LABELS, "seed": seed,
        "deduplication": "literal string equality; no semantic normalization",
        "split_policy": "seeded shuffle of sorted groups; 15% test/15% validation groups, remainder train; sizes may differ by rows",
        "balancing": "train-only downsampling" if balance_train else "none",
        "training_rows_removed_by_balancing": before_balance-len(splits["train"]),
        "group_overlap_counts": overlaps,
        "splits": {name: {"rows": len(rows), "groups": len(group_sets[name]), "label_counts": {str(label): sum(r["label"] == label for r in rows) for label in (0,1)}} for name,rows in splits.items()},
        "provenance_and_license": "unverified",
        "sensitive_detection": "heuristic indicators only; not a guarantee of secret removal",
    }
    return splits, quarantine, manifest


def make_private(directory):
    """Restrict access before writing data; Windows ACL failure is fatal."""
    if os.name == "nt":
        identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                  check=True, capture_output=True, text=True)
        sid = next(csv.reader([identity.stdout.strip()]))[-1]
        if not re.fullmatch(r"S-1-(?:\d+-)*\d+", sid):
            raise ValueError("Unable to establish current Windows identity")
        subprocess.run(["icacls", str(directory), "/inheritance:r", "/grant:r", "*"+sid+":(OI)(CI)F"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        directory.chmod(0o700)


def validate_exports(directory, splits, quarantine):
    for name, rows in [*splits.items(), ("quarantine", quarantine)]:
        with (directory / (name+".csv")).open(encoding="utf-8", newline="") as stream:
            exported = list(csv.DictReader(stream))
        if len(exported) != len(rows) or any(formula_cell(value) for row in exported for value in row.values()):
            raise ValueError("Export validation failed")
        if name != "quarantine":
            if any(a["url"] != b["url"] or a["label"] != str(b["label"]) for a,b in zip(exported,rows)):
                raise ValueError("Training values changed during export")


def publish(splits, quarantine, manifest, run_name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_name):
        raise ValueError("Invalid run name")
    root = checked_path(OUTPUT_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    checked_path(root)
    output = checked_path(root / run_name)
    if output.exists():
        raise ValueError("Run directory already exists")
    staging = Path(tempfile.mkdtemp(prefix="_pending_", dir=root))
    try:
        make_private(staging)
        checksums = {}
        for name, rows, columns in [(name, rows, ["url", "label"]) for name,rows in splits.items()] + [("quarantine", quarantine, ["url", "type", "reasons"])]:
            target = staging / (name + ".csv")
            with target.open("x", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    values = {key: row.get(key) for key in columns}
                    if name == "quarantine":
                        # Quarantine is an inspection export, never training input.
                        values = {key: "'"+value if formula_cell(value) else value for key,value in values.items()}
                    elif any(formula_cell(value) for value in values.values()):
                        raise ValueError("Unsafe training cell; refusing to alter URL")
                    writer.writerow(values)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                target.chmod(0o600)
            checksums[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
        validate_exports(staging, splits, quarantine)
        report = dict(manifest, output_checksums=checksums,
                      quarantine_formula_policy="apostrophe-prefix formula-leading cells; never used for training")
        target = staging / "audit_manifest.json"
        with target.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            target.chmod(0o600)
        checked_path(root)
        checked_path(staging)
        checked_path(output)
        if output.exists():
            raise ValueError("Run appeared during preparation")
        # Sibling-directory rename publishes only a complete validated run.
        staging.rename(output)
    finally:
        if staging.exists():
            checked_path(staging)
            if staging.parent != root or not staging.name.startswith("_pending_"):
                raise ValueError("Refusing unsafe cleanup target")
            shutil.rmtree(staging)


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--input", type=Path, required=True)
    arguments.add_argument("--run-name", required=True)
    arguments.add_argument("--seed", type=int, default=42)
    arguments.add_argument("--balance-train", action="store_true")
    args = arguments.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", args.run_name):
        arguments.error("run-name must contain only letters, digits, underscores and hyphens")
    parser = OfflineDomainParser()  # Fail before reading data if PSL is unavailable.
    checked_path(OUTPUT_ROOT / args.run_name)
    raw = read_input(args.input)
    import io
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
    if reader.fieldnames != ["url", "type"]:
        raise ValueError("Expected exactly url,type columns")
    records = []
    for row in reader:
        if len(records) >= MAX_ROWS:
            raise ValueError("Row limit exceeded")
        records.append(row)
    if any(None in row or any(value is None for value in row.values()) for row in records):
        raise ValueError("Irregular CSV structure; no output generated")
    splits, quarantine, manifest = prepare(records, parser, args.seed, args.balance_train)
    manifest.update({"input_sha256": hashlib.sha256(raw).hexdigest(), "psl_sha256": PSL_SHA256,
                     "psl_version": "2025-07-09_15-23-09_UTC", "publicsuffix2_version": importlib.metadata.version("publicsuffix2"),
                     "pipeline_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "parser_sha256": hashlib.sha256((BACKEND / "offline_psl.py").read_bytes()).hexdigest()})
    publish(splits, quarantine, manifest, args.run_name)
    print("Offline preprocessing complete; private outputs written to the ignored output directory.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never echo an exception that might contain a dataset value.
        print("Preprocessing failed; no success claimed. Check prerequisites and input structure privately.", file=sys.stderr)
        raise SystemExit(1)
