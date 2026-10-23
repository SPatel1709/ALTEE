"""Build comparable ABAC/TEE benchmark datasets from one MuSimA output ZIP.

This script only writes generated datasets. It never touches /etc/abac,
securityfs, the TEE daemon, or protected files.
"""

import argparse
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

from convert_musima import check_layout, parse_rule


SIZES = (10, 50, 100, 500, 1000)
PERCENTS = (25, 50, 75, 100)
ORDER = ("SA_1", "SA_2", "SA_3", "OA_1", "OA_2", "OA_3", "EA_1", "EA_2")


def read_master(path):
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith("/outputs/output.json")]
            if len(names) != 1:
                raise ValueError("ZIP must contain exactly one outputs/output.json")
            raw = archive.read(names[0])
    else:
        raw = path.read_bytes()
    data = json.loads(raw)
    check_layout(data)
    if len(data["S"]) != 200 or len(data["O"]) != 200:
        raise ValueError("Expected 200 subjects and 200 objects")
    return data, hashlib.sha256(raw).hexdigest()


def unique_rules(data):
    pools = {}
    for effect, key in (("ALLOW", "permit_rules"), ("DENY", "deny_rules")):
        pool = {}
        for source_index, text in enumerate(data[key], 1):
            fields = parse_rule(text, data)
            signature = tuple(fields[name] for name in ORDER)
            pool.setdefault(signature, (effect, text, signature, source_index))
        pools[effect] = list(pool.values())
        print(f"{effect}: {len(data[key])} generated, {len(pool)} distinct")
    if len(pools["ALLOW"]) < 800 or len(pools["DENY"]) < 200:
        raise ValueError("Not enough distinct permit/deny rules for an 800/200 policy")
    return pools


def subject_profiles(data, subject):
    if subject not in data["SV"]:
        raise ValueError(f"Unknown subject {subject}")
    environment = ("weekday", "working_hours")
    profiles = {}
    for obj in data["O"]:
        profiles[obj] = tuple(data["SV"][subject] + data["OV"][obj] + list(environment))
    return profiles


def choose_anchors(data, pools, subject):
    profiles = subject_profiles(data, subject)
    grouped = {}
    for obj, signature in profiles.items():
        grouped.setdefault(signature, []).append(obj)

    deny_signatures = {rule[2] for rule in pools["DENY"]}
    permits = [rule for rule in pools["ALLOW"] if rule[2] in grouped and rule[2] not in deny_signatures]
    denies = [rule for rule in pools["DENY"] if rule[2] in grouped]
    if len(permits) < 2 or len(denies) < 2:
        raise ValueError(f"{subject} needs two stable permits and two explicit denies; choose another subject")

    # Prefer conditions exercised by more than one object; the selected object
    # still appears just once in the fixed workload.
    permits.sort(key=lambda rule: (-len(grouped[rule[2]]), rule[3]))
    denies.sort(key=lambda rule: (-len(grouped[rule[2]]), rule[3]))
    selected = {"ALLOW": permits[:2], "DENY": denies[:2]}
    fixed = [(effect, grouped[rule[2]][0]) for effect in ("ALLOW", "DENY") for rule in selected[effect]]
    if len({obj for _, obj in fixed}) != 4:
        raise ValueError("Fixed workload did not yield four distinct objects")
    return selected, fixed


def select_nested(pools, anchors, seed):
    rng = random.Random(seed)
    remaining = {}
    selected = {effect: list(anchors[effect]) for effect in ("ALLOW", "DENY")}
    for effect in selected:
        anchored = {rule[2] for rule in anchors[effect]}
        remaining[effect] = [rule for rule in pools[effect] if rule[2] not in anchored]
        rng.shuffle(remaining[effect])

    policies = {}
    for size in SIZES:
        for effect, target in (("ALLOW", size * 4 // 5), ("DENY", size // 5)):
            needed = target - len(selected[effect])
            selected[effect].extend(remaining[effect][:needed])
            del remaining[effect][:needed]
        policies[size] = {effect: list(selected[effect]) for effect in selected}
    return policies


def selected_truth(data, policy, subject, fixed):
    signatures = {effect: {rule[2] for rule in policy[effect]} for effect in policy}
    profiles = subject_profiles(data, subject)
    for expected, obj in fixed:
        signature = profiles[obj]
        actual = "DENY" if signature in signatures["DENY"] else (
            "ALLOW" if signature in signatures["ALLOW"] else "DEFAULT_DENY")
        if actual != expected:
            raise ValueError(f"Fixed request {obj} changed from {expected} to {actual}")


def write_dataset(data, policy, subject, uid, master_sha, fixed, size, percent, root, base_dir):
    directory = root / f"D{size}_T{percent}"
    if directory.exists():
        raise ValueError(f"Output already exists: {directory}")

    subset = dict(data)
    subset["permit_rules"] = [rule[1] for rule in policy["ALLOW"]]
    subset["deny_rules"] = [rule[1] for rule in policy["DENY"]]
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "output.json"
        source.write_text(json.dumps(subset) + "\n")
        subprocess.run([
            sys.executable, str(Path(__file__).with_name("convert_musima.py")), str(source),
            "--output-dir", str(directory), "--base-dir", str(base_dir),
            "--tee-percent", str(percent), "--subject", subject, "--uid", str(uid),
        ], check=True)

    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.update({"master_sha256": master_sha, "series_size": size,
                     "permit_rules": size * 4 // 5, "deny_rules": size // 5,
                     "benchmark_subject": subject, "fixed_workload_objects": [obj for _, obj in fixed]})
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    paths = manifest["object_paths"]
    (directory / "workload_fixed.txt").write_text("".join(
        f"{effect} {paths[obj]}\n" for effect, obj in fixed))
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="MuSimA abac_outputs ZIP or output.json")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--subject", default="S_83")
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--base-dir", type=Path, default=Path("/home/secured/musima"))
    parser.add_argument("--seed", type=int, default=20261019)
    args = parser.parse_args()

    try:
        if args.uid < 1:
            raise ValueError("UID must be a positive non-root UID")
        base_dir = args.base_dir.resolve()
        if not base_dir.is_relative_to(Path("/home/secured")):
            raise ValueError("--base-dir must be inside /home/secured")
        if args.output_root.exists() and any(args.output_root.iterdir()):
            raise ValueError("Output root must be new or empty")

        data, master_sha = read_master(args.input)
        pools = unique_rules(data)
        anchors, fixed = choose_anchors(data, pools, args.subject)
        policies = select_nested(pools, anchors, args.seed)
        for size, policy in policies.items():
            selected_truth(data, policy, args.subject, fixed)

        args.output_root.mkdir(parents=True, exist_ok=True)
        sizes = {}
        for size, policy in policies.items():
            percents = PERCENTS if size == 1000 else (25,)
            sizes[size] = {}
            for percent in percents:
                directory = write_dataset(data, policy, args.subject, args.uid, master_sha,
                                          fixed, size, percent, args.output_root, base_dir)
                sizes[size][percent] = directory.name

        description = {
            "master_sha256": master_sha, "subject": args.subject, "uid": args.uid,
            "seed": args.seed, "sizes": sizes,
            "fixed_requests": [{"expected": effect, "object": obj} for effect, obj in fixed],
            "note": "Run under the configured weekday working-hours context. Use abac load --tee for updates."
        }
        (args.output_root / "series.json").write_text(json.dumps(description, indent=2) + "\n")
        counts = Counter(effect for effect, _ in fixed)
        print(f"Created {sum(map(len, sizes.values()))} datasets under {args.output_root}")
        print(f"Fixed read workload: {counts['ALLOW']} allow, {counts['DENY']} explicit deny")
    except (KeyError, ValueError, TypeError, OSError, zipfile.BadZipFile,
            subprocess.CalledProcessError) as error:
        parser.exit(1, f"Dataset series rejected: {error}\n")


if __name__ == "__main__":
    main()
