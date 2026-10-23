"""Write a read workload from a converted MuSimA dataset.

The output contains an expected decision and an absolute path on each line.
It does not change ABAC configuration or create protected files.
"""

import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--subject")
    parser.add_argument("--kind", choices=("all", "matched", "allow", "explicit-deny", "default-deny"),
                        default="matched")
    args = parser.parse_args()

    users = json.loads((args.dataset / "user_attr.json").read_text())["users"]
    if args.subject is None:
        if len(users) != 1:
            parser.error("Specify --subject when more than one subject is mapped")
        args.subject = next(iter(users))
    if args.subject not in users:
        parser.error(f"Subject {args.subject} is not mapped to a Linux user")
    uid = users[args.subject]["uid"]
    if os.getuid() != uid:
        parser.error(f"Run as UID {uid}; current UID is {os.getuid()}")

    paths = json.loads((args.dataset / "manifest.json").read_text())["object_paths"]
    decisions = json.loads((args.dataset / "expected_access.json").read_text())["decisions"]
    lines = []
    for row in decisions:
        if row["subject"] != args.subject:
            continue
        decision = row["expected"]
        matched = bool(row["matching_rule_ids"])
        kind = "allow" if decision == "ALLOW" else ("explicit-deny" if matched else "default-deny")
        if args.kind not in ("all", "matched", kind):
            continue
        if args.kind == "matched" and not matched:
            continue
        path = paths[row["object"]]
        if not path.startswith("/home/secured/") or any(c.isspace() for c in path):
            parser.error(f"Unsupported object path: {path}")
        lines.append(f"{decision} {path}\n")

    if not lines:
        parser.error(f"No requests for {args.subject} with --kind {args.kind}")
    args.output.write_text("".join(lines))
    print(f"Wrote {len(lines)} {args.kind} requests to {args.output}")


if __name__ == "__main__":
    main()
