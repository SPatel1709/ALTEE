"""Convert a MuSimA output.json into the configuration read by abac load.

This command only creates files under --output-dir. It does not load policy,
create Linux accounts, or touch /etc/abac or the securityfs interface.
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ATTRIBUTE_NAMES = {
    "SA_1": "SA_1", "SA_2": "SA_2", "SA_3": "SA_3",
    "OA_1": "OA_1", "OA_2": "OA_2", "OA_3": "OA_3",
    "EA_1": "day", "EA_2": "time",
}
ENV_VALUES = {"EA_1_1": "weekday", "EA_2_1": "working_hours"}
PROTECTED = {
    25: {"EA_1", "EA_2"},
    50: {"EA_1", "EA_2", "SA_1", "OA_1"},
    75: {"EA_1", "EA_2", "SA_1", "SA_2", "OA_1", "OA_2"},
    100: set(ATTRIBUTE_NAMES),
}
PAIR = re.compile(r"\s*((?:SA|OA|EA)_\d+)\s*=\s*((?:SA|OA|EA)_\d+_\d+)\s*\Z")


def check_layout(data):
    for group, expected in (("SA", 3), ("OA", 3), ("EA", 2)):
        names = [f"{group}_{i}" for i in range(1, expected + 1)]
        if data.get(group) != names:
            raise ValueError(f"Expected {group} attributes {names}")
        values = data.get({"SA": "SAV", "OA": "OAV", "EA": "EAV"}[group], {})
        if set(values) != set(names):
            raise ValueError(f"Missing or extra {group} value lists")
        for name, options in values.items():
            if not options or len(set(options)) != len(options):
                raise ValueError(f"Invalid values for {name}")
    if data["E"] != ["E_1"] or data["EAV"] != {
        "EA_1": ["EA_1_1"], "EA_2": ["EA_2_1"]
    }:
        raise ValueError("This benchmark needs one environment and fixed day/time values")
    if len(set(data["S"])) != len(data["S"]) or len(set(data["O"])) != len(data["O"]):
        raise ValueError("Duplicate subject or object ID")


def profile(data, entity, ids, attributes, value_lists):
    result = {}
    if set(data[entity]) != set(ids):
        raise ValueError(f"{entity} profiles do not match entity IDs")
    for entity_id in ids:
        values = data[entity][entity_id]
        if len(values) != len(attributes):
            raise ValueError(f"{entity_id} needs exactly {len(attributes)} values")
        row = {}
        for name, value in zip(attributes, values):
            if value not in data[value_lists][name]:
                raise ValueError(f"Invalid {name} value for {entity_id}: {value}")
            row[name] = ENV_VALUES[value] if name in ("EA_1", "EA_2") else value
        result[entity_id] = row
    return result


def parse_rule(text, data):
    fields = {}
    for part in text.split(","):
        match = PAIR.fullmatch(part)
        if not match:
            raise ValueError(f"Unsupported rule term: {part!r} (wildcards are not supported)")
        name, value = match.groups()
        key = {"SA": "SAV", "OA": "OAV", "EA": "EAV"}[name[:2]]
        if name in fields or name not in ATTRIBUTE_NAMES or value not in data[key][name]:
            raise ValueError(f"Duplicate or invalid rule term: {part!r}")
        fields[name] = ENV_VALUES[value] if name.startswith("EA") else value
    if set(fields) != set(ATTRIBUTE_NAMES):
        raise ValueError("Every rule must have all 8 attributes; use global_stars=0")
    return fields


def uid_mapping(args, data):
    if args.uid_map:
        if args.subject or args.uid is not None:
            raise ValueError("Choose --uid-map OR --subject with --uid")
        mapping = json.loads(args.uid_map.read_text())
    else:
        if not args.subject or args.uid is None:
            raise ValueError("Provide --subject S_1 --uid YOUR_UID, or --uid-map mapping.json")
        mapping = {args.subject: args.uid}
    if not isinstance(mapping, dict) or not mapping or not set(mapping).issubset(data["S"]):
        raise ValueError("UID mapping has unknown subjects or is empty")
    if any(type(uid) is not int or uid < 1 for uid in mapping.values()):
        raise ValueError("UIDs must be positive integers for non-root test accounts")
    if len(set(mapping.values())) != len(mapping):
        raise ValueError("Each subject must map to a distinct Linux UID")
    return mapping


def expected_decisions(rules, users, objects, environment):
    decisions = []
    counts = Counter()
    for subject, user in users.items():
        for obj, actual in objects.items():
            matches = [
                i for i, (effect, required) in enumerate(rules, start=1)
                if all(required[name] == source[name]
                       for group, source in (("SA", user), ("OA", actual), ("EA", environment))
                       for name in required if name.startswith(group))
            ]
            effect = "DENY" if any(rules[i - 1][0] == "DENY" for i in matches) else (
                "ALLOW" if matches else "DENY")
            counts[effect] += 1
            decisions.append({"subject": subject, "object": obj,
                              "expected": effect, "matching_rule_ids": matches})
    return decisions, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="MuSimA output.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--base-dir", type=Path, default=Path("/home/secured/musima"))
    parser.add_argument("--tee-percent", type=int, choices=tuple(PROTECTED), default=25)
    parser.add_argument("--subject", help="One MuSimA subject for a smoke test")
    parser.add_argument("--uid", type=int, help="Existing Linux UID for --subject")
    parser.add_argument("--uid-map", type=Path, help='JSON such as {"S_1": 1000, "S_2": 2001}')
    parser.add_argument("--allow-duplicates", action="store_true", help="Smoke tests only")
    args = parser.parse_args()

    try:
        data = json.loads(args.input.read_text())
        check_layout(data)
        if not args.base_dir.is_absolute() or not args.base_dir.resolve().is_relative_to(Path("/home/secured")):
            raise ValueError("--base-dir must be inside /home/secured")
        args.base_dir = args.base_dir.resolve()
        mapping = uid_mapping(args, data)
        users = profile(data, "SV", data["S"], data["SA"], "SAV")
        objects = profile(data, "OV", data["O"], data["OA"], "OAV")
        environment = profile(data, "EV", data["E"], data["EA"], "EAV")["E_1"]
        rules = [(effect, parse_rule(text, data)) for effect, group in
                 (("ALLOW", "permit_rules"), ("DENY", "deny_rules")) for text in data[group]]
        if not rules:
            raise ValueError("Dataset has no rules")
        signatures = [(effect, tuple(sorted(fields.items()))) for effect, fields in rules]
        duplicates = len(signatures) - len(set(signatures))
        if duplicates and not args.allow_duplicates:
            raise ValueError(f"{duplicates} duplicate rules; regenerate with another seed")
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise ValueError("Output directory is not empty; choose a fresh directory")

        protected = PROTECTED[args.tee_percent]
        policy = []
        for effect, fields in rules:
            sections = {}
            for group, key in (("SA", "user"), ("OA", "obj"), ("EA", "env")):
                sections[key] = {
                    ("tee:" if name in protected else "") + ATTRIBUTE_NAMES[name]: fields[name]
                    for name in fields if name.startswith(group)
                }
            policy.append({**sections, "op": "READ", "effect": effect})

        paths = {obj: str(args.base_dir / f"{obj}.txt") for obj in data["O"]}
        decisions, counts = expected_decisions(rules, {s: users[s] for s in mapping}, objects,
                                               environment)
        outputs = {
            "policy.json": {"rules": policy},
            "user_attr.json": {"users": {
                subject: {"uid": uid, "avps": {
                    ATTRIBUTE_NAMES[name]: value for name, value in users[subject].items()
                }} for subject, uid in mapping.items()
            }},
            "obj_attr.json": {"objects": {
                paths[obj]: {ATTRIBUTE_NAMES[name]: value for name, value in attrs.items()}
                for obj, attrs in objects.items()
            }},
            "env_attr.json": {"env": {
                ATTRIBUTE_NAMES[name]: value for name, value in environment.items()
            }},
            "path_scope.json": {"include": [str(args.base_dir) + "/"], "exclude": []},
            "expected_access.json": {"assumption": "weekday, working hours, READ, ABAC scope",
                                     "decisions": decisions},
            "manifest.json": {
                "source_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
                "source_seed": data.get("generation_diagnostics", {}).get("seed"),
                "entries": len(rules), "duplicate_rules": duplicates,
                "subjects_in_source": len(data["S"]), "subjects_mapped": len(mapping),
                "objects": len(objects), "tee_percent": args.tee_percent,
                "protected_attributes": sorted(protected),
                "expected_allows": counts["ALLOW"], "expected_denies": counts["DENY"],
                "object_paths": paths,
            },
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, content in outputs.items():
            (args.output_dir / name).write_text(json.dumps(content, indent=2) + "\n")
        print(f"Generated {len(rules)} rules, {duplicates} duplicates, "
              f"{len(mapping)} mapped subject(s), {len(objects)} objects")
        print(f"Expected decisions for mapped subjects: {counts['ALLOW']} allow, "
              f"{counts['DENY']} deny")
        print(f"Files: {args.output_dir}")
    except (KeyError, ValueError, TypeError, OSError, json.JSONDecodeError) as error:
        parser.exit(1, f"Dataset rejected: {error}\n")


if __name__ == "__main__":
    main()
