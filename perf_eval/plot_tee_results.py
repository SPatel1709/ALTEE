#!/usr/bin/env python3
"""Plot the completed 39 repeated runs and one correctness check."""
import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--results', type=Path, default=Path('perf_eval/results_master'))
parser.add_argument('--output', type=Path, default=Path('perf_eval/report_figures'))
args = parser.parse_args()
pattern = re.compile(r'D(\d+)_T(\d+)(_OFF)?_run([123])')
metrics = ('mean_ns', 'p50_ns', 'p95_ns', 'p99_ns', 'ops_per_sec')
groups, provenance, checks = defaultdict(list), [], []
seen = set()

for path in sorted(args.results.glob('*.csv')):
    with path.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 1:
        raise ValueError(f'{path}: expected one summary row')
    row = rows[0]
    label = row['label']
    if label != path.stem or label in seen:
        raise ValueError(f'{path}: duplicate label or filename mismatch')
    seen.add(label)
    counts = tuple(int(row[k]) for k in ('samples', 'allows', 'denies'))
    for key in metrics:
        row[key] = float(row[key])
        if not math.isfinite(row[key]) or row[key] <= 0:
            raise ValueError(f'{path}: invalid {key}')
    if not row['p50_ns'] <= row['p95_ns'] <= row['p99_ns']:
        raise ValueError(f'{path}: invalid percentile order')
    match = pattern.fullmatch(label)
    if match and counts == (1000, 500, 500):
        n, share, off, run = match.groups()
        groups[int(n), int(share), bool(off)].append(row)
    elif label == 'D1000_T100_all' and counts == (200, 13, 187):
        checks.append(row)
    else:
        raise ValueError(f'{path}: unexpected label or decision counts')
    provenance.append(dict(
        file=path.name,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest()
    ))

expected = {
    (n, 25, off)
    for n in (10, 50, 100, 500, 1000)
    for off in (False, True)
}
expected |= {(1000, share, False) for share in (50, 75, 100)}

if set(groups) != expected or len(checks) != 1 or any(len(v) != 3 for v in groups.values()):
    raise ValueError('Expected 13 points, three runs each, and one full-object check')

summary = []
for (n, share, off), rows in sorted(groups.items()):
    item = dict(rules=n, tee_percent=share, mode='off' if off else 'on', runs=3)
    for metric in metrics:
        values = [r[metric] for r in rows]
        item[metric] = statistics.median(values)
        item[metric + '_min'] = min(values)
        item[metric + '_max'] = max(values)
    summary.append(item)

args.output.mkdir(parents=True, exist_ok=True)
with (args.output / 'summary.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
    writer.writeheader()
    writer.writerows(summary)

(args.output / 'provenance.json').write_text(json.dumps(dict(
    input_files=provenance,
    correctness_checks=checks,
    aggregation='Median of three run summaries; error bars show minimum to maximum.',
    percentile_note='Medians of run percentiles, not pooled request percentiles.'
), indent=2) + '\n')

plt.rcParams.update({
    'font.size': 10,
    'pdf.fonttype': 42,
    'axes.spines.top': False,
    'axes.spines.right': False
})

def series(ax, points, xkey, metric, scale, label):
    points = sorted(points, key=lambda p: p[xkey])
    y = [p[metric] / scale for p in points]
    errors = [
        [(p[metric] - p[metric + '_min']) / scale for p in points],
        [(p[metric + '_max'] - p[metric]) / scale for p in points]
    ]
    ax.errorbar(
        [p[xkey] for p in points], y, yerr=errors,
        marker='o', capsize=3, label=label
    )

def save(fig, ax, name):
    ax.grid(axis='y', alpha=0.2)
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    for extension in ('pdf', 'png'):
        fig.savefig(
            args.output / f'{name}.{extension}',
            dpi=220, bbox_inches='tight'
        )
    plt.close(fig)

for name, metric, scale, ylabel in (
    ('policy_throughput', 'ops_per_sec', 1000, 'Throughput (thousand reads/s)'),
    ('policy_p95', 'p95_ns', 1000, 'Median of run p95 latencies (microseconds)')
):
    fig, ax = plt.subplots(figsize=(6.4, 3.7))
    for mode in ('off', 'on'):
        points = [
            p for p in summary
            if p['tee_percent'] == 25 and p['mode'] == mode
        ]
        series(ax, points, 'rules', metric, scale, f'TEE {mode}')
    ax.set(
        xlabel='Number of policy rules (25% protected attributes)',
        ylabel=ylabel, xscale='log'
    )
    ax.set_xticks(
        [10, 50, 100, 500, 1000],
        labels=['10', '50', '100', '500', '1,000']
    )
    save(fig, ax, name)

share = sorted(
    [p for p in summary if p['rules'] == 1000 and p['mode'] == 'on'],
    key=lambda p: p['tee_percent']
)
baseline = next(
    p for p in summary
    if (p['rules'], p['tee_percent'], p['mode']) == (1000, 25, 'off')
)

fig, ax = plt.subplots(figsize=(6.4, 3.7))
series(ax, share, 'tee_percent', 'ops_per_sec', 1, 'TEE on; 1,000 rules')
ax.axhline(
    baseline['ops_per_sec'], linestyle='--',
    color='gray', label='TEE-off baseline'
)
ax.set(
    xlabel='Protected attributes per rule (%)',
    ylabel='Throughput (reads/s; log scale)', yscale='log'
)
ax.set_xticks([25, 50, 75, 100])
save(fig, ax, 'share_throughput')

fig, ax = plt.subplots(figsize=(6.4, 3.7))
for metric in ('p50_ns', 'p95_ns', 'p99_ns'):
    series(
        ax, share, 'tee_percent', metric, 1000,
        f'Median of run {metric[:3]}'
    )
ax.set(
    xlabel='Protected attributes per rule (%)',
    ylabel='Latency (microseconds; log scale)', yscale='log'
)
ax.set_xticks([25, 50, 75, 100])
save(fig, ax, 'share_latency')

def table(filename, header, rows):
    lines = [
        '\\begin{tabular}{' + 'r' * len(header) + '}',
        '\\toprule',
        ' & '.join(header) + r' \\',
        '\\midrule'
    ]
    lines += [' & '.join(row) + r' \\' for row in rows]
    lines += ['\\bottomrule', '\\end{tabular}']
    (args.output / filename).write_text('\n'.join(lines) + '\n')

policy_rows = []
for n in (10, 50, 100, 500, 1000):
    on = next(
        p for p in summary
        if (p['rules'], p['tee_percent'], p['mode']) == (n, 25, 'on')
    )
    off = next(
        p for p in summary
        if (p['rules'], p['tee_percent'], p['mode']) == (n, 25, 'off')
    )
    policy_rows.append([
        str(n),
        f"{off['ops_per_sec']:.1f}",
        f"{on['ops_per_sec']:.1f}",
        f"{on['p95_ns']/1000:.2f}",
        f"{off['ops_per_sec']/on['ops_per_sec']:.2f}"
    ])

table('policy_table.tex', [
    'Rules', 'Off (reads/s)', 'On (reads/s)',
    r'On p95 ($\mu$s)', 'Off/on throughput'
], policy_rows)

header = [
    'Protected', 'Reads/s', r'Mean ($\mu$s)',
    r'p50 ($\mu$s)', r'p95 ($\mu$s)', r'p99 ($\mu$s)'
]
table('share_table.tex', header, [
    [str(p['tee_percent']) + r'\%', f"{p['ops_per_sec']:.1f}"]
    + [f'{p[m]/1000:.2f}' for m in metrics[:4]]
    for p in share
])
table('all_metrics_table.tex', ['Rules/share/mode'] + header[1:], [
    [
        f"{p['rules']}/{p['tee_percent']}" + r'\%/' + p['mode'],
        f"{p['ops_per_sec']:.1f}"
    ] + [f'{p[m]/1000:.2f}' for m in metrics[:4]]
    for p in summary
])

print(
    'Validated 39 repeated runs and one correctness check. '
    f'Wrote four graphs and tables to {args.output}'
)
