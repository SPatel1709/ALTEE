# MuSimA benchmark series

Source: the uploaded 200-subject, 200-object, one-environment MuSimA output.
There are 819 permit and 205 deny entries. Deduplication leaves 806 permit
and 205 deny entries; this series uses 800 and 200 at its largest size.
Opposite-effect entries with the same attribute condition remain distinct.

The policy sizes are 10, 50, 100, 500, and 1,000 rules. Each contains 80%
permits and 20% denies, and each smaller policy's rules are a subset of the
next policy's rules. At 1,000 rules the protected attribute fractions are
25%, 50%, 75%, and 100%. All files map MuSimA subject S_83 to Linux UID 1000
and 200 objects to /home/secured/musima/O_*.txt.

Each dataset has its own expected_access.json for every object, a manifest,
and workload_fixed.txt. The fixed workload uses two allowed and two explicitly
denied objects, with the same decisions at all eight points. It is suited
to controlled policy-size and TEE-attribute-fraction comparisons. The full
expected_access.json includes default denies for correctness checks.

The environment condition is day=weekday and time=working_hours. The expected
outcomes require a workday/time configuration covering the benchmark run.
Write down the chosen /etc/abac/tee_env.conf values and restore the original
configuration after tests. Changing tee_env.conf requires `abac load --tee`.

The dataset files do not activate policies. Create the 200 target files and
install one dataset's five ABAC JSON configuration files into /etc/abac, then
use the synchronized `abac load --tee` command. Set the TEE mode on before
running the benchmark. Recheck generation, pending=0, and updating=0 after
every policy load. Do not load policies through the older perf_eval/benchmark.py.

When testing TEE off, load the same dataset with `abac load --no-tee` while
tee_mode is off. Merely changing tee_mode against a TEE-split kernel policy
does not make a valid non-TEE comparison.

The C reader measures end-to-end open/read/close latency, not isolated ECALL
time. Keep workload, iterations, warmup, machine, and environment configuration
the same for comparisons. See series.json for provenance and the fixed objects.
