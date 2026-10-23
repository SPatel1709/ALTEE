MuSimA 10-entry smoke dataset, 25% protected attributes.
Mapping: S_2 -> Linux UID 1000; O_1..O_10 -> /home/secured/musima/O_*.txt.
EA_1_1 -> day=weekday; EA_2_1 -> time=working_hours.
This seed has 2 repeated permit rules: 10 entries, 8 distinct rules.
S_2/O_3 is allowed; S_2/O_5 and S_2/O_7 match explicit DENY rules
during the configured weekday 09:00-17:00 window.
These files are for review; use the TEE generation transaction to load them.
