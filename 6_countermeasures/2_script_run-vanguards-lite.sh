#!/usr/bin/env bash

# Run simulations for Vanguards-lite countermeasure in parallel with different
# adversarial parameters. The output must be redirected to a log file.
#
# Usage:
#    ./2_script_run-vanguards-lite.sh > results.log
#
# The order of arguments passed to attack_simulation.py:
#   1) N_ADV_HSDIRS: number of adversarial HSDirs per onion address
#   2) ADV_BW_SHARE: share of relay bandwidth operated by adversary
#   3) N_EXPERIMENTS: number of samples from experiments to replay ('-1' for all)
#   4) N_RUNS: number of times to run each simulation
#   5) N_INITIAL_TOKENS: number of initial tokens in bucket (set to '0' to disable)
#   6) TOKEN_REFILL_RATE: number of tokens added to bucket per second (set to '0' to disable)
#   7) VANGUARDSLITE_ENABLED: iff equal to '1', Vanguards-lite defense enabled
#
# We use the start and end times of HS_DESC lookups from the sampled experiments
# to replay lookups in each simulation.

N_RUNS=50

# h=1/6, Vanguards-lite enabled
python3 attack_simulation.py 1 0.05 -1 ${N_RUNS} 0 0 1 &

# h=1/3, Vanguards-lite enabled
python3 attack_simulation.py 2 0.05 -1 ${N_RUNS} 0 0 1 &

# h=1, Vanguards-lite enabled
python3 attack_simulation.py 6 0.05 -1 ${N_RUNS} 0 0 1 &

wait
