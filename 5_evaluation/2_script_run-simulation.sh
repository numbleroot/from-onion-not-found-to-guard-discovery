#!/usr/bin/env bash

# Run simulations in parallel with different adversarial parameters.
# The output must be redirected to a log file.
#
# Usage:
#     ./2_script_run-simulation.sh N_EXPERIMENTS_TO_REPLAY N_RUNS > results.log
#
# N_EXPERIMENTS_TO_REPLAY: We randomly sample this number of experiments from
# HS_DESC_MAX_RATE experiments with rate=3. If N_EXPERIMENTS_TO_REPLAY=-1, we
# take all experiments (still only using rate=3), without any sampling.
#
# We use the start and end times of HS_DESC lookups from the sampled experiments
# to replay lookups in each simulation.
#
# For each experiment, we run simulations for a total of N_RUNS times.
#
# Example: Run 50 simulations of all experiments:
#    ./2_script_run-simulation.sh -1 50 > sim_results_all_50.log
#
# Example: Run 10 simulations of 100 randomly sampled experiments:
#    ./2_script_run-simulation.sh 100 10 > sim_results_100_10.log
#
# Due to not using random seeds, each Python script (attack_simulation.py) will
# sample a different subset of experiments. This may introduce a bias between
# simulation runs with different adversarial parameters. We used -1 (i.e., no
# sampling) for the results in our paper to take advantage of all data we have,
# while avoiding potential bias due to sampling.

N_EXPERIMENTS_TO_REPLAY=$1
N_RUNS=$2

python3 attack_simulation.py 1 0.01 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 1 0.02 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 1 0.05 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 2 0.01 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 2 0.02 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 2 0.05 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 6 0.01 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 6 0.02 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &
python3 attack_simulation.py 6 0.05 ${N_EXPERIMENTS_TO_REPLAY} ${N_RUNS} &

wait
