# Attack Evaluation

We provide the code and data that can be used to rerun the experiments and regenerate the figures and tables for section 5.1 "Estimating Tor's Noise Lookup Rate", section 5.3 "Attack Success", and section 5.4 "Time to Generate Attack Keys". Please see below linked Bash script ([`2_script_run-simulation.sh`](./2_script_run-simulation.sh)) for instructions on how to run the supplied source code.

You may rerun the Jupyter Notebooks on the provided data to check that our paper figures match the ones you obtain. Start Jupyter Lab by running:
```bash
user@host  $    jupyter lab
```
Visit the mentioned `localhost` webpage in your browser. In the presented interface, you may rerun the Jupyter Notebooks linked below.


### Tor's Noise Lookup Rate

* Data folder holding the HSDir response code count results: [`1_data_noise-lookup-rate`](./1_data_noise-lookup-rate)
* Jupyter Notebook analyzing the HSDir response code count results: [`1_analysis_noise-lookup-rate.ipynb`](./1_analysis_noise-lookup-rate.ipynb)


### Attack Success

* List of lookup timestamps from Tor crawls with injection rate 3: [`hsdesc_lookup_details.json`](./hsdesc_lookup_details.json)
* Jupyter Notebook creating `hsdesc_lookup_details.json` from experiment result files: [`2_analysis_hsdesc-lookup-details.ipynb`](./2_analysis_hsdesc-lookup-details.ipynb) ( [`../4_attack-tuning/process_events_log.py`](../4_attack-tuning/process_events_log.py) needs to run on them prior to this Notebook)
* Relay list used by attack success simulation script: [`2020-09-22-18-36-48_relays.csv`](./2020-09-22-18-36-48_relays.csv)
* Python script for attack success simulation: [`attack_simulation.py`](./attack_simulation.py)
* Script calling `attack_simulation.py` with appropriate parameters: [`2_script_run-simulation.sh`](./2_script_run-simulation.sh)
* Data folder holding the simulation results: [`2_data_attack-time`](./2_data_attack-time)
* Jupyter Notebook to analyze the simulation results: [`2_analysis_attack-time.ipynb`](./2_analysis_attack-time.ipynb)


### Attack Public Key Generation Time

* Python script to download Tor network state needed for subsequent HSDir construction: [`load_hsdirs.py`](./load_hsdirs.py)
* Data folder holding the Tor network state used for time measurement of key generation: [`3_data_consensus-descriptors`](./3_data_consensus-descriptors)
* Python script measuring time it takes to generate a set of v3 attack public keys: [`gen_atk_pubkeys.py`](./gen_atk_pubkeys.py). This can be run via:
```bash
user@host  $    mkdir output_gen-atk-pubkeys
# MIND: Make sure to configure NUM_WORKER_PROCS, NUM_ADV_HSDIRS, and NUM_REPETITIONS
#       at the top of the script in order to fit your hardware and desired experiment
#       setting. Mind that depending on these parameters, the script may run for many
#       hours. The data provided here was obtained over ca. 16 hours (default parameters).
#       Adjust the following parameters:
#       1) Set NUM_WORKER_PROCS to the number of threads you want to utilize,
#       2) Specify the adversarial HSDirs in your setting in NUM_ADV_HSDIRS,
#       3) Set NUM_REPETITIONS to the number of times each NUM_ADV_HSDIRS is sampled.
user@host  $    python3 gen_atk_pubkeys.py --state_dir ./3_data_consensus-descriptors --out_dir ./output_gen-atk-pubkeys
```
* Data folder holding the 10 repeated runs of the time measurement script: [`3_data_generate-attack-public-keys`](./3_data_generate-attack-public-keys)
* Jupyter Notebook analyzing the time measurement results: [`3_analysis_generate-attack-public-keys.ipynb`](./3_analysis_generate-attack-public-keys.ipynb)
