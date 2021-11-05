# Countermeasures to our Guard Discovery Attack

In order to evaluate how well the three countermeasures we discuss in our paper work towards limiting the impact of our guard discovery attack on Tor users, we integrate their behavior in the same simulation script used to determine attack success: [`attack_simulation.py`](./attack_simulation.py). The countermeasures discussed in our paper are already present in the attack simulation script used in [`../5_evaluation`](../5_evaluation), but we reproduce the script and its two dependency files [`2020-09-22-18-36-48_relays.csv`](./2020-09-22-18-36-48_relays.csv) and [`hsdesc_lookup_details.json`](./hsdesc_lookup_details.json) here for completeness. The countermeasures can be evaluated by calling the attack simulation script with the proper set of parameters. Please use below linked Bash scripts in case you want to run your own countermeasures simulations.

We provide the simulation data and the Jupyter Notebooks we used to obtain countermeasure figures 6, 7, and 8 in the paper. You may rerun the Jupyter Notebooks on the provided data to check that our paper figures match the ones you obtain. Start Jupyter Lab by running:
```bash
user@host  $    jupyter lab
```
Visit the mentioned `localhost` webpage in your browser. In the presented interface, you may rerun the Jupyter Notebooks linked below.


### Token Bucket

* Data folder holding the simulation results when a token bucket is used: [`1_data_token-bucket`](./1_data_token-bucket)
* Jupyter Notebook analyzing the simulation results: [`1_analysis_token-bucket.ipynb`](./1_analysis_token-bucket.ipynb)
* Script calling `attack_simulation.py` with appropriate parameters for token bucket countermeasure: [`1_script_run-token-bucket.sh`](./1_script_run-token-bucket.sh)


### Vanguards-lite

* Data folder holding the simulation results when Vanguards-lite is used: [`2_data_vanguards-lite`](./2_data_vanguards-lite)
* Jupyter Notebook analyzing the simulation results: [`2_analysis_vanguards-lite.ipynb`](./2_analysis_vanguards-lite.ipynb)
* Script calling `attack_simulation.py` with appropriate parameters for Vanguards-lite countermeasure: [`2_script_run-vanguards-lite.sh`](./2_script_run-vanguards-lite.sh)


### Vanguards-lite with Token Bucket

* Data folder holding the simulation results when Vanguards-lite combined with a token bucket is used: [`3_data_vanguards-lite-with-token-bucket`](./3_data_vanguards-lite-with-token-bucket)
* Jupyter Notebook analyzing the simulation results: [`3_analysis_vanguards-lite-with-token-bucket.ipynb`](./3_analysis_vanguards-lite-with-token-bucket.ipynb)
* Script calling `attack_simulation.py` with appropriate parameters for combination countermeasure of Vanguards-lite and a token bucket: [`3_script_run-vanguards-lite-and-token-bucket.sh`](./3_script_run-vanguards-lite-and-token-bucket.sh)
