# Maximizing the Victim Lookup Rate

The four Jupyter Notebooks follow the experiments described in section 4 of our paper. Associated with each Jupyter Notebook is a folder that contains the essential parts of our crawls on the live Tor network and for the latter three experiments a script each that outlines how we accessed the attack webpage. The two guard lists (`.csv` files) are used in various of the detailed experiments.

You may rerun the Jupyter Notebooks on the provided data to check that our paper figures match the ones you obtain. Start Jupyter Lab by running:
```bash
user@host  $    jupyter lab
```
Visit the mentioned `localhost` webpage in your browser. In the presented interface, you may rerun this folder's Jupyter Notebooks.

This folder contains the following source code files:
* [`launch_attack.py`](./launch_attack.py): Python script that launches one attack experiment and measures the metrics we are interested in.
* [`adv_website.html`](./adv_website.html): The attack webpage as viewed by a victim in our experiments. The attack parameters (onion service version, resource type, injection rate) can be adjusted via GET parameters.
* [`adv_website_nojs_combined.html`](./adv_website_nojs_combined.html): The scriptless attack webpage that embeds [`single_attack_frame_0.html`](./single_attack_frame_0.html) to determine whether our attack works when JavaScript is disabled.
* [`select_guards.py`](./select_guards.py): Python script that samples guards from the current consensus based on different criteria.
* [`process_events_log.py`](./process_events_log.py): Python script that extracts the information into `events_hs_desc.csv` files by parsing an experiment's `victim_client_events.log` files. Due to space limitations we only include the `events_hs_desc.csv` files for the larger-scale experiments here.
* [`process_tor_log.py`](./process_tor_log.py): Python script that parses an experiment's tor log file (`tor_*.log`) and amends the experiment's `results.json` file with counters of the identified events. Due to space limitations we do not provide the experiments' tor logs here.
* [`genonion.go`](./genonion.go): Go script that is used to generate attack onion addresses.
* [`requirements.txt`](./requirements.txt): Contains the Python packages needed to running the experiments.

To obtain the datasets mentioned in this README, start by installing the required Python packages:
```bash
user@host  $    pip install -r requirements.txt
```

Next, sample a list of guards to use for a crawl (written into folder `./experiments_relay-lists`):
```bash
user@host  $    mkdir experiments_relay-lists
user@host  $    python3 select_guards.py --num_sampled_from_guard_prob 100
```

Generate non-existing onion addresses:
```bash
user@host  $    mkdir pregen_addr
user@host  $    go mod init genonion && go mod tidy
user@host  $    go run genonion.go -v3 -numAddr 100000 -outputDir ./pregen_addr
user@host  $    ls ./pregen_addr
v3_0000.addr
v3_0001.addr
v3_0002.addr
v3_0003.addr
v3_0004.addr
v3_0005.addr
v3_0006.addr
v3_0007.addr
v3_0008.addr
v3_0009.addr
v3_0010.addr
v3_0011.addr
v3_0012.addr
v3_0013.addr
v3_0014.addr
v3_0015.addr
v3_0016.addr
v3_0017.addr
v3_0018.addr
v3_0019.addr
```

Now you can run the attack script itself. **Mind:** We require connection details of a Tor guard when calling below script. We will fix to this guard for the duration of the attack run. Please be mindful when selecting this guard, as all circuits created during this attack run will go through this relay. For example, use a Tor guard under your control. Run the attack script as follows:
```bash
# Arguments:
#   TTB_PATH:  file system path to Tor Browser Bundle to use
#   GUARD_FP:  fingerprint of a Tor guard to use (e.g., a guard under your control)
#      OR_IP:  OR IP address of selected Tor guard
#    OR_PORT:  OR port of selected Tor guard
#     DIR_IP:  directory IP address of selected Tor guard
#   DIR_PORT:  directory port of selected Tor guard
user@host  $    python3 launch_attack.py \
                    --log_level INFO \
                    --tor_log_level info \
                    --experiments_dir ./experiments \
                    --virtual_display \
                    --tag ONION_NOT_FOUND_GUARD_DISCOVERY \
                    --tbb "${TBB_PATH}" \
                    --attack_duration 60 \
                    --onion_ver 3 \
                    --resource_type js \
                    --rate_per_sec 3 \
                    --guard_fp "${GUARD_FP}"\
                    --guard_or_ip "${OR_IP}"\
                    --guard_or_port "${OR_PORT}"\
                    --guard_dir_ip "${DIR_IP}"\
                    --guard_dir_port "${DIR_PORT}"
```

Afterwards, you can run the processing scripts on the output folder:
```bash
# Arguments:
#   EXP_RES_DIR:  file system path to just-created experiment result folder
user@host  $    python3 process_events_log.py --exp_dir "${EXP_RES_DIR}"
#                   |-> This will likely print a lot of discovered log lines.
user@host  $    python3 process_tor_log.py --exp_dir "${EXP_RES_DIR}"
#                   |-> This will likely not print anything.
```

The scripts below show the range of parameters we used in each experiment:
* [`2_script_onion-version_victim-setting.sh`](./2_script_onion-version_victim-setting.sh)
* [`3_script_injection-rate_victim-setting.sh`](./3_script_injection-rate_victim-setting.sh)
* [`4_script_scriptless-attack.sh`](./4_script_scriptless-attack.sh)
