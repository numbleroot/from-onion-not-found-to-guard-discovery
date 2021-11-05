# Is the Attack Cell Pattern Unique?

For the task of determining whether our attack cell pattern is unique among a large number of Tor traffic patterns, we run another Shadow experiment. Instead of a hand-crafted network as for the [determinism experiments](../determinism/), we opt to use [TorNetTools](https://github.com/shadow/tornettools) (in version `v1.0.1`) which generates a representative Tor network of arbitrary scale from a historical Tor network state. We use Tor network data from May 2020 and obtain a 2%-scale Tor network by building and executing the accompanying [`Dockerfile.tornetgen`](../docker-builds/Dockerfile.tornetgen) like so:
```bash
user@host  $    mkdir tornettools_2020-05-data
user@host  $    sudo docker run --rm \
                    -v "$(pwd)"/tornettools_2020-05-data:/tor-network-generation \
                    ubuntu-tornetgen-tor:latest
```

We include the final generated 2%-scale network modified as mentioned in the paper (two `tgen` servers operating v3 onion services, two `tgen` servers operating v2 onion services, clients configured to contact the respective onion addresses as part of their target address set) in the assembled Shadow experiment configuration [`shadow-plugin-tor_2-perc-scale-tor`](./shadow-plugin-tor_2-perc-scale-tor/resource/shadowtor-2-perc-scale-tor/). Mind that the TorNetTools-generated network does not come with the mentioned modifications.

When running the 2%-Tor-scale Shadow experiment, we see clients creating a total of 1,866,782 circuits over the course of the simulated hour of operation. The experiment produces a total of 311 cell counter logs (174 clients + 133 relays + 4 onion services) with a total size of ca. 974 GB. Due to this amount and the size limitations of data sharing repositories, we can't share all logs. Instead, we provide a selection of 93 of the total 311 produced cell counter logs with a combined size of ca. 64.5 GB here:
* OSF data repository holding 93 of the uniqueness cell counter logs (ca. 64.5 GB): [https://osf.io/t9x4b](https://osf.io/t9x4b/)

In case you aim to run the same Shadow experiment, follow the steps below from the current folder. Mind that instructing Shadow via appropriate flags to run across multiple threads will speed up the simulation (which is what we did). Also note that the analysis script [`./shadow_exps_find_adv_pattern_workstation.sh`](./shadow_exps_find_adv_pattern_workstation.sh) assumes you have at least 16 CPU threads available. Steps:
```bash
user@host  $    cd uniqueness/shadow-plugin-tor_2-perc-scale-tor
user@host  $    mkdir cell_counters_reproduced
# MIND: Below command will take a long time (i.e., multiple days with parallelization)!
#       Please check if some Shadow flags may speed up this process depending on your hardware resources.
#       We ran this experiment across multiple threads. You may append a shadow command with more tuned
#       parameters to the end of below docker command to overwrite the default CMD.
user@host  $    sudo docker run --rm \
                    -v "$(pwd)"/resource/shadowtor-2-perc-scale-tor:/experiment \
                    -v "$(pwd)"/cell_counters_reproduced:/home/shadow/cell_counters \
                    ubuntu-shadow-tgen-tor-cellcounters:latest
user@host  $    ../shadow_exps_find_adv_pattern_workstation.sh ./cell_counters_reproduced
```
Similar to our determinism experiments, feel free to replace the paths `./cell_counters` and `./cell_counters_analyzed` below with the ones generated when running the commands above, `./cell_counters_reproduced` and `./cell_counters_reproduced_analyzed`, respectively.

When running the analysis script on the 311 cell counter logs, we see that all of them contain the respective expected lines stating that neither the second-hop nor third-hop attack cell pattern has been found in any of them:
```bash
user@host  $    cd shadow-plugin-tor_2-perc-scale-tor
user@host  $    ls ./cell_counters/ | wc -l
311      # This is our ground truth.
user@host  $    grep -rin "2ND_HOP_RESULT" ./cell_counters_analyzed/ | grep "No adversarial second-hop circuits found" | wc -l
311      # This is the number we expect for the second-hop pattern.
user@host  $    grep -rin "3RD_HOP_RESULT" ./cell_counters_analyzed/ | grep "No adversarial third-hop circuits found" | wc -l
311      # This is the number we expect for the third-hop pattern.
```

We provide the 311 output files of the analysis script in folder [cell_counters_analyzed_2-perc-scale-tor](./cell_counters_analyzed_2-perc-scale-tor). Rerunning the checks from above shows the expected result:
```bash
user@host  $    grep -rin "2ND_HOP_RESULT" ./cell_counters_analyzed_2-perc-scale-tor/ | grep "No adversarial second-hop circuits found" | wc -l
311      # This is the number we expect for the second-hop pattern.
user@host  $    grep -rin "3RD_HOP_RESULT" ./cell_counters_analyzed_2-perc-scale-tor/ | grep "No adversarial third-hop circuits found" | wc -l
311      # This is the number we expect for the third-hop pattern.
```

Please feel free to check the [log of the analysis script](./2021-04-26-11-49-00_shadow_exps_find_adv_pattern_workstation.log) showing that it went through all cell counter logs, as well as the provided selection of cell counter logs in the [OSF data repository](https://osf.io/t9x4b/).
