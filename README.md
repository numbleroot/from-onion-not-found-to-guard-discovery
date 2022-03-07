# From "Onion Not Found" to Guard Discovery (PETS'22)

This repository holds the code and data for our **[PETS'22](https://petsymposium.org/cfp22.php)** paper titled **['From "Onion Not Found" to Guard Discovery'](https://www.esat.kuleuven.be/cosic/publications/article-3392.pdf)**. Each subfolder contains instructions to reproduce results, figures, and tables per the respective section in the paper. Please see the `README.md` files in each subfolder for more information.

[Güneş Acar](https://github.com/gunesacar) contributed heavily to the creation of this artifact.

![Attack overview](https://user-images.githubusercontent.com/1864826/139098575-c23e1265-5885-4a68-aab8-41d89466ad51.png)


## Obtaining this Repository and Setting up the Environment

**Warning:** After taking below download steps, this repository is more than 16 GB in total size. There is also an [accompanying data set hosted at the OSF](https://osf.io/t9x4b/) that is about 64.5 GB.

```bash
user@host  $    git clone https://github.com/numbleroot/from-onion-not-found-to-guard-discovery.git
user@host  $    cd from-onion-not-found-to-guard-discovery
user@host  $    curl --location "https://files.de-1.osf.io/v1/resources/mbn95/providers/osfstorage/617bf5ad91ed6e00f3891f66?action=download&version=1&direct" --output 3_cell-pattern_large-files.tar
user@host  $    tar xvf 3_cell-pattern_large-files.tar
user@host  $    rm 3_cell-pattern_large-files.tar
```

The reproducibility steps described in this repository require superuser privileges (`root`) and a number of installed packages. Installation and setup of those will depend on your system. In case you are running a recent Ubuntu, we recommend to run the following steps so that the commands we list in the READMEs across this repository complete successfully:
1. Update your package list: `sudo apt update`
2. Install Python 3 (programming language): `sudo apt install python3`,
3. Install Pip (Python package manager): `sudo apt install python3-pip`,
4. Install Go (programming language): `sudo apt install golang`,
5. Install Docker (virtualization software to run containers): please follow the steps listed [on their documentation page](https://docs.docker.com/engine/install/ubuntu/),
6. Install Jupyter Lab and Python libraries numpy, pandas, seaborn, and matplotlib: `pip install jupyterlab numpy pandas seaborn matplotlib`,
7. Download Tor Browser from [their download page](https://www.torproject.org/download/) and extract it to a location dedicated for usage with this repository.

**Note:** Please mind that due to `/proc/cpuinfo` and `/proc/meminfo` not being available, the attack script [4_attack-tuning/launch_attack.py](./4_attack-tuning/launch_attack.py) will not work on MacOS (unless alternative ways to obtain the desired values are used in their places).


## Primary Data Sets

* OSF data repository holding 93 of the [./3_cell-pattern/uniqueness](./3_cell-pattern/uniqueness) cell counter logs (ca. 64.5 GB): [https://osf.io/t9x4b](https://osf.io/t9x4b/)
* Victim lookup crawl to determine the effect of injected subresource types: [./4_attack-tuning/1_data_resource-type](./4_attack-tuning/1_data_resource-type)
* Victim lookup crawl to determine the effect of injected onion service version: [./4_attack-tuning/2_data_onion-version_victim-setting](./4_attack-tuning/2_data_onion-version_victim-setting)
* Victim lookup crawl to determine the optimal injection rate: [./4_attack-tuning/3_data_injection-rate_victim-setting](./4_attack-tuning/3_data_injection-rate_victim-setting)
* Victim lookup crawl with disabled JavaScript: [./4_attack-tuning/4_data_scriptless-attack](./4_attack-tuning/4_data_scriptless-attack)
* HSDir response code count log: [./5_evaluation/1_data_noise-lookup-rate](./5_evaluation/1_data_noise-lookup-rate)


## Instructions for Reproduction

Browse the READMEs linked below for instructions for how to reproduce the results of each section:
* [3. "404 Not Found" Cell Pattern](./3_cell-pattern/README.md)
  * [Determinism](./3_cell-pattern/determinism/README.md)
  * [Uniqueness](./3_cell-pattern/uniqueness/README.md)
* [4. Maximizing the Victim Lookup Rate](./4_attack-tuning/README.md)
* [5. Attack Evaluation](./5_evaluation/README.md)
* [6. Countermeasures](./6_countermeasures/README.md)


## Reference

You can use the following BibTeX to cite our paper:
```
@article{OldenburgAcarDiaz_GuardDiscovery,
    title   = {{From "Onion Not Found" to Guard Discovery}},
    author  = {Lennart Oldenburg and Gunes Acar and Claudia Diaz},
    journal = {Proceedings on Privacy Enhancing Technologies},
    number  = {1},
    volume  = {2022},
    year    = {2022},
    doi     = {doi:10.2478/popets-2022-0026},
    url     = {https://doi.org/10.2478/popets-2022-0026},
    pages   = {522--543}
}
```
