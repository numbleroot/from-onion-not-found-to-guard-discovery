# Is the Attack Cell Pattern Deterministic?

This folder holds the Shadow experiments on a small hand-crafted network that extract the attack cell pattern of lookups for non-existing onion addresses ("404 Not Found" cell pattern). The goal is to extract the cell pattern used by the adversary and confirm that it is deterministic by extracting it the exact expected number of times across the set of configurations detailed below. We do this by having a configured number of `torhiddenclient`s request the descriptor for a non-existing v3 onion address (`wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad.onion`) or v2 onion address (`fhohevtqjym2vxry.onion`), respectively, via the relay sequence `guard` <=> `middle1` <=> `middle2` <=> `4uthority` (combined Authority and HSDir role) for a configured number of times. The network is set to `10ms` latency per edge, no packet loss, no jitter.

We include the result files from the Shadow experiments in their respective experiment folder. However, in case you want to reproduce the results detailed below, you can run the [provided script](./run_all_shadow_experiments.sh) that executes all Shadow experiments in an instance of the previously built Docker image:
```bash
# MIND: Below command will take some time!
user@host  $    ./run_all_shadow_experiments.sh
```
The script will store all produced cell counter logs in a folder called `cell_counters_reproduced` per each of the experiment folders. The analysis file obtained by running [`shadow_exps_find_adv_pattern.py`](../shadow_exps_find_adv_pattern.py) on the cell counter logs of relays `middle1` and `middle1` are placed into each experiment's newly created `cell_counters_reproduced_analyzed` folder. This way, you can compare the experiment results you obtained with the results we provide in the `cell_counters`/`cell_counters_analyzed` folders that come with this repository.


### v3, 1 client, 1 lookup attempt (shadow-plugin-tor_v3-addr_1-client_1-attempt)

As ground truth, we use the Tor and Tor Control Port logs produced during each Shadow experiment. We query them for the number of definitive lookup events that we subsequently match with the cell counter logs we produced and analyzed.

Ground truth for v3, 1 client, 1 lookup attempt:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_1-attempt
user@host  $    grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" . | wc -l
1
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
user@host  $    grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" | wc -l
1
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
```

Checking the analyzed cell counter logs (either the ones we provide in the respective `cell_counters_analyzed` folder or the ones you obtained yourself in the `cell_counters_reproduced_analyzed` folders) for the second-hop circuit position relay (`middle1`), we find that the expected one circuit with the second-hop "404 Not Found" cell pattern and the expected none with the third-hop cell pattern were identified by our script:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_1-attempt
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 1 adversarial second-hop circuits:
        0x55fd74886770/004_2583471346.003_0529976232

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

This is what the "404 Not Found" cell pattern for the second-hop circuit position looks like in the cell counter logs (including the eventual `DESTROY` cell we accept if present):
```bash
user@host  $    grep -rin "0x55fd74886770" cell_counters/middle1_cell_counters.log
... (another circuit uses this memory location before the one our script identified as the attack cell pattern) ...
10895:946685580.041000014 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='create2'
10897:946685580.041000014 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='created2'
10898:946685580.081000018 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10899:946685580.081000018 0x55fd74886770 ???_?????????? |-> relay_cmd='EXTEND2'
10900:946685580.081000018 0x55fd74886770 003_0529976232 DEST -1: circ_prps='Circuit at relay', cell_cmd='create2'
10901:946685580.102000020 0x55fd74886770 003_0529976232 DEST +1: circ_prps='Circuit at relay', cell_cmd='created2'
10902:946685580.102000020 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'
10903:946685580.142000024 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10904:946685580.142000024 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10905:946685580.142000024 0x55fd74886770 003_0529976232 DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10906:946685580.183000028 0x55fd74886770 003_0529976232 DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'
10907:946685580.183000028 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10908:946685580.183000028 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'
10909:946685580.223000032 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10910:946685580.223000032 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10911:946685580.223000032 0x55fd74886770 003_0529976232 DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10912:946685580.223000032 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10913:946685580.223000032 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10914:946685580.223000032 0x55fd74886770 003_0529976232 DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'
10915:946685580.263000036 0x55fd74886770 003_0529976232 DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'
10916:946685580.263000036 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10917:946685580.263000036 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'
10918:946685580.273000003 0x55fd74886770 003_0529976232 DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'
10919:946685580.273000003 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10920:946685580.273000003 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'
10921:946685580.273000003 0x55fd74886770 003_0529976232 DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'
10922:946685580.273000003 0x55fd74886770 ???_?????????? |-> Encrypted payload, passing on
10923:946685580.273000003 0x55fd74886770 004_2583471346 ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'
11581:946686207.020000003 0x55fd74886770 004_2583471346 ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='destroy'
```

For the third-hop circuit position relay (`middle2`), we find that the expected one circuit with the third-hop "404 Not Found" cell pattern and the expected none with the second-hop cell pattern were identified by our script:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_1-attempt
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 1 adversarial third-hop circuits:
        0x55fd747acc10/004_0529976232.002_1690933000
...
```


### v3, 1 client, 20 lookup attempts (shadow-plugin-tor_v3-addr_1-client_20-attempts)

Ground truth for v3, 1 client, 20 lookup attempts each:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_20-attempts
user@host  $    grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" . | wc -l
20
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
user@host  $    grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" | wc -l
20
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 20 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_20-attempts
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 20 adversarial second-hop circuits:
        0x55d4d4bcec70/004_2583471346.003_0529976232
        0x55d4d4ef6de0/004_3469708694.003_0956732936
        0x55d4d4ec6140/004_3896524000.003_1863081256
        0x55d4d4ec40f0/004_4007947666.003_0405822890
        0x55d4d52b2970/004_3657349656.003_1942452534
        0x55d4d4d83f40/004_4010272596.003_2132220788
        0x55d4d52b81d0/004_2932752132.003_0212642174
        0x55d4d48a3ad0/004_2768076096.003_0499773190
        0x55d4d5349a80/004_2295110452.003_2036421818
        0x55d4d53493b0/004_3106038684.003_1748206002
        0x55d4d4f47410/004_3224437170.003_2071724476
        0x55d4d4f45d80/004_2575873262.003_1469064792
        0x55d4d4f105c0/004_4098976942.003_1099271068
        0x55d4d5351b30/004_3329266082.003_0702755364
        0x55d4d534cf80/004_3296948600.003_0369102596
        0x55d4d53598a0/004_3620527634.003_1963298378
        0x55d4d535c1f0/004_2486867786.003_1530222014
        0x55d4d535c3c0/004_2199840166.003_0801579698
        0x55d4d5370720/004_2565454590.003_2047406764
        0x55d4d536f9a0/004_2469721076.003_0873427130

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 20 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_1-client_20-attempts
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 20 adversarial third-hop circuits:
        0x55d4d4d4ee00/004_0529976232.002_1690933000
        0x55d4d478e230/004_0956732936.002_1563187530
        0x55d4d32dbb40/004_1863081256.002_1365776914
        0x55d4d4960970/004_0405822890.002_1486960322
        0x55d4d52a8590/004_1942452534.002_1210517496
        0x55d4d4e5ee20/004_2132220788.002_1310952112
        0x55d4d48a07b0/004_0212642174.002_0790569358
        0x55d4d52b83a0/004_0499773190.002_2084412830
        0x55d4d4f16cd0/004_2036421818.002_1399294058
        0x55d4d4f162d0/004_1748206002.002_0977093108
        0x55d4d4f11760/004_2071724476.002_0816012030
        0x55d4d4f126f0/004_1469064792.002_0825874334
        0x55d4d4f438c0/004_1099271068.002_1622085834
        0x55d4d4f45640/004_0702755364.002_0040651616
        0x55d4d48a72d0/004_0369102596.002_1972996756
        0x55d4d53587d0/004_1963298378.002_1824302370
        0x55d4d535b910/004_1530222014.002_0268887802
        0x55d4d495c7b0/004_0801579698.002_2053949476
        0x55d4d535d880/004_2047406764.002_0528884792
        0x55d4d536ea60/004_0873427130.002_0069912126
...
```


### v3, 20 clients, 1 lookup attempt each (shadow-plugin-tor_v3-addr_20-clients_1-attempt)

Ground truth for v3, 20 clients, 1 lookup attempt each:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1-attempt
user@host  $    grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" . | wc -l
20
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
user@host  $    grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" | wc -l
20
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
1  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 20 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1-attempt
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 20 adversarial second-hop circuits:
        0x55cc1abb3b70/004_2387988028.003_0104529732
        0x55cc1abaf480/004_4239320508.003_2066481960
        0x55cc1abb3390/004_3963733892.003_0465647152
        0x55cc1abb3780/004_3989435674.003_0338458274
        0x55cc1abaf860/004_2599846474.003_0741892144
        0x55cc1abb3f30/004_2921626036.003_1606785062
        0x55cc1aae4240/004_2353318426.003_1784257534
        0x55cc1abb2760/004_4195357314.003_0572100852
        0x55cc1abb0800/004_4028190798.003_1868123772
        0x55cc1abca000/004_2830307316.003_0808437678
        0x55cc1abd2c10/004_3073564572.003_1532384502
        0x55cc1abd3070/004_3440266638.003_0326793792
        0x55cc1abd34d0/004_4121738530.003_0618769556
        0x55cc1abd3930/004_3595598342.003_1477801242
        0x55cc1abd3d90/004_2612271262.003_0399366510
        0x55cc1abda1b0/004_4109240362.003_0515639144
        0x55cc1abda3f0/004_2752727356.003_1180450718
        0x55cc1abda6b0/004_3297115472.003_0915751424
        0x55cc1abaecc0/004_3849538358.003_1295757596
        0x55cc1ab2e930/004_4128432990.003_0892258444

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 20 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1-attempt
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 20 adversarial third-hop circuits:
        0x55cc1142b8e0/004_2066481960.002_1344879106
        0x55cc1abd2080/004_0741892144.002_0776027582
        0x55cc1abcd600/004_0338458274.002_1902530224
        0x55cc1abd16f0/004_1606785062.002_0846460270
        0x55cc1abc7a80/004_0104529732.002_2025017790
        0x55cc1abdace0/004_1784257534.002_0123152636
        0x55cc1abc6240/004_0465647152.002_1606858984
        0x55cc1abe2410/004_0399366510.002_0795969006
        0x55cc1abbb590/004_0572100852.002_1056872310
        0x55cc1abdd590/004_1868123772.002_1193171220
        0x55cc1ab58620/004_1532384502.002_1143972670
        0x55cc1abea010/004_1180450718.002_0720574222
        0x55cc1abea320/004_0515639144.002_0888082986
        0x55cc19f6d2a0/004_0915751424.002_1957718498
        0x55cc11673e30/004_1477801242.002_0242449416
        0x55cc1abe6c00/004_0326793792.002_0188165776
        0x55cc1abe70e0/004_0618769556.002_1718572030
        0x55cc1abebe30/004_1295757596.002_2079733038
        0x55cc1abec3d0/004_0892258444.002_1439186920
        0x55cc1abec970/004_0808437678.002_2017325756
...
```


### v3, 20 clients, 100 lookup attempts each (shadow-plugin-tor_v3-addr_20-clients_100-attempts)

Ground truth for v3, 20 clients, 100 lookup attempts each:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_100-attempts
user@host  $    grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" . | wc -l
2000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
user@host  $    grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" | wc -l
2000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
100  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 2000 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_100-attempts
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 2000 adversarial second-hop circuits:
        0x562169307eb0/004_2615576186.003_1735644284
        0x5621696b89b0/004_2564543370.003_1578784736
        0x5621696ac010/004_3891043720.003_1240177678
        0x562171f8f7b0/004_4109693286.003_1881949936
...
        0x5621777832d0/004_3611762992.003_2105817946
        0x562172a3ae00/004_2312950798.003_1407156454
        0x56217745ece0/004_3469504026.003_2038955652
        0x56217246f800/004_2961952212.003_1935021486
        0x5621726da4d0/004_2782653932.003_1388322736

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 2000 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_100-attempts
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 2000 adversarial third-hop circuits:
        0x5621692d33c0/004_1520513950.002_0200407114
        0x5621692d5cb0/004_1578784736.002_2024726354
        0x5621692d4290/004_0740902666.002_1893395308
        0x5621692fa970/004_1912513556.002_1632860084
        0x562169300360/004_1562583758.002_0661355682
        0x56216950aa60/004_0188613976.002_1146968374
        0x56216950da30/004_2064622792.002_0295770644
        0x562169835d90/004_1993165428.002_1687243320
        0x5621697610d0/004_2066481960.002_1344879106
        0x56217208b320/004_0912847690.002_1983485534
...
```


### v3, 20 clients, 1000 lookup attempts each (shadow-plugin-tor_v3-addr_20-clients_1000-attempts)

Ground truth for v3, 20 clients, 1000 lookup attempts each:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1000-attempts
user@host  $    grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" . | wc -l
20000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_hsdesc_v3(): Received v3 hsdesc (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
user@host  $    grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" | wc -l
20000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED wye33xyqo22z5jkjace76cxsiygngnslq3jfcrjsj6plf4j2vthr2sad .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
1000  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 20000 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1000-attempts
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 20000 adversarial second-hop circuits:
        0x55d10c50d200/004_2615576186.003_1735644284
        0x55d10c9640c0/004_3934309600.003_1562583758
        0x55d10c4935b0/004_2619944018.003_0353161448
        0x55d10ca66670/004_2544400444.003_0100887086
        0x55d10ca6aaf0/004_4055401900.003_0185010758
...
        0x55d12c5b9460/004_2745169572.003_0169934850
        0x55d12a8efa40/004_2497678776.003_1563372758
        0x55d12f2a47d0/004_3354056048.003_1989202446
        0x55d12e9954a0/004_2229348602.003_1858616362
        0x55d12be5c6e0/004_3263963464.003_0900594666

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 20000 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v3-addr_20-clients_1000-attempts
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 20000 adversarial third-hop circuits:
        0x55d10c4bd270/004_1101487544.002_0231545342
        0x55d10c4c8c60/004_1520513950.002_0200407114
        0x55d10c4da9d0/004_0740902666.002_1893395308
        0x55d10c4edb80/004_2044800114.002_1859284778
        0x55d10c4f8990/004_0100887086.002_1414170360
        0x55d10c6df600/004_2064622792.002_0295770644
        0x55d10c67c430/004_0241748794.002_1702730774
        0x55d10c5a45c0/004_1052971628.002_1202377892
        0x55d10c7f58b0/004_1101881202.002_0043346690
        0x55d10c761e00/004_2066481960.002_1344879106
...
```


### v2, 1 client, 1 lookup attempt (shadow-plugin-tor_v2-addr_1-client_1-attempt)

Mind, while we focus on v3 onion services in our paper, we also use v2 onion services in some experiments, [which will be disabled as of October 15, 2021](https://blog.torproject.org/v2-deprecation-timeline).

Ground truth for v2, 1 client, 1 lookup attempt:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_1-client_1-attempt
user@host  $    grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" . | wc -l
2
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
2  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
user@host  $    grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" | wc -l
2
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
2  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient
```

As you can see, we observe an interesting difference to lookups for non-existing v3 onion addresses. Each tor client contacts the single HSDir twice per lookup attempt for the non-existing v2 onion address specified in the Shadow experiment files before noting that all potential HSDirs have been contacted for this address already (similar to v3 lookup attempts). Thus, we expect to see two lookup attempts in the logs for each lookup attempt specified in the Shadow experiment files.

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 2 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_1-client_1-attempt
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 2 adversarial second-hop circuits:
        0x558c96bdffe0/004_2583471346.003_0529976232
        0x558c953b0ce0/004_3469708694.003_0956732936

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 2 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_1-client_1-attempt
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 2 adversarial third-hop circuits:
        0x558c96aa8740/004_0529976232.002_1690933000
        0x558c96bd7b40/004_0956732936.002_1563187530
...
```


### v2, 20 clients, 10 lookup attempts (shadow-plugin-tor_v2-addr_20-clients_10-attempts)

Ground truth for v2, 20 clients, 10 lookup attempts each:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_10-attempts
user@host  $    grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" . | wc -l
400
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
user@host  $    grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" | wc -l
400
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
20  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
```

Interestingly, lookup attempts are spaced 30 seconds apart in our v2 onion address experiments:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_10-attempts
user@host  $    grep -rin "connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'" ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1/stdout-torhiddenclient1.tor.1000.log
466:Jan 01 00:13:00.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
673:Jan 01 00:13:30.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
811:Jan 01 00:14:00.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
954:Jan 01 00:14:30.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1094:Jan 01 00:15:00.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1208:Jan 01 00:15:30.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1301:Jan 01 00:16:00.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1421:Jan 01 00:16:30.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1566:Jan 01 00:17:00.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
1704:Jan 01 00:17:30.000 [info] connection_ap_handle_onion(): Got a hidden service request for ID 'fhohevtqjym2vxry'
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 400 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_10-attempts
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 400 adversarial second-hop circuits:
        0x56408780ec70/004_2981311978.003_1074898544
        0x56407f0f20a0/004_4015311084.003_1673508826
        0x5640879736c0/004_3525047978.003_0625379052
        0x56408751c620/004_2387988028.003_0104529732
        0x5640883c0ee0/004_4239320508.003_2066481960
...
        0x5640888b4570/004_2622040668.003_0976022604
        0x564087bc59e0/004_2666105604.003_1417782366
        0x564088954b10/004_3415915284.003_1648332088
        0x5640889695a0/004_2334863296.003_0178839490
        0x564087b11eb0/004_3941018966.003_1526379120

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 400 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_10-attempts
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 400 adversarial third-hop circuits:
        0x56407eb29090/004_0693334420.002_1023451538
        0x56407eb34a60/004_0441667586.002_0739360970
        0x56407eb3c900/004_1074898544.002_0757312414
        0x56407eb2dfc0/004_0861522564.002_0641030326
        0x56407eb53360/004_1822018698.002_2056744444
        0x56407f0f6f90/004_1633521374.002_1448499298
        0x56407ec0e7e0/004_2066481960.002_1344879106
        0x5640879a0fb0/004_2051476742.002_0563109566
        0x5640879f6ff0/004_0507820018.002_0714454500
        0x56407d3afd90/004_0024817390.002_0174158946
...
```


### v2, 20 clients, 100 lookup attempts (shadow-plugin-tor_v2-addr_20-clients_100-attempts)

Due the 30 seconds spacing between the lookup attempts for the non-existing v2 onion address in our experiments, 100 lookup attempts would not complete in the 47 minutes of the simulated 60 minutes of Tor operation (50 minutes are needed). Thus, for this final v2 experiment, we extend the simulation time from the previously used 60 minutes to 70 minutes.

Ground truth for v2, 20 clients, 100 lookup attempts each:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_100-attempts
user@host  $    grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" . | wc -l
4000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "handle_response_fetch_renddesc_v2(): Received rendezvous descriptor (body size 0, status 404 (\"Not found\"))" "${client}"/stdout-torhiddenclient*.tor.1000.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
user@host  $    grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" | wc -l
4000
user@host  $    for client in ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient*; do grep -rin "HS_DESC FAILED fhohevtqjym2vxry .* REASON=NOT_FOUND" "${client}"/stdout-torhiddenclient*.torctl.1001.log | wc -l | tr -d '\n'; printf "  ${client}\n"; done
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient1
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient10
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient11
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient12
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient13
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient14
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient15
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient16
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient17
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient18
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient19
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient2
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient20
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient3
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient4
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient5
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient6
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient7
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient8
200  ./resource/shadowtor-hsdesc-not-found/shadow.data/hosts/torhiddenclient9
```

Analyzed cell counter logs for the second-hop circuit position relay (`middle1`) identify the expected 4000 circuits with the second-hop cell pattern and the expected none with the third-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_100-attempts
user@host  $    cat cell_counters_analyzed/middle1   # or: cell_counters_reproduced_analyzed/middle1
...
[2ND_HOP_RESULT] 4000 adversarial second-hop circuits:
        0x55a8507da630/004_3484685168.003_0003987074
        0x55a850a68950/004_2832680892.003_0500580980
        0x55a850a68950/004_3493241856.003_1040100992
        0x55a850a700c0/004_3188713320.003_0833182588
        0x55a850a700c0/004_2210748406.003_2137554460
...
        0x55a85a57c830/004_2737268692.003_0253163984
        0x55a85ac6a4a0/004_2397841058.003_0744568518
        0x55a85a946ef0/004_3810173582.003_1478387132
        0x55a850c0b9f0/004_2458921954.003_1250195316
        0x55a85ab3c960/004_3995931580.003_2044066504

[3RD_HOP_RESULT] No adversarial third-hop circuits found.
...
```

Analyzed cell counter logs for the third-hop circuit position relay (`middle2`) identify the expected 4000 circuits with the third-hop cell pattern and the expected none with the second-hop cell pattern:
```bash
user@host  $    cd shadow-plugin-tor_v2-addr_20-clients_100-attempts
user@host  $    cat cell_counters_analyzed/middle2   # or: cell_counters_reproduced_analyzed/middle2
...
[2ND_HOP_RESULT] No adversarial second-hop circuits found.
[3RD_HOP_RESULT] 4000 adversarial third-hop circuits:
        0x55a8509e3410/004_2101439790.002_0574020090
        0x55a850a609a0/004_0693334420.002_1023451538
        0x55a850a609a0/004_1427793672.002_1848303922
        0x55a850a698a0/004_0441667586.002_0739360970
        0x55a850a749c0/004_1074898544.002_0757312414
        0x55a850a81c40/004_0861522564.002_0641030326
        0x55a850a8ac50/004_1822018698.002_2056744444
        0x55a850d9da00/004_1734601504.002_0708728552
        0x55a850cd5480/004_2133425806.002_1520291266
        0x55a850fe5360/004_2118597104.002_1687325074
...
```
