#!/usr/bin/env bash

# Safety settings.
set -euo pipefail
shopt -s failglob


for exp in $( find ~+ -type d -name "shadow-*" ); do

    mkdir "${exp}"/cell_counters_reproduced

    sudo docker run --rm \
        -v "${exp}"/resource/shadowtor-hsdesc-not-found:/experiment \
        -v "${exp}"/cell_counters_reproduced:/home/shadow/cell_counters \
        ubuntu-shadow-tgen-tor-cellcounters:latest

    python3 ../shadow_exps_find_adv_pattern.py \
        --cell_cnt_log "${exp}"/cell_counters_reproduced/middle1_cell_counters.log \
        --out_dir "${exp}"/cell_counters_reproduced_analyzed

    python3 ../shadow_exps_find_adv_pattern.py \
        --cell_cnt_log "${exp}"/cell_counters_reproduced/middle2_cell_counters.log \
        --out_dir "${exp}"/cell_counters_reproduced_analyzed

done
