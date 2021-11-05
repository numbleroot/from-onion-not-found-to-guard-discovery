#!/usr/bin/env bash

# This script was part of our investigation to determine the highest rate
# of HS_DESC lookups achievable with our attack in the live Tor network.
# It runs the scriptless version of our attack to determine whether users
# with disabled JavaScript were vulnerable anyways.
#
# Arguments:
#   1: file system path to Tor Browser Bundle to use
#   2: list of Tor guards to traverse
#
# Usage:
#     ./4_script_scriptless-attack.sh TTB_PATH GUARD_LIST_PATH


TBB_PATH=${1}
GUARD_LIST_PATH=${2}

ATTACK_DURATION=60
N_RUNS_FOR_EACH_SET=3
ONION_VER=2

# Read in guard list.
GUARDS=$(cat "${GUARD_LIST_PATH}")


for _ in $(seq ${N_RUNS_FOR_EACH_SET})
do
    while IFS=, read -r _ fingerprint or_address_v4 dir_address _ _ _
    do
        if [[ "${fingerprint}" != "fingerprint" ]]
        then

            # Prepare OR address and port.
            IFS=':' read -r OR_IP OR_PORT <<< "${or_address_v4}"

            # Prepare directory address and port.
            if [[ "${dir_address}" != "none" ]]
            then
                IFS=':' read -r DIR_IP DIR_PORT <<< "${dir_address}"
            else
                DIR_IP="none"
                DIR_PORT="none"
            fi

            # Call the launch script with all appropriate parameters.
            python3 launch_attack.py \
                --log_level INFO \
                --tor_log_level info \
                --virtual_display \
                --tag MAX_HSDESC_RATE_NOJS \
                --tbb "${TBB_PATH}" \
                --attack_duration ${ATTACK_DURATION} \
                --resource_type js \
                --guard_fp "${fingerprint}"\
                --guard_or_ip "${OR_IP}"\
                --guard_or_port "${OR_PORT}"\
                --guard_dir_ip "${DIR_IP}"\
                --guard_dir_port "${DIR_PORT}"\
                --no_js\
                --adv_page adv_website_nojs_combined.html
        fi
    done <<< "${GUARDS}"
done
