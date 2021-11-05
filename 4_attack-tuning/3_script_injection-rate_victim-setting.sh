#!/usr/bin/env bash

# This script was part of our investigation to determine the highest rate
# of HS_DESC lookups achievable with our attack in the live Tor network.
# As parameters, it expects the client class ('slow', 'medium', 'fast')
# that defines the respective network conditions, the Tor Browser Bundle
# path, and the path to the list of guards to use in all iterations.
#
# Arguments:
#   1: client profile defining the network conditions for this machine
#   2: file system path to Tor Browser Bundle to use
#   3: list of Tor guards to traverse
#
# Usage:
#     ./3_script_injection-rate_victim-setting.sh CLIENT_PROFILE TBB_PATH GUARD_LIST_PATH


# Command-line arguments.
CLIENT_PROFILE=${1}
TBB_PATH=${2}
GUARD_LIST_PATH=${3}

# Fixed attack parameters.
ATTACK_DURATION=60
N_RUNS_FOR_EACH_SET=3

# Set default network parameters for the 'slow' client.
DOWN_MBIT=10
UP_MBIT=1
LATENCY_MEAN_MS=30
LATENCY_STDDEV_MS=10
PACKET_LOSS_PERC=0.5
PACKET_LOSS_CORR_PERC=25

# Adapt them according to the supplied client profile.
if [[ "${CLIENT_PROFILE}" == "medium" ]]
then
    DOWN_MBIT=50
    UP_MBIT=10
    LATENCY_MEAN_MS=20
    LATENCY_STDDEV_MS=5
    PACKET_LOSS_PERC=0.25
    PACKET_LOSS_CORR_PERC=25
elif [[ "${CLIENT_PROFILE}" == "fast" ]]
then
    DOWN_MBIT=150
    UP_MBIT=50
    LATENCY_MEAN_MS=10
    LATENCY_STDDEV_MS=1
    PACKET_LOSS_PERC=0
    PACKET_LOSS_CORR_PERC=0
fi


# Read in guard list.
GUARDS=$(cat "${GUARD_LIST_PATH}")


# Make sure the required kernel modules are present.
sudo modprobe ifb
sudo modprobe act_mirred

# Delete any leftover or general rules.
sudo tc qdisc del dev eth0 root
sudo tc qdisc del dev eth0 ingress
sudo tc qdisc del dev ifb0 root
sudo tc qdisc del dev ifb0 ingress


# Bring ingress-mirroring virtual network interface up.
sudo ifconfig ifb0 up

# Create ingress handle on eth0.
sudo tc qdisc add dev eth0 handle ffff: ingress

# Forward all ingress traffic on eth0 as egress traffic to ifb0.
# This is necessary, because tc only allows to shape outgoing traffic.
sudo tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0


# As the root discipline, specify latency and packet loss on the
# incoming channel according to the supplied client profile.
sudo tc qdisc add dev ifb0 root handle 1:0 netem \
    delay "${LATENCY_MEAN_MS}"ms "${LATENCY_STDDEV_MS}"ms distribution normal \
    loss "${PACKET_LOSS_PERC}"% "${PACKET_LOSS_CORR_PERC}"%

# Secondly, use the Hierarchical Token Bucket (htb) as the bandwidth
# shaping scheme for download traffic (i.e., on the ingress queue).
sudo tc qdisc add dev ifb0 parent 1:0 handle 2:0 htb default 1

# Set rate and ceiling for download speed for the default and only class.
sudo tc class add dev ifb0 parent 2:0 classid 2:1 htb rate "${DOWN_MBIT}"mbit ceil "${DOWN_MBIT}"mbit


# Repeat the same number of steps but with the upload instead of the
# download bandwidth for the outgoing interface (eth0).
sudo tc qdisc add dev eth0 root handle 1:0 netem \
    delay "${LATENCY_MEAN_MS}"ms "${LATENCY_STDDEV_MS}"ms distribution normal \
    loss "${PACKET_LOSS_PERC}"% "${PACKET_LOSS_CORR_PERC}"%
sudo tc qdisc add dev eth0 parent 1:0 handle 2:0 htb default 1
sudo tc class add dev eth0 parent 2:0 classid 2:1 htb rate "${UP_MBIT}"mbit ceil "${UP_MBIT}"mbit



for RATE_PER_SEC in 1 2 3 4 5 6
do
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
                    --tag MAX_HSDESC_RATE \
                    --tbb "${TBB_PATH}" \
                    --attack_duration ${ATTACK_DURATION} \
                    --onion_ver 2 \
                    --resource_type js \
                    --rate_per_sec ${RATE_PER_SEC} \
                    --guard_fp "${fingerprint}"\
                    --guard_or_ip "${OR_IP}"\
                    --guard_or_port "${OR_PORT}"\
                    --guard_dir_ip "${DIR_IP}"\
                    --guard_dir_port "${DIR_PORT}"

                # Truncate geckodriver log of Tor Browser.
                # Otherwise we run out of disk space very quickly.
                truncate -s 0 "${TBB_PATH}"/Browser/geckodriver.log
            fi
        done <<< "${GUARDS}"
    done
done


# Reset all network modifications.
sudo tc qdisc del dev eth0 root
sudo tc qdisc del dev eth0 ingress
sudo tc qdisc del dev ifb0 root
sudo tc qdisc del dev ifb0 ingress
