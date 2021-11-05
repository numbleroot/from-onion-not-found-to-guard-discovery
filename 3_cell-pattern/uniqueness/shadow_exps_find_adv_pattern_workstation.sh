#!/usr/bin/env bash

# Usage:
#   ./shadow_exps_find_adv_pattern_workstation.sh PATH_TO_CELL_COUNTER_LOGS_DIR

CELL_CNT_DIR=$(readlink -f "${1}")

# Create log file.
analysis_start=$(date +%Y-%m-%d-%H-%M-%S)
touch "${analysis_start}"_shadow_exps_find_adv_pattern_workstation.log

# Iterate over Shadow experiment files in descending file size order.
for log_file in $(ls --sort=size "${CELL_CNT_DIR}"/*); do

    can_be_placed="false"

    while [ "${can_be_placed}" = "false" ]; do

        # Check how many analysis processes are already running.
        running_procs=$(ps aux | grep -i "python3 shadow_exps_find_adv_pattern" | wc -l)

        # If <= 15 analysis processes are ongoing, start another one.
        # The value in running_procs includes the grep output, thus one higher.
        if [ "${running_procs}" -le 16 ]
        then
            can_be_placed="true"
        fi

        # Make sure we don't overheat trying to place when
        # we are at capacity of ongoing processes.
        if [ "${can_be_placed}" = "false" ]
        then
            sleep 2
        fi

    done

    cur_time=$(date +%Y/%m/%d_%H:%M:%S)

    # Log progress to STDOUT and log file.
    printf "[${cur_time}] Processing '${log_file}'...\n"
    printf "[${cur_time}] Processing '${log_file}'...\n" >> "${analysis_start}"_shadow_exps_find_adv_pattern_workstation.log

    # Run one more analysis process.
    python3 ../../shadow_exps_find_adv_pattern.py --cell_cnt_log "${log_file}" --out_dir "${CELL_CNT_DIR}_analyzed" &

    # Make sure to wait one second before continuing.
    sleep 1

done

wait

# Final end log line.
cur_time=$(date +%Y/%m/%d_%H:%M:%S)
printf "[${cur_time}] All done!\n"
printf "[${cur_time}] All done!\n" >> "${analysis_start}"_shadow_exps_find_adv_pattern_workstation.log
