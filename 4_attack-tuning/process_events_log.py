#!/usr/bin/env python3

"""
Extract info of events from an experiment's events log.
"""

import os
import sys
import csv
import json
import argparse
import datetime
import collections


ONE_MICRO_S = datetime.timedelta(microseconds=1)


def print_warn_tor_log_lines(exp_dir):
    """Traverses experiment directory and outputs any " [warn] "-prefixed
    lines found in each of the experiment's Tor logs."""

    for _, _, filenames in os.walk(exp_dir):

        for file in filenames:

            if file.startswith("tor_") and file.endswith(".log"):

                filepath = os.path.join(exp_dir, file)

                # Stash all lines of any "tor_*.log" file.
                tor_log_lines = open(filepath).readlines()

                for line in tor_log_lines:

                    # Output any line that contains " [warn] ".
                    if " [warn] " in line:
                        print("TOR LOG '{}' CONTAINS:\t{}".format(
                            filepath, line), end="")

                print()


def parse_circ_event(event, circ_events, lowest_time, time):
    """Takes in all parameters to parse a CIRC event log line."""

    circ_id = int(event[3])

    if event[4] == "LAUNCHED":

        # Turns 'PURPOSE=HS_CLIENT_HSDIR' into 'hs_client_hsdir'.
        purpose = event[6].split("=")[1].lower()

        # Field 'rebuilt' represents the BUILT event of a circuit
        # that existed before, was chosen to be cannibalized for
        # a new purpose, and then completed.
        circ_events[circ_id] = {
            "final_purpose": purpose,
            "final_status": None,
            "reason": None,
            "guard_fp": None,
            "middle_fp": None,
            "exit_fp": None,
            "hsdir_fp": None,
            "start": time,
            "extended_1": None,
            "extended_2": None,
            "extended_3": None,
            "extended_4": None,
            "end": None,
            "rebuilt": None,
        }

        if time < lowest_time:
            lowest_time = time

    elif (event[4] == "EXTENDED") and (circ_id in circ_events):

        # Turns 'PURPOSE=HS_CLIENT_HSDIR' into 'hs_client_hsdir'.
        purpose = event[7].split("=")[1].lower()

        for ext_level in ["extended_1", "extended_2",
                          "extended_3", "extended_4"]:

            if circ_events[circ_id][ext_level] is not None:
                continue

            circ_events[circ_id]["final_purpose"] = purpose
            circ_events[circ_id][ext_level] = time
            break

    elif (event[4] == "BUILT") and (circ_id in circ_events):

        # Turns 'BUILT' into 'built'.
        status = event[4].lower()

        # Turns 'PURPOSE=HS_CLIENT_HSDIR' into 'hs_client_hsdir'.
        purpose = event[7].split("=")[1].lower()

        circ_events[circ_id]["final_purpose"] = purpose
        circ_events[circ_id]["final_status"] = status

        if circ_events[circ_id]["end"] is None:
            circ_events[circ_id]["end"] = time
        else:
            circ_events[circ_id]["rebuilt"] = time

        if "PURPOSE=HS_CLIENT_HSDIR" in event:

            # Remove leading dollar sign and nickname of
            # relay separated from fingerprint by a tilde.
            def extract_only_fp(relay):
                return relay.lstrip("$").split("~", 1)[0]

            # Split sequence of relay names at commas.
            relay_fps = event[5].split(",")

            # Extract only the fingerprint from each relay name.
            relay_fps = list(map(extract_only_fp, relay_fps))

            # Assign the fingerprints to the appropriate position.
            circ_events[circ_id]["guard_fp"] = relay_fps[0]
            circ_events[circ_id]["middle_fp"] = relay_fps[1]
            circ_events[circ_id]["exit_fp"] = relay_fps[2]
            circ_events[circ_id]["hsdir_fp"] = relay_fps[3]

    elif (event[4] == "FAILED") and (circ_id in circ_events):

        # Turns 'FAILED' into 'failed'.
        status = event[4].lower()

        # Turns 'PURPOSE=HS_CLIENT_HSDIR' into 'hs_client_hsdir'.
        purpose = event[7].split("=")[1].lower()

        circ_events[circ_id]["final_purpose"] = purpose
        circ_events[circ_id]["final_status"] = status

        if circ_events[circ_id]["end"] is None:
            circ_events[circ_id]["end"] = time
        else:
            circ_events[circ_id]["rebuilt"] = time

        if ("PURPOSE=GENERAL" in event) and (len(event) >= 10):

            # Turns 'REASON=DESTROYED' into 'destroyed' (or others).
            reason = event[9].split("=")[1].lower()
            circ_events[circ_id]["reason"] = reason

        elif ("PURPOSE=HS_CLIENT_HSDIR" in event) and (len(event) >= 11):

            # Turns 'REASON=DESTROYED' into 'destroyed' (or others).
            reason = event[10].split("=")[1].lower()
            circ_events[circ_id]["reason"] = reason

    return circ_events, lowest_time


def parse_hs_desc_event(event, hs_desc_events, lowest_time, time):
    """Takes in all parameters to parse an HS_DESC event log line."""

    # Turns 'REQUESTED' into 'requested'.
    status = event[3].lower()

    # Extracts the onion address in question from the log.
    addr = event[4]

    # Extracts the HSDir's fingerprint only from the log.
    hsdir_fp = event[6].lstrip("$").split("~", 1)[0]

    if status == "requested":

        if (addr, hsdir_fp) not in hs_desc_events:

            hs_desc_events[(addr, hsdir_fp)] = {
                "status": None,
                "reason": None,
                "circ": None,
                "guard_fp": None,
                "middle_fp": None,
                "exit_fp": None,
                "start": time,
                "end": None,
                "lookup_timestamps": None,
            }

        if time < lowest_time:
            lowest_time = time

    elif status == "received":

        if (addr, hsdir_fp) not in hs_desc_events:
            return hs_desc_events, lowest_time

        hs_desc_events[(addr, hsdir_fp)]["end"] = time
        hs_desc_events[(addr, hsdir_fp)]["status"] = status

    elif (status == "failed") and ("REASON=NOT_FOUND" in event):

        if (addr, hsdir_fp) not in hs_desc_events:
            return hs_desc_events, lowest_time

        # Turns 'REASON=NOT_FOUND' into 'not_found'.
        reason = event[8].split("=")[1].lower()

        hs_desc_events[(addr, hsdir_fp)]["end"] = time
        hs_desc_events[(addr, hsdir_fp)]["status"] = status
        hs_desc_events[(addr, hsdir_fp)]["reason"] = reason

    return hs_desc_events, lowest_time


def parse_events(ev_fp, w_id):
    """Take in an experiment's events log and parse it line-by-line."""

    circ_events = collections.OrderedDict()
    hs_desc_events = collections.OrderedDict()

    lowest_time = datetime.datetime.now() + datetime.timedelta(days=365250)
    highest_time = datetime.datetime.now() - datetime.timedelta(days=365250)

    for _, line in enumerate(ev_fp):

        # Split log line at separator distinguishing
        # the time part from the message.
        if " | " not in line:
            print("Unexpected log format (could be an error): %s" % line)
            continue
        fields = line.strip().split(" | ")
        time = datetime.datetime.strptime(fields[0], "%Y-%m-%d %H:%M:%S:%f")

        # We only consider messages that actually
        # are event logs emitted by stem.
        if fields[1].startswith("[tor_browser_worker{}] [EVENT]".format(w_id)):

            event = fields[1].split()

            # Update highest time in case this log
            # line has a higher one than any before.
            if time > highest_time:
                highest_time = time

            if event[2] == "CIRC":
                circ_events, lowest_time = \
                    parse_circ_event(event, circ_events, lowest_time, time)

            elif event[2] == "HS_DESC":
                hs_desc_events, lowest_time = parse_hs_desc_event(
                    event, hs_desc_events, lowest_time, time)

    # Below, fill hsdir_matches with each
    # (circ, addr, diff) tuple that matches
    # to the current HSDir fingerprint.
    hsdir_matches = collections.OrderedDict()

    for circ_id in circ_events:
        circ = circ_events[circ_id]

        for (addr, hsdir_fp) in hs_desc_events:
            req = hs_desc_events[(addr, hsdir_fp)]

            if (circ["hsdir_fp"] == hsdir_fp) and (req["end"] is not None):

                # Calculate the absolute timedelta in microseconds (for
                # better resolution) between the CIRCUIT start and HS_DESC
                # start times.
                t_diff = abs((circ["start"] - req["start"])) / ONE_MICRO_S

                if hsdir_fp not in hsdir_matches:
                    hsdir_matches[hsdir_fp] = []

                # Append information about this HSDir
                # fingerprint match the potentially
                # already existing list.
                hsdir_matches[hsdir_fp].append({
                    "circ_id": circ_id,
                    "addr": addr,
                    "t_diff": t_diff,
                })

    # The idea to find the correct circuit an HS_DESC
    # request used is the following:
    # For each HSDir fingerprint that was contacted
    # multiple times throughout the experiment, figure
    # out the HS_DESC that has the closest time distance
    # to the CIRC event (i.e., local t_diff minimum).
    # Match this HS_DESC<->CIRC pair, remove it from
    # hsdir_matches, and continue going, until the whole
    # list is empty.
    while len(hsdir_matches) > 0:

        # We need this iteration technique, because we
        # will modify the underlying list in the loop.
        for hsdir_fp in list(hsdir_matches.keys()):

            # Stash this HSDir fingerprint match list.
            hsdir = hsdir_matches[hsdir_fp]

            # Ultimately, these descriptors will point to
            # the HS_DESC request for the circuit. Initially,
            # we set them to the first element in the list.
            circ_id = hsdir[0]["circ_id"]
            addr = hsdir[0]["addr"]
            min_t_diff = hsdir[0]["t_diff"]

            for mat in hsdir:

                # In case the next element in the list is the
                # new local minimum, update the descriptor variables.
                if mat["t_diff"] < min_t_diff:
                    circ_id = mat["circ_id"]
                    addr = mat["addr"]
                    min_t_diff = mat["t_diff"]

            # Once we found the local minimum, update the
            # corresponding HS_DESC to have used this CIRC.
            hs_desc_events[(addr, hsdir_fp)]["circ"] = circ_id
            hs_desc_events[(addr, hsdir_fp)]["guard_fp"] = \
                circ_events[circ_id]["guard_fp"]
            hs_desc_events[(addr, hsdir_fp)]["middle_fp"] = \
                circ_events[circ_id]["middle_fp"]
            hs_desc_events[(addr, hsdir_fp)]["exit_fp"] = \
                circ_events[circ_id]["exit_fp"]

            # Calculate the number of microseconds it took between
            # having established the final hop of this HS_DESC circuit
            # and having received a response to the lookup. This depends
            # on knowing the circuit over which the lookup took place,
            # excluding all lookups that somehow completed but could not
            # be matched to a circuit from the statistics of this value.
            lookup_end = hs_desc_events[(addr, hsdir_fp)]["end"]
            lookup_start = circ_events[circ_id]["extended_4"]

            dur = (lookup_end - lookup_start) / ONE_MICRO_S
            # (hs_desc_events[(addr, hsdir_fp)]["end"] - circ_events[circ_id]["extended_4"]) / ONE_MICRO_S

            if dur > 0.0:
                hs_desc_events[(addr, hsdir_fp)]["lookup_timestamps"] = (
                    lookup_start.timestamp(), lookup_end.timestamp())

            for i, mat in reversed(list(enumerate(hsdir))):

                # Remove any element from this HSDir fingerprint match
                # list that either has the same CIRC ID or onion address.
                if (mat["circ_id"] == circ_id) or (mat["addr"] == addr):
                    del hsdir[i]

            # If all elements of this HSDir fingerprint match list
            # have been successfully matched to the corresponding
            # HS_DESC request, remove the whole HSDir fingerprint.
            # This will shrink the list we are looping over until
            # its size reaches zero and we terminate.
            if len(hsdir) == 0:
                del hsdir_matches[hsdir_fp]

    return circ_events, hs_desc_events, lowest_time, highest_time


def write_circ_events_file(exp_dir, events):
    """Writes out the CSV file for CIRC events."""

    with open(os.path.join(exp_dir, "events_circ.csv"), "w", newline="") \
            as csv_fp:

        ev_writer = csv.DictWriter(
            csv_fp, fieldnames=[
                "circ_id", "final_purpose", "final_status", "reason",
                "hsdir_fp", "start", "extended_1", "extended_2",
                "extended_3", "extended_4", "end", "rebuilt"])

        ev_writer.writeheader()

        for circ_id in events:

            event = events[circ_id]

            data = {
                "circ_id": circ_id,
                "final_purpose": event["final_purpose"],
                "final_status": event["final_status"],
                "reason": event["reason"],
                "hsdir_fp": event["hsdir_fp"],
                "start": event["start"],
                "extended_1": event["extended_1"],
                "extended_2": event["extended_2"],
                "extended_3": event["extended_3"],
                "extended_4": event["extended_4"],
                "end": event["end"],
                "rebuilt": event["rebuilt"],
            }

            ev_writer.writerow(data)


def group_hs_desc_events_file(events):
    """Translates chronological HS_DESC representation to grouped one."""

    events_grouped = collections.OrderedDict()

    for (addr, hsdir_fp) in events:
        event = events[(addr, hsdir_fp)]

        if addr not in events_grouped:
            events_grouped[addr] = collections.OrderedDict()

        if hsdir_fp not in events_grouped[addr]:

            events_grouped[addr][hsdir_fp] = {
                "status": event["status"],
                "reason": event["reason"],
                "circ": event["circ"],
                "guard_fp": event["guard_fp"],
                "middle_fp": event["middle_fp"],
                "exit_fp": event["exit_fp"],
                "start": event["start"],
                "end": event["end"],
            }

    return events_grouped


def write_hs_desc_events_file(exp_dir, events):
    """Writes out the CSV file for HS_DESC events."""

    with open(os.path.join(exp_dir, "events_hs_desc.csv"), "w", newline="") \
            as csv_fp:

        ev_writer = csv.DictWriter(csv_fp, fieldnames=[
            "addr", "status", "reason", "circ", "guard_fp",
            "middle_fp", "exit_fp", "hsdir_fp", "start", "end"])

        ev_writer.writeheader()

        for addr in events:

            for hsdir_fp in events[addr]:
                event = events[addr][hsdir_fp]

                data = {
                    "addr": addr,
                    "status": event["status"],
                    "reason": event["reason"],
                    "circ": event["circ"],
                    "guard_fp": event["guard_fp"],
                    "middle_fp": event["middle_fp"],
                    "exit_fp": event["exit_fp"],
                    "hsdir_fp": hsdir_fp,
                    "start": event["start"],
                    "end": event["end"],
                }

                ev_writer.writerow(data)


def write_results_file(exp_dir, circ_events,
                       hs_desc_events, lowest_time, highest_time):
    """Calculates basic statistics and writes them out to a JSON file."""

    with open(os.path.join(exp_dir, "results.json"), "w") as res_fp:

        # Calculate the run time in seconds.
        run_time_sec = (highest_time - lowest_time).total_seconds()

        circ_cnt = 0
        circ_built_cnt = 0
        circ_failed_cnt = 0

        for circ_id in circ_events:
            circ = circ_events[circ_id]

            # Increment general CIRC counter.
            circ_cnt += 1

            # Increment BUILT counter if successful.
            if circ["final_status"] == "built":
                circ_built_cnt += 1

            # Increment FAILED counter otherwise.
            elif circ["final_status"] == "failed":
                circ_failed_cnt += 1

        hsdesc_cnt = 0
        hsdesc_recvd_cnt = 0
        hsdesc_notfound_cnt = 0

        lookup_timestamps = []

        for (addr, hsdir_fp) in hs_desc_events:
            req = hs_desc_events[(addr, hsdir_fp)]

            # Increment general HS_DESC counter.
            hsdesc_cnt += 1

            # Increment RECEIVED counter if HS_DESC was
            # present at HSDir and received by client.
            if req["status"] == "received":
                hsdesc_recvd_cnt += 1

            # Increment NOT_FOUND counter if HS_DESC was
            # not present at HSDir, HSDir told the client,
            # and we see a matching CIRC for this request.
            elif (req["status"] == "failed") and \
                (req["reason"] == "not_found") and \
                    (req["circ"] is not None):
                hsdesc_notfound_cnt += 1

            # Append all lookup durations to list that exist.
            # This excludes durations of HS_DESC requests that
            # somehow completed but we could not match to a
            # circuit. As we rely on circuit timing information
            # to calculate the duration, there is not much we
            # can do in these cases.
            if req["lookup_timestamps"] is not None:
                lookup_timestamps.append(req["lookup_timestamps"])

        # Calculate CIRC and HS_DESC items that have
        # undetermined (= neither success nor failed) status.
        circ_undetermined_cnt = circ_cnt - circ_built_cnt - circ_failed_cnt
        hsdesc_other_cnt = hsdesc_cnt - hsdesc_recvd_cnt - hsdesc_notfound_cnt

        # Calculate the rate of BUILT CIRC per second.
        circ_built_per_sec = circ_built_cnt / run_time_sec

        # Calculate the rate of HS_DESC with completion
        # reason NOT_FOUND per second.
        hsdesc_notfound_per_sec = hsdesc_notfound_cnt / run_time_sec

        results = {
            "run_time_sec": run_time_sec,
            "circ_built_per_sec": circ_built_per_sec,
            "hsdesc_notfound_per_sec": hsdesc_notfound_per_sec,
            "circ_cnt": circ_cnt,
            "circ_built_cnt": circ_built_cnt,
            "circ_failed_cnt": circ_failed_cnt,
            "circ_undetermined_cnt": circ_undetermined_cnt,
            "hsdesc_cnt": hsdesc_cnt,
            "hsdesc_recvd_cnt": hsdesc_recvd_cnt,
            "hsdesc_notfound_cnt": hsdesc_notfound_cnt,
            "hsdesc_other_cnt": hsdesc_other_cnt,
            "lookup_timestamps": lookup_timestamps,
        }

        # Dump assembled results dictionary to JSON file.
        json.dump(results, res_fp, indent=4)
        res_fp.write("\n")


def main():
    """Process the events log file and output relevant times."""

    try:

        if os.getuid() == 0:
            print("Do not run this program as root.")
            sys.exit(1)

        # Define and parse command-line arguments.
        parser = argparse.ArgumentParser()
        parser.add_argument("--exp_dir", type=str, required=True,
                            help="Specify the file system location "
                            "of the experiment directory to analyze.")
        parser.add_argument("--worker_id", type=int, default=0,
                            help="ID of worker to process logs for.")
        args = parser.parse_args()

        # As a fail-safe, search for "[warn]"-prefixed lines
        # in Tor log of this run to alert user about them.
        print_warn_tor_log_lines(args.exp_dir)

        # Parse file into events hashmap.
        with open(os.path.join(args.exp_dir, "victim_client_events.log"),
                  "r") as ev_fp:

            circ_events, hs_desc_events, lowest_time, highest_time = \
                parse_events(ev_fp, args.worker_id)

        # Write out CIRC events to CSV.
        write_circ_events_file(args.exp_dir, circ_events)

        # Group HS_DESC by address.
        hs_desc_events_grouped = group_hs_desc_events_file(hs_desc_events)

        # Write out HS_DESC events to CSV.
        write_hs_desc_events_file(args.exp_dir, hs_desc_events_grouped)

        # Calculate basic statistics and
        # generate JSON results file.
        write_results_file(
            args.exp_dir, circ_events, hs_desc_events,
            lowest_time, highest_time)

    except KeyboardInterrupt:
        print("[main] Ended by receiving a keyboard interrupt.")


if __name__ == "__main__":
    main()
