#!/usr/bin/env python3

"""
Parses the tor log of an experiment.
Right now, the only check performed is whether at any point
the fixed guard was supposed to be contacted as HSDir as well.
"""

import re
import json
import argparse
from glob import glob
from sys import exit as sysexit
from os import getuid
from os.path import join


def parse_tor_log(experiment_dir, guard_fp):
    """Accepts an experiment folder and possibly the guard's fingerprint,
    and parses the contained tor log."""

    if getuid() == 0:
        return "Do not run this program as root."

    # If no guard fingerprint was supplied as argument,
    # load it from the experiment's JSON file.
    if guard_fp == "":
        with open(join(experiment_dir, "experiment.json"), "r") as exp_fp:
            guard_fp = json.load(exp_fp)["guard_fp"]

    # Construct path to tor log of experiment.
    tor_log = glob(join(experiment_dir, "tor_*.log"))[0]

    # Count how often either the v2 or the v3 pattern for
    # an HSDir lookup to the chosen guard is initiated.
    hsdir_is_guard_cnt = 0
    v2_onion_pat = r"directory_get_from_hs_dir\(\): Sending fetch request "\
        r"for v2 descriptor for service '.+' with descriptor ID '.+', auth "\
        r"type 0, and descriptor cookie '\[none\]' to hidden service "\
        r"directory \${}\~.+ at \d+\.\d+\.\d+\.\d+".format(guard_fp)
    v3_onion_pat = r"directory_launch_v3_desc_fetch\(\): Descriptor fetch "\
        r"request for service .+ with blinded key .+ to directory "\
        r"\${}\~.+ at \d+\.\d+\.\d+\.\d+".format(guard_fp)

    # Count how often no suitable relay could be found
    # as the first hop of a new circuit.
    first_hop_failed_cnt = 0
    first_hop_failed_pat = r"Failed to find node for hop \#1 of our path\. "\
        r"Discarding this circuit\."

    # Count how often the experiment's guard is requested
    # as the exit for an about-to-be-attempted circuit.
    guard_as_exit_cnt = 0
    guard_as_exit_pat = r"onion_pick_cpath_exit\(\): Using requested exit "\
        r"node '\${}\~.+ at \d+\.\d+\.\d+\.\d+'".format(guard_fp)

    # Count how often the [notice]-level message is logged that
    # the whole circuit-building process from guard-as-guard to
    # guard-as-HSDir has failed.
    circ_died_cnt = 0
    circ_died_pat = r"Our circuit \d \(id: \d+\) died due to an invalid "\
        r"selected path, purpose Hidden service client: Fetching HS "\
        r"descriptor\. This may be a torrc configuration issue, or a bug\."

    with open(tor_log, "r") as tor_log_fp:

        for line in tor_log_fp:

            if re.search(v2_onion_pat, line) or re.search(v3_onion_pat, line):
                hsdir_is_guard_cnt += 1

            elif re.search(first_hop_failed_pat, line):
                first_hop_failed_cnt += 1

            elif re.search(guard_as_exit_pat, line):
                guard_as_exit_cnt += 1

            elif re.search(circ_died_pat, line):
                circ_died_cnt += 1

    # In case any of the tracked counters has a positive
    # value, add two counter fields to the results JSON file.
    if ((hsdir_is_guard_cnt > 0) or (first_hop_failed_cnt > 0)
            or (guard_as_exit_cnt > 0) or (circ_died_cnt > 0)):

        with open(join(experiment_dir, "results.json"), "r") as res_fp:
            results = json.load(res_fp)

        results["failure_guard_is_hsdir_cnt"] = hsdir_is_guard_cnt
        results["failure_guard_is_hsdir_path_attempts_cnt"] = \
            first_hop_failed_cnt

        with open(join(experiment_dir, "results.json"), "w") as res_fp:
            json.dump(results, res_fp, indent=4)
            res_fp.write("\n")

    else:
        print("No indication that the guard was ever the HSDir, too.")

    return "success"


if __name__ == "__main__":

    # Define and parse command-line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument("--exp_dir", type=str, required=True,
                        help="Specify the file system location "
                        "of the experiment directory to analyze.")
    parser.add_argument("--guard_fp", type=str, default="",
                        help="If the guard fingerprint is not contained "
                        "in the experiment.json, supply it directly.")
    args = parser.parse_args()

    parse_result = parse_tor_log(args.exp_dir, args.guard_fp)

    if parse_result != "success":
        print(parse_result)
        sysexit(1)
