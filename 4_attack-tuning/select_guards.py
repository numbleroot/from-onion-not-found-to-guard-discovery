#!/usr/bin/env python3

"""
Download information about all running guards in order to sort
the list by some specific criterion and use it in our experiments.
"""

import csv
import argparse
from sys import exit as sysexit
from os import getuid
from os.path import abspath, join
from datetime import datetime
from random import shuffle
from numpy import random as nprandom
import requests


ONIONOO_BASE_URL = "https://onionoo.torproject.org"
ONIONOO_DOC_TYPE = "details"
ONIONOO_PARAM_RELAY = "type=relay"
ONIONOO_PARAM_RUNNING = "running=true"

ONIONOO_PARAM_FLAG_GUARD = "flag=guard"
ONIONOO_PARAM_GUARDS_FIELDS = "fields=nickname,fingerprint,"\
    "or_addresses,dir_address,country,advertised_bandwidth,"\
    "guard_probability"

ONIONOO_PARAM_RELAYS_FIELDS = "fields=nickname,fingerprint,"\
    "flags,country,region_name,city_name,latitude,longitude,as,"\
    "advertised_bandwidth,guard_probability,middle_probability,"\
    "exit_probability"


def build_onionoo_url(is_guard_query):
    """Puts all parts of the Onionoo query URL together."""

    if is_guard_query:
        return "{}/{}?{}&{}&{}&{}".format(
            ONIONOO_BASE_URL, ONIONOO_DOC_TYPE, ONIONOO_PARAM_RELAY,
            ONIONOO_PARAM_RUNNING, ONIONOO_PARAM_FLAG_GUARD,
            ONIONOO_PARAM_GUARDS_FIELDS)

    else:
        return "{}/{}?{}&{}&{}".format(
            ONIONOO_BASE_URL, ONIONOO_DOC_TYPE, ONIONOO_PARAM_RELAY,
            ONIONOO_PARAM_RUNNING, ONIONOO_PARAM_RELAYS_FIELDS)


def make_onionoo_req(url):
    """Issues the Onionoo request and returns the JSON response."""

    try:
        # Request the data from Onionoo endpoint.
        resp = requests.get(url)

        # Parse response as JSON.
        resp_json = resp.json()

        # Raise any exception, if occured.
        resp.raise_for_status()

    except requests.HTTPError as err:
        print(err)

    except Exception as err:
        print(err)

    else:
        return resp_json


def select_guards_by_cumul_guard_prob(fraction, guards):
    """Returns a new list containing all guards sorted in descending
    guard probability order until the supplied cumulative fraction
    of guard probability is reached."""

    guards_selected = list()
    cumul_prob = 0.0

    for guard in guards:

        # Append current guard to new list and update cumulative
        # guard probability with its individual value.
        guards_selected.append(guard)
        cumul_prob += guard["guard_probability"]

        # Once we hit our target fraction, we exit.
        if cumul_prob >= fraction:
            break

    return guards_selected


def select_guards_by_cumul_adv_band(fraction, guards):
    """Returns a new list containing all guards sorted in descending
    advertised bandwidth order until the supplied cumulative fraction
    of advertised bandwidth is reached."""

    guards_selected = list()
    total_band = 0.0
    target_band = 0.0
    cumul_band = 0.0

    for guard in guards:
        total_band += guard["advertised_bandwidth"]

    # Once we know the total advertised bandwidth, we can
    # calculate the bytes-per-second value that corresponds
    # to the supplied fraction argument.
    target_band = total_band * fraction

    for guard in guards:

        # Append current guard to new list and update cumulative
        # advertised bandwidth with its individual value.
        guards_selected.append(guard)
        cumul_band += guard["advertised_bandwidth"]

        # Once we hit our target bandwidth, we exit.
        if cumul_band >= target_band:
            break

    return guards_selected


def write_guards_list_file(path, guards):
    """Writes the list of selected guards as CSV to file system location."""

    with open(path, "w") as guards_fp:

        guards_writer = csv.DictWriter(
            guards_fp, fieldnames=[
                "nickname", "fingerprint", "or_address_v4", "dir_address",
                "country", "advertised_bandwidth", "guard_probability"])

        guards_writer.writeheader()

        for guard in guards:

            or_address = guard["or_addresses"][0]

            for addr in guard["or_addresses"]:
                if (addr.count(".") == 3) and (addr.count(":") == 1):
                    or_address = addr

            dir_address = "none"
            if "dir_address" in guard:
                dir_address = guard["dir_address"]

            country = "unknown"
            if "country" in guard:
                country = guard["country"]

            data = {
                "nickname": guard["nickname"],
                "fingerprint": guard["fingerprint"],
                "or_address_v4": or_address,
                "dir_address": dir_address,
                "country": country,
                "advertised_bandwidth": guard["advertised_bandwidth"],
                "guard_probability": guard["guard_probability"],
            }

            guards_writer.writerow(data)


def write_relays_list_file(path, relays):
    """Writes the list of all relays as CSV to file system location."""

    with open(path, "w") as relays_fp:

        relays_writer = csv.DictWriter(
            relays_fp, fieldnames=[
                "nickname", "fingerprint", "is_guard", "is_exit", "country",
                "region_name", "city_name", "latitude", "longitude", "as",
                "advertised_bandwidth", "guard_probability",
                "middle_probability", "exit_probability"])

        relays_writer.writeheader()

        for relay in relays:

            is_guard = False
            if "Guard" in relay["flags"]:
                is_guard = True

            is_exit = False
            if "Exit" in relay["flags"]:
                is_exit = True

            country = "unknown"
            if "country" in relay:
                country = relay["country"]

            region_name = "unknown"
            if "region_name" in relay:
                region_name = relay["region_name"]

            city_name = "unknown"
            if "city_name" in relay:
                city_name = relay["city_name"]

            latitude = "unknown"
            if "latitude" in relay:
                latitude = relay["latitude"]

            longitude = "unknown"
            if "longitude" in relay:
                longitude = relay["longitude"]

            as_name = "unknown"
            if "as" in relay:
                as_name = relay["as"]

            data = {
                "nickname": relay["nickname"],
                "fingerprint": relay["fingerprint"],
                "is_guard": is_guard,
                "is_exit": is_exit,
                "country": country,
                "region_name": region_name,
                "city_name": city_name,
                "latitude": latitude,
                "longitude": longitude,
                "as": as_name,
                "advertised_bandwidth": relay["advertised_bandwidth"],
                "guard_probability": relay["guard_probability"],
                "middle_probability": relay["middle_probability"],
                "exit_probability": relay["exit_probability"],
            }

            relays_writer.writerow(data)


def select_guards(cumul_guard_prob_perc, cumul_adv_band_perc,
                  num_sampled_from_guard_prob, randomize, output_dir):
    """Accept parameters specifying the criterion on which to select
    guards, download relay infos, sort the guard list, select the guards,
    possibly permute the guards list, and finally store both lists."""

    if getuid() == 0:
        return "Do not run this program as root."

    # Stash current time and use it for output file.
    now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    if (cumul_guard_prob_perc * cumul_adv_band_perc *
            num_sampled_from_guard_prob) <= 0:
        return "Exactly one selection criterion (cumul_guard_prob_perc, " \
            "cumul_adv_band_perc, num_sampled_from_guard_prob) must be " \
            "set to an appropriate value of its respective domain."

    if ((cumul_guard_prob_perc > 0) and (cumul_adv_band_perc > 0)
            and (num_sampled_from_guard_prob > 0)):
        return "Exactly one selection criterion (cumul_guard_prob_perc, " \
            "cumul_adv_band_perc, num_sampled_from_guard_prob) must be " \
            "set to an appropriate value of its respective domain."

    if cumul_guard_prob_perc > 0:
        cumul_guard_prob_perc = (cumul_guard_prob_perc / 100.0)

    elif cumul_adv_band_perc > 0:
        cumul_adv_band_perc = (cumul_adv_band_perc / 100.0)

    # Build the two (guards, all relays) file paths.
    relay_file = join(output_dir, "{}_relays.csv".format(now))

    if cumul_guard_prob_perc > 0:
        guard_file = \
            join(output_dir, "{}_guards_cumul_guard_prob_perc-{}.csv"
                 .format(now, cumul_guard_prob_perc))

    elif cumul_adv_band_perc > 0:
        guard_file = \
            join(output_dir, "{}_guards_cumul_adv_band_perc-{}.csv"
                 .format(now, cumul_adv_band_perc))

    elif num_sampled_from_guard_prob > 0:
        guard_file = \
            join(output_dir, "{}_guards_num_sampled_from_guard_prob-{}.csv"
                 .format(now, num_sampled_from_guard_prob))

    # Construct the two request URLs.
    onionoo_guards_url = build_onionoo_url(True)
    onionoo_relays_url = build_onionoo_url(False)

    # Issue the two requests and obtain the JSON responses.
    guards_resp = make_onionoo_req(onionoo_guards_url)
    relays_resp = make_onionoo_req(onionoo_relays_url)

    if cumul_guard_prob_perc > 0:

        # Sort list of relays by guard probability in descending order.
        guards_sorted = sorted(
            guards_resp["relays"],
            key=lambda relay: relay["guard_probability"],
            reverse=True)

        # Create final list of guards selected by decreasing guard
        # probability until target cumulative percentage is reached.
        guards_selected = select_guards_by_cumul_guard_prob(
            cumul_guard_prob_perc, guards_sorted)

    elif cumul_adv_band_perc > 0:

        # Sort list of relays by advertised bandwidth in descending order.
        guards_sorted = sorted(
            guards_resp["relays"],
            key=lambda relay: relay["advertised_bandwidth"],
            reverse=True)

        # Create final list of guards selected by decreasing advertised
        # bandwidth until target cumulative percentage is reached.
        guards_selected = select_guards_by_cumul_adv_band(
            cumul_adv_band_perc, guards_sorted)

    elif num_sampled_from_guard_prob > 0:

        guards = guards_resp["relays"]

        # Extract weights of each guard in order of
        # appearance of the guard in the list.
        guards_weights = []
        for guard in guards:
            guards_weights.append(guard["guard_probability"])

        # Sample the configured number of guards without
        # replacement from the list of guards weighted
        # by their individual guard probability.
        guards_selected_unsorted = nprandom.choice(
            guards, size=num_sampled_from_guard_prob,
            replace=False, p=guards_weights)

        # Sort sampled list of guards in descending
        # order of their guard probability.
        guards_selected = sorted(
            guards_selected_unsorted,
            key=lambda guard: guard["guard_probability"],
            reverse=True)

    if randomize:
        shuffle(guards_selected)

    # Write the two lists to files.
    write_guards_list_file(guard_file, guards_selected)
    write_relays_list_file(relay_file, relays_resp["relays"])

    return "success"


if __name__ == "__main__":

    # Define and parse command-line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument("--cumul_guard_prob_perc", type=float, default=-1.0,
                        help="Select all guards that collectively account for "
                        "X per cent of the total guard selection probability, "
                        "chosen by descending individual selection probability"
                        " (e.g., X = 75.0).")
    parser.add_argument("--cumul_adv_band_perc", type=float, default=-1.0,
                        help="Select all guards that collectively account for "
                        "X per cent of the total advertised guard bandwidth, "
                        "chosen by descending individual advertised bandwidth "
                        "(e.g., X = 50.0).")
    parser.add_argument("--num_sampled_from_guard_prob", type=int, default=-1,
                        help="Return this number of guards, sampled from their"
                        " guard probability distribution.")
    parser.add_argument("--randomize", type=bool, default=False,
                        help="After selecting guards by means of the "
                        "cumulative criterion, shuffle the selected list "
                        "before storing it at the specified location.")
    parser.add_argument("--output_dir", type=str,
                        default=abspath("./experiments_relay-lists"),
                        help="File system location of output directory.")
    args = parser.parse_args()

    selection_result = select_guards(
        args.cumul_guard_prob_perc, args.cumul_adv_band_perc,
        args.num_sampled_from_guard_prob, args.randomize, args.output_dir)

    if selection_result != "success":
        print(selection_result)
        sysexit(1)
