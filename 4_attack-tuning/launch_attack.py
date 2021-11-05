#!/usr/bin/env python3

"""
Run and log Tor Guard Discovery experiments using
Tor Browser Selenium and Stem.
"""

import os
import json
import logging
import argparse
import subprocess
import contextlib
import shutil
from time import sleep
from getpass import getuser
from datetime import datetime
from socket import gethostname
from secrets import randbelow
from multiprocessing import Pool
from os.path import abspath, dirname, join
from sys import exit as sysexit

from stem.control import Controller, EventType
from tbselenium.common import (
    STEM_CONTROL_PORT, STEM_SOCKS_PORT, USE_RUNNING_TOR)
from tbselenium.tbdriver import TorBrowserDriver
from tbselenium.utils import (
    launch_tbb_tor_with_stem, start_xvfb, stop_xvfb,
    set_security_level, SECURITY_HIGH)


GUARD_DISCOVERY_DIR = dirname(abspath(__file__))
ADDR_DIR = join(GUARD_DISCOVERY_DIR, "pregen_addr")
EXPERIMENTS_DIR = join(GUARD_DISCOVERY_DIR, "experiments")

EXP_CONFIG_JSON = "experiment.json"
PACKET_FIELDS_CSV = "network_traffic_fields.csv"
NETWORK_TRAFFIC_PCAP = "network_traffic.pcap"
NETWORK_TRAFFIC_SUMMARY_DATA = "network_traffic_summary.data"

LISTENED_STEM_EVENTS_DEBUG_LEVEL = {
    EventType.BW,
    EventType.CONN_BW,
    EventType.HS_DESC_CONTENT,
    EventType.ORCONN,
    EventType.TRANSPORT_LAUNCHED,
    EventType.BUILDTIMEOUT_SET,
}

LISTENED_STEM_EVENTS_INFO_LEVEL = {
    EventType.CIRC_BW,
    EventType.CIRC,
    EventType.CIRC_MINOR,
    EventType.HS_DESC,
    EventType.STREAM,
    EventType.STREAM_BW,
}

# Log circuits every second.
CIRCUIT_LOG_INTERVAL = 1

# Define buffer times at various stages that
# should result in all components completing
# in enough time.
WORKER_BUFFER_TIME = 15
MAIN_TOR_BUFFER_TIME = 7
MAIN_WORKER_BUFFER_TIME = 15

# We don't log circuits of these purposes.
EXCLUDED_CIRC_PURPOSES = ["GENERAL"]

# Specify how many pregenerated onion address
# files are available for each onion version.
# File names follow the scheme:
#   '<ONION_VER>_<ID_SEQUENCE>.addr'
# where ID_SEQUENCE is a 4-digit, zero-padded
# number from the interval: [0, NUM_ADDR_FILES).
NUM_ADDR_FILES = 20

# Additional, experiment-specific torrc parameters.
# CAUTION: All values have to be strings as well!
ADDITIONAL_TORRC_PARAMS = {}

# Initialize the logger, it will be set up later.
logger = logging.getLogger("guard_discovery")


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


def tshark_capture(attack_duration, output_dir, guard_or_ip,
                   guard_or_port, guard_dir_ip, guard_dir_port):
    """Run tshark command in background to capture traffic with guard."""

    # IMPORTANT: This tshark command captures the network
    #            traffic of _all_ workers connecting to the
    #            guard. It is an aggregate measure and does
    #            not yield per-victim metrics right now.
    #            If needed, this might be achieved by filtering
    #            for victim port when calculating conversation
    #            statistics at the end of the experiment.

    if (guard_or_ip != "none") and (guard_or_port != "none") and \
            (guard_dir_ip != "none") and (guard_dir_port != "none"):

        query = "(host {} and port {}) or (host {} and port {})".format(
            guard_or_ip, guard_or_port, guard_dir_ip, guard_dir_port)

    elif (guard_or_ip != "none") and (guard_or_port != "none"):

        query = "(host {} and port {})".format(guard_or_ip, guard_or_port)

    cmd = ["tshark", "-l", "-f", query, "-w",
           join(output_dir, NETWORK_TRAFFIC_PCAP)]

    capture_dur = attack_duration + WORKER_BUFFER_TIME

    try:

        logger.info("[tshark_capture] Launching PCAP capture "
                    "for %d seconds...", capture_dur)

        # Start recording network traffic using tshark
        # in the background and output it to file.
        if attack_duration >= 0:
            subprocess.run(args=cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=capture_dur,
                           check=True, close_fds=True)
        else:
            subprocess.run(args=cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True,
                           close_fds=True)

    except subprocess.TimeoutExpired:
        logger.info("[tshark_capture] Ended by reaching capture "
                    "duration (%d seconds).", capture_dur)

    except KeyboardInterrupt:
        logger.info(
            "[tshark_capture] Ended by receiving a keyboard interrupt.")


def conn_logger(attack_duration, guard_or_ip, guard_or_port,
                guard_dir_ip, guard_dir_port):
    """Count the number of connections to the guard's OR or DIR port."""

    if logger.getEffectiveLevel() == logging.DEBUG:

        capture_dur = attack_duration
        if attack_duration >= 0:
            capture_dur += WORKER_BUFFER_TIME

        sec_left = capture_dur

        while sec_left != 0:

            num_conns = 0

            # Find all connections.
            conns = subprocess.check_output(
                args=["lsof", "-i4", "-n", "-P"]).decode("utf-8").splitlines()

            # Increment counter if connection is
            # to our fixed entry guard.
            guard_or_addr = "{}:{}".format(guard_or_ip, guard_or_port)
            guard_dir_addr = "{}:{}".format(guard_dir_ip, guard_dir_port)
            for line in conns:
                if (guard_or_addr in line) or (guard_dir_addr in line):
                    num_conns += 1

            # Output counters to log file.
            logger.debug("[conn_logger] global_num_conns=%d", num_conns)

            sleep(1)
            sec_left -= 1

            logger.debug(
                "[conn_logger] End of capture (%d seconds).",
                capture_dur)


def tor_browser_worker(worker_id, tbb, adv_url, guard_fp, capture_dur,
                       output_dir, browser_state_dir, tor_control_port,
                       tor_socks_port, use_virtual_display, tor_log_level,
                       no_js, attack_duration):
    """Launch Tor Browser and load the attack page."""

    xvfb_display = None
    torrc = {
        "SOCKSPort": str(tor_socks_port),
        "ControlPort": str(tor_control_port),
        "EntryNode": guard_fp,
        "DataDirectory": browser_state_dir,
        "Log": "{} file {}".format(
            tor_log_level, join(
                output_dir, "tor_{}.log".format(tor_socks_port))),
        "SafeLogging": "0",
        "LogTimeGranularity": "1"  # in milliseconds
    }

    # Append experiment-specific additional
    # arguments, in case they have been set
    # for this experiment run.
    torrc.update(ADDITIONAL_TORRC_PARAMS)

    should_log_circuits = logger.getEffectiveLevel() == logging.DEBUG

    def log_event_on_info(event):
        logger.info("[tor_browser_worker%d] [EVENT] %s", worker_id, event)

    def log_event_on_debug(event):
        logger.debug("[tor_browser_worker%d] [EVENT] %s", worker_id, event)

    try:
        # Launch tor process with custom torrc via stem.
        logging.debug(
            "[tor_browser_worker%d] Starting tor via stem",
            worker_id)
        tor_process = launch_tbb_tor_with_stem(tbb_path=tbb, torrc=torrc)

        logging.debug(
            "[tor_browser_worker%d] Starting TorBrowserDriver",
            worker_id)

        if use_virtual_display:
            # Start a virtual display.
            xvfb_display = start_xvfb()

        with TorBrowserDriver(
                tbb, socks_port=tor_socks_port, control_port=tor_control_port,
                tor_cfg=USE_RUNNING_TOR) as driver:

            if no_js:  # scriptless attack
                logger.info(
                    "[tor_browser_worker%d] Tor Browser will disable JS",
                    worker_id)
                set_security_level(driver, SECURITY_HIGH)
            with Controller.from_port(port=tor_control_port) as controller:
                controller.authenticate()

                for event in LISTENED_STEM_EVENTS_DEBUG_LEVEL:
                    controller.add_event_listener(
                        log_event_on_debug, event)

                for event in LISTENED_STEM_EVENTS_INFO_LEVEL:
                    controller.add_event_listener(
                        log_event_on_info, event)

                # Load adversarial webpage.
                logger.info(
                    "[tor_browser_worker%d] Tor Browser will load the attack "
                    "page: %s, SOCKS port: %d, control port: %d",
                    worker_id, adv_url, tor_socks_port, tor_control_port)

                # time out to avoid exceeding the attack duration
                driver.set_page_load_timeout(attack_duration)
                driver.load_url(adv_url)

                sec_left = capture_dur

                # Run for as long as capture_dur specifies in
                # seconds, or forever if set to a negative value.
                while sec_left != 0:

                    if should_log_circuits:
                        log_tor_circuits(controller, worker_id)

                    sleep(CIRCUIT_LOG_INTERVAL)
                    sec_left -= CIRCUIT_LOG_INTERVAL

                logger.info(
                    "[tor_browser_worker%d] End of capture (%d seconds).",
                    worker_id, capture_dur)

    except KeyboardInterrupt:
        raise

    except Exception as exc:
        logger.exception(
            "[tor_browser_worker%d] Exception while running stem and Tor "
            "Browser: %s", worker_id, exc)

    finally:

        if xvfb_display is not None:
            stop_xvfb(xvfb_display)

        if tor_process:
            tor_process.kill()


def log_tor_circuits(controller, worker_id):
    """Log circuits with a purpose of interest."""

    # Gather total number and status of circuits.
    for circ in sorted(controller.get_circuits()):

        if circ.purpose in EXCLUDED_CIRC_PURPOSES:
            continue

        logger.debug(
            "[tor_browser_worker%d] CIRCUIT#%d purpose=%s status=%s "
            "hs_state=%s created=%s reason=%s remote_reason=%s",
            worker_id, circ.id, circ.purpose, circ.status, circ.hs_state,
            circ.created, circ.reason, circ.remote_reason)


def setup_logger(output_dir, log_level="INFO", log_to_console=False):
    """Configure global logger according to preferences and CLI arguments."""

    file_handler = logging.FileHandler(
        join(output_dir, "victim_client_events.log"))

    handlers = [file_handler]

    if log_to_console:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s:%(msecs)03d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S", handlers=handlers)


def extract_packet_fields_from_pcap(output_dir):
    """Extract packet fields from the PCAP in the given output directory."""

    logger.info("[main] Executing the tshark processing commands now...")
    cmd = ["tshark", "-n", "-r", join(output_dir, NETWORK_TRAFFIC_PCAP),
           "-T", "fields", "-E", "header=y", "-E", "separator=,", "-e",
           "frame.number", "-e", "frame.time_relative", "-e", "frame.len",
           "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e",
           "tcp.dstport"]

    with open(join(output_dir, PACKET_FIELDS_CSV), "w") as traffic_fields_file:
        subprocess.run(args=cmd, stdout=traffic_fields_file,
                       stderr=subprocess.DEVNULL, check=True, close_fds=True)


def extract_network_summary_from_pcap(output_dir):
    """Extract network summary from the PCAP in the given output directory."""

    cmd = [
        "tshark", "-q", "-n", "-r", join(output_dir, NETWORK_TRAFFIC_PCAP),
        "-z", "io,stat,1,BYTES", "-z", "conv,tcp"]

    summary_data_path = join(output_dir, NETWORK_TRAFFIC_SUMMARY_DATA)

    with open(summary_data_path, "w") as traffic_summary_file:
        subprocess.run(args=cmd, stdout=traffic_summary_file,
                       stderr=subprocess.DEVNULL, check=True, close_fds=True)


def dump_experiment_config(exp_start_time, tag, user, host, tbb, adv_page,
                           addr_file, attack_duration, log_level, num_parallel,
                           auto_start, onion_ver, resource_type, rate_per_sec,
                           guard_fp, guard_or_ip, guard_or_port, guard_dir_ip,
                           guard_dir_port, output_dir, no_js):
    """Dumps the set of parameters that characterize this
    experiment run to a JSON file in the output directory."""

    try:

        # Extract number of CPU cores on machine.
        cpu_cores_grep = subprocess.check_output(
            args=["grep", "^processor", "/proc/cpuinfo"])\
            .decode("utf-8").splitlines()

        cpu_cores_num = len(cpu_cores_grep)

    except BaseException:
        cpu_cores_num = "not found"

    try:
        # Extract amount of RAM on machine.
        mem_total_grep = subprocess.check_output(
            args=["grep", "MemTotal", "/proc/meminfo"])\
            .decode("utf-8").splitlines()

        for line in mem_total_grep:
            mem_total_kb = line.split(":")[1].strip()
            mem_total_kb = mem_total_kb.split(" ")[0]
            break

    except BaseException:
        mem_total_kb = "not found"

    try:
        # Extract tc configuration applied to this machine.
        tc_ifb0_conf = "not set"

        tc_ifb0_speeds_conf = subprocess.check_output(
            args=["tc", "-g", "-s", "class", "show", "dev", "ifb0"])\
            .decode("utf-8").splitlines()

        for line in tc_ifb0_speeds_conf:
            if "prio 0 rate" in line:
                line = line.strip()
                tc_ifb0_speeds = line.split("prio 0 ")[1]
                tc_ifb0_conf = " ".join(tc_ifb0_speeds.split())
                break

        tc_ifb0_latency_loss_conf = subprocess.check_output(
            args=["tc", "qdisc", "show", "dev", "ifb0"])\
            .decode("utf-8").splitlines()

        for line in tc_ifb0_latency_loss_conf:
            if "root refcnt 2 limit" in line:
                line = line.strip()
                tc_ifb0_lat_loss = line.split("root refcnt 2 ")[1]
                tc_ifb0_lat_loss = " ".join(tc_ifb0_lat_loss.split())
                tc_ifb0_conf = "{}, {}".format(tc_ifb0_conf, tc_ifb0_lat_loss)
                break

    except BaseException:
        tc_ifb0_conf = "not set"

    try:
        tc_eth0_conf = "not set"

        tc_eth0_speeds_conf = subprocess.check_output(
            args=["tc", "-g", "-s", "class", "show", "dev", "eth0"])\
            .decode("utf-8").splitlines()

        for line in tc_eth0_speeds_conf:
            if "prio 0 rate" in line:
                line = line.strip()
                tc_eth0_speeds = line.split("prio 0 ")[1]
                tc_eth0_conf = " ".join(tc_eth0_speeds.split())
                break

        tc_eth0_latency_loss_conf = subprocess.check_output(
            args=["tc", "qdisc", "show", "dev", "eth0"])\
            .decode("utf-8").splitlines()

        for line in tc_eth0_latency_loss_conf:
            if "root refcnt 2 limit" in line:
                line = line.strip()
                tc_eth0_lat_loss = line.split("root refcnt 2 ")[1]
                tc_eth0_lat_loss = " ".join(tc_eth0_lat_loss.split())
                tc_eth0_conf = "{}, {}".format(tc_eth0_conf, tc_eth0_lat_loss)
                break

    except BaseException:
        tc_eth0_conf = "not set"

    try:
        # Extract used Tor Browser version.
        with open(os.path.join(tbb, "Browser/tbb_version.json"), "r") as tbb_fp:
            tbb_version = json.load(tbb_fp)["version"]

    except BaseException:
        tbb_version = "not found"

    config = {
        "start_time": exp_start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "tag": tag,
        "user": user,
        "host": host,
        "cpu_cores_num": cpu_cores_num,
        "mem_total_kb": mem_total_kb,
        "tc_ifb0_conf": tc_ifb0_conf,
        "tc_eth0_conf": tc_eth0_conf,
        "tbb": tbb,
        "tbb_version": tbb_version,
        "adv_page": adv_page,
        "chosen_addr_file": addr_file,
        "attack_duration": attack_duration,
        "log_level": log_level,
        "num_parallel": num_parallel,
        "auto_start": auto_start,
        "onion_ver": onion_ver,
        "resource_type": resource_type,
        "rate_per_sec": rate_per_sec,
        "guard_fp": guard_fp,
        "guard_or_ip": guard_or_ip,
        "guard_or_port": guard_or_port,
        "guard_dir_ip": guard_dir_ip,
        "guard_dir_port": guard_dir_port,
        "circuit_log_interval": CIRCUIT_LOG_INTERVAL,
        "worker_buffer_time": WORKER_BUFFER_TIME,
        "main_tor_buffer_time": MAIN_TOR_BUFFER_TIME,
        "main_worker_buffer_time": MAIN_WORKER_BUFFER_TIME,
        "excluded_circ_purposes": EXCLUDED_CIRC_PURPOSES,
        "additional_torrc_params": ADDITIONAL_TORRC_PARAMS,
        "no_js": no_js,
    }

    with open(join(output_dir, EXP_CONFIG_JSON), "w") as exp_fp:
        json.dump(config, exp_fp, indent=4)
        exp_fp.write("\n")


def build_attack_page_url(auto_start, adv_page, onion_ver,
                          resource_type, rate_per_sec):
    """Builds the attack page URL."""

    # Convert auto_start argument from bool to lower-case string.
    auto_start = str(auto_start).lower()

    # Prepare attack URL template by combining its components.
    attack_url_template = \
        "%s?autoStart=%s&onionVer=%s&mediaType=%s&ratePerSec=%s"

    # Initially set the full URL or path to the adversarial
    # website to the supplied CLI argument.
    adv_page_path = adv_page

    # In case the website argument is not pointing to a remote
    # website, compose the full file:// URL to a local resource.
    if not adv_page.startswith("http"):
        adv_page_path = "file://" + adv_page

    # Replace all placeholders with the correct arguments.
    adv_url = attack_url_template % (
        adv_page_path, auto_start, onion_ver, resource_type, rate_per_sec)

    return adv_url


def wait_for_workers_to_finish(attack_duration):
    """Wait for specified experiment run time before shutting down."""

    # Sleep until the specified duration.
    sleep(attack_duration + MAIN_TOR_BUFFER_TIME)
    logger.info(
        "[main] Capture duration reached, Tor Browser(s) will shut down now.")
    logger.info(
        "[main] Waiting for tshark_capture and conn_logger to terminate.")

    # Wait for tshark_capture and conn_logger to finish up.
    sleep(MAIN_WORKER_BUFFER_TIME)
    logger.info(
        "[main] Assuming tshark_capture and conn_logger are done, "
        "starting postprocessing.")


def launch_workers(num_parallel, output_dir, tbb, attack_duration,
                   virtual_display, tor_log_level, adv_page, addr_file,
                   guard_fp, auto_start, onion_ver, resource_type,
                   rate_per_sec, guard_or_ip, guard_or_port, guard_dir_ip,
                   guard_dir_port, no_js):
    """Launch client-side processes involved in the attack."""

    # Prepare adversarial webpage URL.
    if no_js and not adv_page.startswith("http"):
        # we don't need any url params in the noscript attack
        adv_url = "file://" + abspath(adv_page)
    else:
        adv_url = build_attack_page_url(
            auto_start, adv_page, onion_ver, resource_type, rate_per_sec)

    # In case adv_url is a local, 'file://' website, take care
    # of embedding the randomly chosen pregenerated addresses
    # into the website.
    # We don't embed random onions in the scriptless attack
    if adv_url.startswith("file://") and not no_js:

        # Copy adversarial website file as backup.
        shutil.copy2(adv_page, (adv_page + ".bak"))

        # Read the adversarial website file entirely.
        with open(adv_page, "r") as adv_page_fp:
            adv_page_content = adv_page_fp.read()

        # Read selected address file entirely.
        with open(addr_file, "r") as addr_file_fp:
            addr_list = addr_file_fp.read().split("\n")

        # Compose address string by joining the list
        # elements and prefixing the variable assignment.
        addr_str = "\",\n\t\t\t\"".join(addr_list)
        addr_str = "var addrList = [\n\t\t\t\"" + addr_str + "\",\n\t\t];"

        # Replace the addrList assignment in the adversarial
        # website with the prepared list of addresses.
        adv_page_content = \
            adv_page_content.replace("var addrList = [];", addr_str)

        # Overwrite adversarial website with new content.
        with open(adv_page, "w") as adv_page_fp:
            adv_page_fp.write(adv_page_content)

    # Prepare num_parallel + 2 workers to handle num_parallel
    # Tor clients, the global traffic volume logger, and the
    # global connection counter.
    num_workers = num_parallel + 2

    try:

        with Pool(num_workers) as pool:

            worker_args = []

            # Launch background traffic volume logger.
            pool.starmap_async(
                tshark_capture, [(attack_duration, output_dir,
                                  guard_or_ip, guard_or_port,
                                  guard_dir_ip, guard_dir_port), ])

            # Launch background connection count logger.
            pool.starmap_async(
                conn_logger, [(attack_duration, guard_or_ip, guard_or_port,
                               guard_dir_ip, guard_dir_port), ])

            for i in range(num_parallel):

                tor_control_port = (STEM_CONTROL_PORT + (i * 10))
                tor_socks_port = (STEM_SOCKS_PORT + (i * 10))

                browser_state_dir = join(
                    GUARD_DISCOVERY_DIR,
                    "tor_browser_state_{}".format(tor_socks_port))

                # Remove the tor state file
                with contextlib.suppress(FileNotFoundError):
                    os.remove(join(browser_state_dir, "state"))

                os.makedirs(browser_state_dir, exist_ok=True)

                # Prepare argument lists for victim client
                # processes about to be launched.
                worker_args.append(
                    (i, tbb, adv_url, guard_fp, attack_duration, output_dir,
                     browser_state_dir, tor_control_port, tor_socks_port,
                     virtual_display, tor_log_level, no_js, attack_duration))

                # Run the actual victim processes in parallel.
                pool.starmap_async(tor_browser_worker, worker_args)

            # Do not accept new jobs for the pool.
            pool.close()

            # If not set to infinite run time, wait for the
            # specified number of seconds to elapse before
            # cleaning up and shutting down.
            if attack_duration != -1:
                wait_for_workers_to_finish(attack_duration)

            # Wait for all workers to finish their jobs.
            pool.join()

    except KeyboardInterrupt:
        raise

    except Exception as exc:
        logger.exception("Error: %s", exc)

    finally:

        # Terminate all workers and the pool itself.
        if pool:
            pool.terminate()

        # In case the adversarial website was a local file,
        # move the original website copied to ".bak" back to
        # its original location (overwriting the modified file).
        if adv_url.startswith("file://") and not no_js:
            shutil.move((adv_page + ".bak"), adv_page)


def launch_attack(tbb, log_level, tor_log_level, log_to_console,
                  experiments_dir, virtual_display, tag, num_parallel,
                  attack_duration, guard_fp, adv_page, auto_start,
                  onion_ver, resource_type, rate_per_sec, guard_or_ip,
                  guard_or_port, guard_dir_ip, guard_dir_port, no_js):
    """Parse arguments and spawn logging and worker processes."""

    if os.getuid() == 0:
        return "Do not call this function as root."

    # Stash current time and use it for output folder.
    now = datetime.now()
    now_formatted = now.strftime("%Y-%m-%d-%H-%M-%S")

    # Stash user running this script
    # and the host it is run on.
    user = getuser()
    host = gethostname()

    add_torrc_par = ""
    if any(ADDITIONAL_TORRC_PARAMS):
        add_torrc_par = "_" + "_".join(
            "%s-%s" % (key, value) for (key, value)
            in ADDITIONAL_TORRC_PARAMS.items())

    # Default the randomly chosen pregenerated address
    # file to exception string in case the user-supplied
    # adversarial website is located remotely.
    addr_file = "does not apply, remote adv_page"

    if not adv_page.startswith("http") and not no_js:

        # Expand possibly relative path to absolute path.
        adv_page = abspath(adv_page)

        # Pick a random file containing 5k pregenerated
        # onion addresses based on onion_ver argument.
        rand_num_str = str(randbelow(NUM_ADDR_FILES)).zfill(4)
        addr_file = join(
            ADDR_DIR, "v{}_{}.addr".format(onion_ver, rand_num_str))

    # Include a tag if supplied.
    tag_formatted = ""
    if tag != "":
        tag_formatted = tag + "_"

    # Construct experiment-specific output folder name.
    experiment_name = "{}_{}{}-{}_{}-v{}-{}-{}s{}".format(
        now_formatted, tag_formatted, user, host, rate_per_sec, onion_ver,
        resource_type, attack_duration, add_torrc_par)
    output_dir = join(experiments_dir, tag, experiment_name)

    # Create output folder for this experiment run.
    os.makedirs(output_dir, exist_ok=True)

    # Set up logging to log file.
    setup_logger(output_dir, log_level, log_to_console)

    logger.info("[main] Events log file for victim clients.")
    logger.info("[main] Will use the output directory: %s", output_dir)

    dump_experiment_config(now, tag, user, host, tbb, adv_page, addr_file,
                           attack_duration, log_level, num_parallel,
                           auto_start, onion_ver, resource_type, rate_per_sec,
                           guard_fp, guard_or_ip, guard_or_port, guard_dir_ip,
                           guard_dir_port, output_dir, no_js)
    launch_workers(num_parallel, output_dir, tbb, attack_duration,
                   virtual_display, tor_log_level, adv_page, addr_file,
                   guard_fp, auto_start, onion_ver, resource_type,
                   rate_per_sec, guard_or_ip, guard_or_port, guard_dir_ip,
                   guard_dir_port, no_js)
    extract_packet_fields_from_pcap(output_dir)
    extract_network_summary_from_pcap(output_dir)

    # As a fail-safe, search for "[warn]"-prefixed lines
    # in Tor log of this run to alert user about them.
    print_warn_tor_log_lines(output_dir)

    logger.info("[main] All done! Data in %s", output_dir)

    return "success"


if __name__ == "__main__":

    # Define and parse command-line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument("--log_level", type=str, default="INFO",
                        choices=logging._nameToLevel.keys(),
                        help="Specify log level of a run.")
    parser.add_argument("--log_to_console", default=False, action="store_true",
                        help="Enable console logs.")
    parser.add_argument("--tor_log_level", type=str, default="info",
                        choices=["info", "debug"], help="Tor log level.")
    parser.add_argument("--experiments_dir", type=str, default=EXPERIMENTS_DIR,
                        help="Specify folder to save experiment folders in.")
    parser.add_argument("--virtual_display", default=False,
                        action="store_true", help="Use a virtual display.")

    parser.add_argument("--tag", type=str, default="",
                        help="Supply a tag to associate this experiment to "
                        "a high-level set of experiments or make it unique.")

    parser.add_argument("--tbb", type=str, required=True,
                        help="Path to Tor Browser Bundle folder.")
    parser.add_argument("--num_parallel", type=int, default=1,
                        help="Number of parallel Tor Browsers to launch.")
    parser.add_argument("--attack_duration", type=int, default=-1,
                        help="Number of seconds the experiment will run for.")
    parser.add_argument("--adv_page", type=str, default=os.path.join(
        GUARD_DISCOVERY_DIR, "adv_website.html"), help="Attack page URL.")
    parser.add_argument("--disable_auto_start", dest="auto_start",
                        default=True, action="store_false",
                        help="Disable auto start.")
    parser.add_argument("--onion_ver", type=int, default=3, choices=[2, 3],
                        help="Onion address version (2 or 3).")
    parser.add_argument("--resource_type", type=str, default="jpg",
                        help="Resource type to inject in the attack.")
    parser.add_argument("--rate_per_sec", type=float, default=5.0,
                        help="Rate of new resources to inject per second.")

    parser.add_argument("--guard_fp", type=str, required=True,
                        help="Fingerprint of guard to use.")
    parser.add_argument("--guard_or_ip", type=str, required=True,
                        help="Onion router IPv4 of guard to use.")
    parser.add_argument("--guard_or_port", type=str, required=True,
                        help="Onion router port of guard to use.")
    parser.add_argument("--guard_dir_ip", type=str, required=True,
                        help="Directory IPv4 of guard to use.")
    parser.add_argument("--guard_dir_port", type=str, required=True,
                        help="Directory port of guard to use.")
    parser.add_argument("--no_js", default=False, action="store_true",
                        help="Launch scriptless attack.")
    args = parser.parse_args()

    attack_result = launch_attack(
        args.tbb, args.log_level, args.tor_log_level, args.log_to_console,
        args.experiments_dir, args.virtual_display, args.tag,
        args.num_parallel, args.attack_duration, args.guard_fp, args.adv_page,
        args.auto_start, args.onion_ver, args.resource_type, args.rate_per_sec,
        args.guard_or_ip, args.guard_or_port, args.guard_dir_ip,
        args.guard_dir_port, args.no_js)

    if attack_result != "success":
        print(attack_result)
        sysexit(1)
