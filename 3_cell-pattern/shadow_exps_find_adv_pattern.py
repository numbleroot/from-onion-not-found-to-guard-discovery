#!/usr/bin/env python3

"""
Parse cell counter logs collected during Shadow experiments
and check for occurrence of adversarial cell pattern.
"""

from os import makedirs
from os.path import join, basename, abspath
from collections import OrderedDict
from argparse import ArgumentParser


# Set to True if all events for each circuit should be collected
# and written out at the end. This consumes a lot of memory.
DEBUG = False


# Sequences of the two checked HS_DESC lookup patterns at
# second and third hop of a four-hop lookup circuit.

ADV_PAT_2ND_HOP = [
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='create",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='created",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> relay_cmd='EXTEND",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='create",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='created",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> Encrypted payload, passing on",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> Encrypted payload, passing on",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> Encrypted payload, passing on",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # Possibly, a DESTROY cell.
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='destroy'",
]

ADV_PAT_3RD_HOP = [
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='create",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='created",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> relay_cmd='EXTEND",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='create",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='created",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> Encrypted payload, passing on",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    # "|-> Encrypted payload, passing on",
    "DEST -1: circ_prps='Circuit at relay', cell_cmd='relay_early'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    "DEST +1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # "|-> Encrypted payload, passing on",
    "ORIGIN -1: circ_prps='Circuit at relay', cell_cmd='relay'",
    # Possibly, a DESTROY cell.
    "ORIGIN +1: circ_prps='Circuit at relay', cell_cmd='destroy'",
]


def extract_fields(line):
    """Returns the three relevant fields of each line."""

    line = line.strip()
    fields = line.split(maxsplit=3)

    mem_loc = fields[1]
    chan_circ = fields[2]
    event = fields[3]

    return mem_loc, chan_circ, event


def is_fuse_event(cands, mem_loc, event):
    """If this event carries an unknown channel-circuit identifier
    but actually links (fuses) together the origin-ward with the
    dest-ward circuit, return the existing key for modification."""

    # The first event of the last added chan_circ needs to have
    # come from ORIGIN in order for this event to be a fusing one.

    last_added_chan_circ, last_added_tracking = \
        list(cands[mem_loc].items())[-1]

    first_event = last_added_tracking["first_event"]

    if (("." not in last_added_chan_circ)
            and ("ORIGIN +1:" in first_event)
            and ("cell_cmd='create" in first_event)
            and ("DEST -1:" in event)
            and ("cell_cmd='create" in event)):
        return last_added_chan_circ

    return ""


def start_tracking(cands, mem_loc, chan_circ, event):
    """Checks whether the event matches the first line of the
    second- or third-hop pattern. Initializes circuit object
    at mem_loc=>chan_circ accordingly."""

    second_hop_next_exp_line = -1
    third_hop_next_exp_line = -1

    if event.startswith(ADV_PAT_2ND_HOP[0]):
        second_hop_next_exp_line = 1

    if event.startswith(ADV_PAT_3RD_HOP[0]):
        third_hop_next_exp_line = 1

    if mem_loc not in cands:
        cands[mem_loc] = OrderedDict()

    cands[mem_loc][chan_circ] = {
        "second_hop_next_exp_line": second_hop_next_exp_line,
        "third_hop_next_exp_line": third_hop_next_exp_line,
        "first_event": event,
    }

    # If DEBUG is set to True, collect all events of circuit.
    if DEBUG:
        cands[mem_loc][chan_circ]["events"] = [event]

    return cands


def update_tracking(cands, mem_loc, key, event):
    """Checks whether the event matches the next expected line of
    the second- or third-hop pattern. If so, increments the line
    next to expect; if not, sets expected line to -1 (fail)."""

    sec_next = cands[mem_loc][key]["second_hop_next_exp_line"]
    third_next = cands[mem_loc][key]["third_hop_next_exp_line"]

    if sec_next != -1:

        if sec_next < len(ADV_PAT_2ND_HOP):

            if event.startswith(ADV_PAT_2ND_HOP[sec_next]):
                cands[mem_loc][key]["second_hop_next_exp_line"] += 1
            else:
                cands[mem_loc][key]["second_hop_next_exp_line"] = -1

        else:
            cands[mem_loc][key]["second_hop_next_exp_line"] = -1

    if third_next != -1:

        if third_next < len(ADV_PAT_3RD_HOP):

            if event.startswith(ADV_PAT_3RD_HOP[third_next]):
                cands[mem_loc][key]["third_hop_next_exp_line"] += 1
            else:
                cands[mem_loc][key]["third_hop_next_exp_line"] = -1

        else:
            cands[mem_loc][key]["third_hop_next_exp_line"] = -1

    # If DEBUG is set to True, collect all events of circuit.
    if DEBUG:
        cands[mem_loc][key]["events"].append(event)

    return cands


def parse_cell_cnt_log(log_file):
    """Steps through supplied cell counters log file line-wise
    and counts how often the adversarial cell pattern occurs at
    which circuit position."""

    cands = OrderedDict()

    for line in open(log_file):

        # Do not consider lines that mark logging to disk events.
        if "LOGGED TO DISK" in line:
            continue

        # Extract the three relevant fields from line.
        mem_loc, chan_circ, event = extract_fields(line)

        # Do not consider meta event lines.
        if chan_circ == "???_??????????":
            continue

        if mem_loc in cands:

            key = ""

            for cur_key in cands[mem_loc].keys():

                if chan_circ in cur_key:
                    key = cur_key

            if key != "":

                # If the channel-circuit identifier is either part of
                # or exactly equal to an already tracked channel-circuit
                # identifier, this is the correct key to update.
                cands = update_tracking(cands, mem_loc, key, event)

            else:

                # Does this event represent the situation where a
                # one-sided circuit is extended to the other side?
                key = is_fuse_event(cands, mem_loc, event)
                if key != "":

                    # The new key carries both channel-circuit
                    # identifiers of the fused circuits.
                    new_key = key + "." + chan_circ

                    # Replace the old key with the new one for the
                    # respective entry, but keep all other ones.
                    cands[mem_loc] = \
                        OrderedDict((new_key if k == key else k, v)
                                    for k, v in cands[mem_loc].items())

                    # Update tracking state for this circuit.
                    cands = update_tracking(cands, mem_loc, new_key, event)

                else:

                    # Unseen channel-circuit identifier. Start tracking.
                    cands = start_tracking(cands, mem_loc, chan_circ, event)

        else:

            # Unseen memory location. Start tracking.
            cands = start_tracking(cands, mem_loc, chan_circ, event)

    return cands


def circ_is_2nd_hop_adv_pattern(circ):
    """This circuit matches the cell pattern an adversary
    controlling the second hop of the circuit looks for,
    if the circuit has completed all essential steps (20)
    or additionally also has been DESTROY'ed already (21).

    Circuits that share the first 20 or 21 cells with the
    adversarial pattern but then continue or diverge, will
    have a '-1' value in the checked field."""

    excl_destroy = (len(ADV_PAT_2ND_HOP) - 1)
    incl_destroy = len(ADV_PAT_2ND_HOP)

    if ((circ["second_hop_next_exp_line"] == excl_destroy)
            or (circ["second_hop_next_exp_line"] == incl_destroy)):
        return True

    return False


def circ_is_3rd_hop_adv_pattern(circ):
    """This circuit matches the cell pattern an adversary
    controlling the third hop of the circuit observes
    and uses to discard this circuit as a candidate to
    discover the victim's guard,
    if the circuit has completed all essential steps (16)
    or additionally also has been DESTROY'ed already (17).

    Circuits that share the first 16 or 17 cells with the
    adversarial pattern but then continue or diverge, will
    have a '-1' value in the checked field."""

    excl_destroy = (len(ADV_PAT_3RD_HOP) - 1)
    incl_destroy = len(ADV_PAT_3RD_HOP)

    if ((circ["third_hop_next_exp_line"] == excl_destroy)
            or (circ["third_hop_next_exp_line"] == incl_destroy)):
        return True

    return False


def writeout_results(out_dir, node_name, cands):
    """Write all analysis results to file."""

    num_circs = 0

    sec_hop_adv_circs = list()
    third_hop_adv_circs = list()

    mismatched_extends = set()

    # Create output folder if it does not exist.
    makedirs(out_dir, exist_ok=True)

    # Prepare path to output file for this analysis.
    out_file = join(out_dir, node_name)

    with open(out_file, "w") as out_fp:

        for mem_loc in cands:

            for chan_circ in cands[mem_loc]:

                num_circs += 1

                # Our final circuit identifier consists of the circuit's
                # memory location and the constructed final channel-circuit
                # identifiers (one, or two of them connected by '.').
                circ_id = "{}/{}".format(mem_loc, chan_circ)

                out_fp.write(
                    "{}:\t\tsecond_hop_next_exp_line:{}\t"
                    "third_hop_next_exp_line:{}\n".format(
                        circ_id,
                        cands[mem_loc][chan_circ]["second_hop_next_exp_line"],
                        cands[mem_loc][chan_circ]["third_hop_next_exp_line"]))

                # Does circuit have the second-hop adversarial cell pattern?
                if circ_is_2nd_hop_adv_pattern(cands[mem_loc][chan_circ]):
                    sec_hop_adv_circs.append(circ_id)

                # Does circuit have the third-hop adversarial cell pattern?
                if circ_is_3rd_hop_adv_pattern(cands[mem_loc][chan_circ]):
                    third_hop_adv_circs.append(circ_id)

                # If we see more than two subcircuits (ORIGIN-ward, DEST-ward)
                # matched to a (high-level) circuit, add circuit to set.
                if chan_circ.count(".") > 1:
                    mismatched_extends.add(circ_id)

                if DEBUG:

                    for event in cands[mem_loc][chan_circ]["events"]:
                        out_fp.write("\t{}\n".format(event))

                    out_fp.write("\n")

        out_fp.write("\n\n")

        # Write out the total number of identified circuits.
        out_fp.write("[NUM_CIRCS] Number of circuits: "
                     "{}\n\n".format(num_circs))

        # Write out how often we saw circuits that match
        # the adversarial second-hop cell pattern.
        if len(sec_hop_adv_circs) > 0:

            out_fp.write("[2ND_HOP_RESULT] {} adversarial second-hop "
                         "circuits:\n".format(len(sec_hop_adv_circs)))
            for circ in sec_hop_adv_circs:
                out_fp.write("\t{}\n".format(circ))
            out_fp.write("\n")

        else:
            out_fp.write("[2ND_HOP_RESULT] No adversarial "
                         "second-hop circuits found.\n")

        # Write out how often we saw circuits that match
        # the adversarial third-hop cell pattern.
        if len(third_hop_adv_circs) > 0:

            out_fp.write("[3RD_HOP_RESULT] {} adversarial third-hop "
                         "circuits:\n".format(len(third_hop_adv_circs)))
            for circ in third_hop_adv_circs:
                out_fp.write("\t{}\n".format(circ))
            out_fp.write("\n")

        else:
            out_fp.write("[3RD_HOP_RESULT] No adversarial "
                         "third-hop circuits found.\n\n")

        # No channel-circuit identifier may
        # contain more than two circuits.
        if len(mismatched_extends) > 0:

            out_fp.write("[ERROR] {} circuits with more than two matched "
                         "subcircuits:\n".format(len(mismatched_extends)))
            for circ in mismatched_extends:
                out_fp.write("\t{}\n".format(circ))
            out_fp.write("\n")

        else:
            out_fp.write("[SANITY_CHECK] No circuits with more than two "
                         "matched subcircuits found (as expected).\n")


def main():
    """Parses cell counter log and extracts number of occurrences
    of adversarial cell pattern."""

    # Define and parse command-line arguments.
    parser = ArgumentParser()
    parser.add_argument("--cell_cnt_log", type=str, required=True,
                        help="Path to cell counters log to process.")
    parser.add_argument("--out_dir", type=str, required=True,
                        default=abspath("./cell_counters_analyzed"),
                        help="Path to directory that will hold the "
                        "created analysis file.")
    args = parser.parse_args()

    # Step through cell counters log file line-wise
    # and track occurrence of adversarial pattern.
    cands = parse_cell_cnt_log(args.cell_cnt_log)

    # Write analysis results to file.
    node_name = basename(args.cell_cnt_log).replace("_cell_counters.log", "")
    writeout_results(args.out_dir, node_name, cands)


if __name__ == "__main__":
    main()
