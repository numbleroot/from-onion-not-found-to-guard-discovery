#!/usr/bin/env python3

"""
Compute upper bound on how long it takes an adversary to compute a list of
valid attack public keys in a specific configuration. An onion service public
key is useful for attack if its blinded version maps to at least one or two
adversarial HSDirs.
"""


from csv import writer
from struct import pack
from os import makedirs
from os.path import join, abspath
from random import sample
from json import load, dump
from hashlib import sha3_256
from time import perf_counter
from bisect import bisect_left
from collections import OrderedDict
from argparse import ArgumentParser
from multiprocessing import Process, Queue
from datetime import datetime, timedelta, timezone
from base64 import standard_b64decode, standard_b64encode
from stem.util import ed25519, _pubkey_bytes
from stem.descriptor import DocumentHandler, parse_file
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# EXPERIMENT CONFIGURATION VALUES

# Number of processes used to generate public keys.
NUM_WORKER_PROCS = 20

# Number of HSDirs the adversary operates in the network.
NUM_ADV_HSDIRS = [10, 15, 20, 25]

# Number of HSDir reselections for a particular NUM_ADV_HSDIRS.
NUM_REPETITIONS = 10


# TOR ONION SERVICE v3 CONSTANTS

# HSDir index prefix string.
HSDIR_IDX_PREFIX = "node-idx".encode()

# Onion service index prefix string.
OS_IDX_PREFIX = "store-at-idx".encode()

# Default length of time period in minutes.
PERIOD_LENGTH = 1440

# Default number of sequences of HSDirs on hashring responsible for
# maintaining an onion service's descriptor ('hsdir_n_replicas').
HSDIR_N_REPLICAS = 2

# Default number of HSDirs in each sequence responsible for maintaining
# an onion service's descriptor ('hsdir_spread_fetch').
HSDIR_SPREAD_FETCH = 3

# Blinding strings.
BLIND_STRING = "Derive temporary signing key".encode() + b'\x00'
BLIND_NONCE_STRING = "key-blind".encode()

# Bit masks used during blinding.
#   AND bitmask: 248, 30 * 255, 63.
#    OR bitmask: 31 * 0, 64.
BLIND_AND_BITMASK = int.from_bytes((b'\xf8' + (b'\xff' * 30) + b'?'), "big")
BLIND_OR_BITMASK = int.from_bytes(((b'\x00' * 31) + b'@'), "big")

# Ed25519 base point as string.
ED25519_BASE_POINT = "(15112221349535400772501151" \
    "40958853151145401269304185720604611328394984" \
    "7762202, 46316835694926478169428394003475163" \
    "141307993866256225615783033603165251855960)".encode()


def load_consensus_from_file(state_dir):
    """Loads consensus from file by parsing it correctly with stem."""

    consensus = next(parse_file(
        join(state_dir, "consensus"),
        descriptor_type="network-status-consensus-3 1.0",
        document_handler=DocumentHandler.DOCUMENT,
    ))

    # Decode current shared random value from its base64 form
    # in the consensus into binary form for later use.
    shared_rand_cur_val = standard_b64decode(
        consensus.shared_randomness_current_value)

    # Add 30 minutes to consensus.valid_after as "now time".
    now = consensus.valid_after + timedelta(minutes=30)

    # Subtract the v3 spec epoch offset (01/01/1970, 12:00:00 UTC).
    now_since_offset = now.replace(tzinfo=timezone.utc) - \
        datetime(1970, 1, 1, 12, 0, 0, 0, tzinfo=timezone.utc)

    # Convert timedelta to integer minute value.
    now_since_offset_minutes = now_since_offset // timedelta(seconds=60)

    # Integer-divide now_since_offset_minutes by PERIOD_LENGTH
    # to obtain the current period number.
    period_num = now_since_offset_minutes // PERIOD_LENGTH

    return shared_rand_cur_val, period_num


def load_hsdirs_from_file(state_dir):
    """Loads HSDirs from file, parsing base64-encoded identity public keys
    into their binary 32-bytes representation along the way."""

    hsdirs = OrderedDict()

    with open(join(state_dir, "hsdirs")) as hsdirs_fp:
        hsdirs_raw = load(hsdirs_fp, object_pairs_hook=OrderedDict)

    for hsdir_raw in hsdirs_raw:

        # Tor stores base64-encoded Ed25519 public keys without trailing
        # equal signs, which trips up Python's library. See as examples:
        # https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt#n446
        # https://github.com/torproject/stem/blob/master/stem/descriptor/certificate.py#L393
        id_pubkey = hsdirs_raw[hsdir_raw]["identity_pubkey"] + "="

        hsdirs[hsdir_raw] = standard_b64decode(id_pubkey)

    return hsdirs


def calc_hsdir_idx(node_identity, shared_rand_cur_val, period_num):
    """Obtain an HSDir's hashring index. Expects all parameters passed to
    already be in encoded form (i.e., Python's binary representation)."""

    # Perform packing of HSDir index input value to hash function:
    #   1. Network byte order (big-endian) => '!'
    #   2. 8 bytes for 'node-idx' => '8s'
    #   3. 32 bytes for node identity key => '32s'
    #   4. 32 bytes for shared random value => '32s'
    #   5. 8 bytes (unsigned long long) for period number => 'Q'
    #   6. 8 bytes (unsigned long long) for period length => 'Q'
    # Spec:
    #   https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n807
    # Source:
    #   https://github.com/torproject/tor/blob/e247aab4eceeb3920f1667bf5a11d5bc83b950cc/src/test/hs_indexes.py#L49
    hsdir_idx_input = pack("!8s32s32sQQ", HSDIR_IDX_PREFIX, node_identity,
                           shared_rand_cur_val, period_num, PERIOD_LENGTH)

    # Hashing packed bytes object yields HSDir index.
    hsdir_idx = sha3_256(hsdir_idx_input).hexdigest()

    return hsdir_idx


def calc_all_hsdir_idx(state_dir, hsdirs, shared_rand_cur_val, period_num):
    """Iterates over all HSDirs and calculates their indexes on the hashring.
    Returns sorted list of all HSDir indexes ready to be bisected to determine
    to which HSDirs a particular candidate public key maps to."""

    hsdir_idx = []

    for _, node_identity in hsdirs.items():

        # Calculate this particular HSDir's index.
        idx = calc_hsdir_idx(node_identity, shared_rand_cur_val, period_num)

        # Append index to list of all indexes.
        hsdir_idx.append(idx)

    # In-place sort list of HSDir indexes.
    hsdir_idx.sort()

    # Write sorted HSDir hashring nicely formatted to file.
    with open(join(state_dir, "hsdirs_idx_sorted"), "w") as hsdir_idx_fp:
        dump(hsdir_idx, hsdir_idx_fp, indent=4)
        hsdir_idx_fp.write("\n")

    return hsdir_idx


def pick_adv_hsdir_idx(num_hsdir_idx, num_adv_hsdirs):
    """Returns a set of size num_adv_hsdirs containing HSDir indexes sampled
    uniformly at random from range [0, num_hsdir_idx)."""

    return set(sample(range(num_hsdir_idx), k=num_adv_hsdirs))


def blind_pubkey(pubkey, period_num):
    """Blinds a public key according to Tor's v3 rendezvous specification:
    https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2236"""

    # Perform packing of blinding parameter for later public key blinding:
    #   1. Network byte order (big-endian) => '!'
    #   2. 29 bytes for 'Derive temporary signing key\0' => '29s'
    #   3. 32 bytes for public key => '32s'
    #   4. 158 bytes for Ed25519 base point as string => '158s'
    #   5. 9 bytes for 'key-blind' => '9s'
    #   6. 8 bytes (unsigned long long) for period number => 'Q'
    #   7. 8 bytes (unsigned long long) for period length => 'Q'
    # Spec:
    #   https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2287
    blinding_param_input = pack("!29s32s158s9sQQ", BLIND_STRING, pubkey,
                                ED25519_BASE_POINT, BLIND_NONCE_STRING,
                                period_num, PERIOD_LENGTH)

    # Hashing packed bytes object yields the blinding parameter.
    blinding_param = sha3_256(blinding_param_input).digest()

    # Clamp the appropriate bytes of the blinding parameter according
    # to the Tor v3 rendezvous specification:
    #   https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2294
    blinding_nonce = int.from_bytes(blinding_param, "big") & BLIND_AND_BITMASK
    blinding_nonce = ((blinding_nonce | BLIND_OR_BITMASK)).to_bytes(32, "big")

    # Perform key blinding with the prepared parameters, taken directly
    # from stem's `_blinded_pubkey()` function:
    #   https://github.com/torproject/stem/blob/faab143a3ebe6dddc9c7bed08bfd00eed14ae0f0/stem/descriptor/hidden_service.py#L1342
    mult = 2 ** (ed25519.b - 2) + sum(2 ** i * ed25519.bit(blinding_nonce, i)
                                      for i in range(3, ed25519.b - 2))
    P = ed25519.decodepoint(_pubkey_bytes(pubkey))
    blinded_pubkey = ed25519.encodepoint(ed25519.scalarmult(P, mult))

    return blinded_pubkey


def calc_os_idx(blinded_pubkey, period_num):
    """Obtain an onion service's (OS) hashring indexes from a blinded Ed25519
    public key. Expects all parameters passed to already be in encoded form
    (i.e., Python's binary representation)."""

    all_os_idx = []

    for i in range(HSDIR_N_REPLICAS):

        replica_num = i + 1

        # Perform packing of onion service index input value to hash function:
        #   1. Network byte order (big-endian) => '!'
        #   2. 12 bytes for 'store-at-idx' => '12s'
        #   3. 32 bytes for blinded public key => '32s'
        #   4. 8 bytes (unsigned long long) for replica number => 'Q'
        #   5. 8 bytes (unsigned long long) for period length => 'Q'
        #   6. 8 bytes (unsigned long long) for period number => 'Q'
        # Spec:
        #   https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n793
        # Source:
        #   https://github.com/torproject/tor/blob/e247aab4eceeb3920f1667bf5a11d5bc83b950cc/src/test/hs_indexes.py#L71
        os_idx_input = pack("!12s32sQQQ", OS_IDX_PREFIX, blinded_pubkey,
                            replica_num, PERIOD_LENGTH, period_num)

        # Hashing packed bytes object yields onion service index.
        os_idx = sha3_256(os_idx_input).hexdigest()

        # Append onion service index to list.
        all_os_idx.append(os_idx)

    return all_os_idx


def gen_atk_pubkey(cand_q, hsdir_idx, adv_hsdir_idx, period_num, give_total):
    """Generates Ed25519 public keys that map to at least one and at
    least two adversarial HSDirs on the hashring. Outputs them on the
    queue supplied as argument that is read by the controller process."""

    # If requested, track total number of generated public keys.
    if give_total:
        gen_pubkeys = 0

    while True:

        # Generate a fresh Ed25519 key pair.
        privkey = Ed25519PrivateKey.generate()
        pubkey = privkey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Blind public key (this is compute-intensive!).
        blinded_pubkey = blind_pubkey(pubkey, period_num)

        # Calculate set of hashring indexes for candidate public key.
        os_idx = calc_os_idx(blinded_pubkey, period_num)

        # Calculate the set of HSDIR_N_REPLICAS * HSDIR_SPREAD_FETCH
        # HSDirs indexes responsible for this public key.
        os_idx_responsible_hsdirs = set()

        for replica_num in range(HSDIR_N_REPLICAS):

            # Obtain first HSDir index this public key maps to for
            # this sequence. Wrap around when reaching the end.
            os_idx_seq = bisect_left(hsdir_idx, os_idx[replica_num])
            if os_idx_seq == len(hsdir_idx):
                os_idx_seq = 0

            # Include all HSDir indexes per sequence on the hashring.
            for hsdir_num in range(HSDIR_SPREAD_FETCH):
                os_idx_responsible_hsdirs.add((os_idx_seq + hsdir_num))

        # Compute the intersection with the set of adversarial HSDirs.
        matches = adv_hsdir_idx.intersection(os_idx_responsible_hsdirs)
        len_matches = len(matches)

        # Increment counter of total generated public keys.
        if give_total:
            gen_pubkeys += 1

        # If the intersection contains at least one HSDir, put the
        # [candidate, intersection, intersection_size] triple onto
        # queue for controller to further process. If the total of
        # generated public keys is requested, send this as last value.
        if len_matches >= 1:

            if give_total:
                vals = (pubkey, sorted(matches), len_matches, gen_pubkeys)
            else:
                vals = (pubkey, sorted(matches), len_matches)

            cand_q.put(vals)


def run_single_exp(out_dir, hsdir_idx, rep, num_adv_hsdirs,
                   period_num, report_gen_rate):
    """Runs a single experiment setting determined by the passed arguments."""

    # The two respective sets of usable attack public keys, based
    # on the size of the intersection with the adversarial HSDirs.
    atk_pubkey_atl_1 = OrderedDict()
    atk_pubkey_atl_2 = OrderedDict()

    # Track timings of various end events in order to ultimately
    # calculate the duration it took from start until said event.
    end_atl_1 = dict()
    end_atl_2 = dict()

    # Pick set of adversarial HSDir indexes for this repetition.
    adv_hsdir_idx = pick_adv_hsdir_idx(len(hsdir_idx), num_adv_hsdirs)
    assert len(adv_hsdir_idx) == num_adv_hsdirs

    # Sort the set of chosen adversarial HSDir indexes and write to file.
    adv_hsdir_idx_sorted = sorted(adv_hsdir_idx)
    adv_hsdir_idx_sorted_file = join(
        out_dir, "{}_{}-adv-hsdirs.txt".format(rep, num_adv_hsdirs))
    with open(adv_hsdir_idx_sorted_file, "w") as idx_fp:
        dump(adv_hsdir_idx_sorted, idx_fp, indent=4)
        idx_fp.write("\n")

    # Spawn queue used to communicate candidate public keys and their
    # intersection size from worker processes to controller process.
    cand_q = Queue()

    # Start time of computation relevant to adversary.
    start = perf_counter()

    # Prepare NUM_WORKER_PROCS workers with the same arguments.
    workers = []
    for _ in range(NUM_WORKER_PROCS):
        workers.append(
            Process(target=gen_atk_pubkey,
                    args=(cand_q, hsdir_idx, adv_hsdir_idx,
                          period_num, report_gen_rate,)))

    # Start all workers, running them in concurrently.
    for worker in workers:
        worker.start()

    while len(atk_pubkey_atl_2) < 900:

        # Retrieve candidate public key, its index intersection
        # with the chosen set of adversarial HSDirs, and the size
        # of that intersection from queue (worker process).
        if report_gen_rate:
            pubkey, matches, len_matches, total_gen = cand_q.get(block=True)
        else:
            pubkey, matches, len_matches = cand_q.get(block=True)

        # Skip over candidate public keys that we already saw.
        if ((pubkey in atk_pubkey_atl_1) or (pubkey in atk_pubkey_atl_2)):
            continue

        if len_matches >= 1:

            # Add candidate public key to set of attack public keys
            # that have at least one HSDir in common with adversary.
            atk_pubkey_atl_1[pubkey] = matches

            # Track intermediate result timings.
            len_atk_pubkey_atl_1 = len(atk_pubkey_atl_1)
            if len_atk_pubkey_atl_1 == 180:
                end_atl_1[180] = perf_counter()
            elif len_atk_pubkey_atl_1 == 360:
                end_atl_1[360] = perf_counter()
            elif len_atk_pubkey_atl_1 == 540:
                end_atl_1[540] = perf_counter()
            elif len_atk_pubkey_atl_1 == 720:
                end_atl_1[720] = perf_counter()
            elif len_atk_pubkey_atl_1 == 900:
                end_atl_1[900] = perf_counter()

        if len_matches >= 2:

            # Add candidate public key to set of attack public keys
            # that have at least two HSDirs in common with adversary.
            atk_pubkey_atl_2[pubkey] = matches

            # Track intermediate result timings.
            len_atk_pubkey_atl_2 = len(atk_pubkey_atl_2)
            if len_atk_pubkey_atl_2 == 180:
                end_atl_2[180] = perf_counter()
            elif len_atk_pubkey_atl_2 == 360:
                end_atl_2[360] = perf_counter()
            elif len_atk_pubkey_atl_2 == 540:
                end_atl_2[540] = perf_counter()
            elif len_atk_pubkey_atl_2 == 720:
                end_atl_2[720] = perf_counter()

    # Capture final result timing.
    end_atl_2[900] = perf_counter()

    # Stop all workers once we reached our goal.
    for worker in workers:
        worker.terminate()

    if report_gen_rate:

        # Calculate rate of generated public keys per second and write to file.
        with open(join(out_dir, "pubkeys_gen_rate.txt"), "a") as pk_fp:

            dur = end_atl_2[900] - start
            rate = float(total_gen) / dur

            pk_fp.write("{}: pub_keys={} / duration={} = {}\n".format(
                rep, total_gen, dur, rate))

    # Encode each public key in base64 and add to write-out structure.
    atk_pubkey_atl_1_enc = OrderedDict()
    for pubkey_raw, matches in atk_pubkey_atl_1.items():
        pubkey_enc = standard_b64encode(pubkey_raw).decode()
        atk_pubkey_atl_1_enc[pubkey_enc] = matches

    # Write at-least-1-match public keys to file.
    atk_pubkey_atl_1_file = \
        "{}_{}_atl-1_pubkeys.txt".format(rep, num_adv_hsdirs)
    with open(join(out_dir, atk_pubkey_atl_1_file), "w") as pk_fp:
        dump(atk_pubkey_atl_1_enc, pk_fp, indent=4)
        pk_fp.write("\n")

    # Encode each public key in base64 and add to write-out structure.
    atk_pubkey_atl_2_enc = OrderedDict()
    for pubkey_raw, matches in atk_pubkey_atl_2.items():
        pubkey_enc = standard_b64encode(pubkey_raw).decode()
        atk_pubkey_atl_2_enc[pubkey_enc] = matches

    # Write at-least-2-matches public keys to file.
    atk_pubkey_atl_2_file = \
        "{}_{}_atl-2_pubkeys.txt".format(rep, num_adv_hsdirs)
    with open(join(out_dir, atk_pubkey_atl_2_file), "w") as pk_fp:
        dump(atk_pubkey_atl_2_enc, pk_fp, indent=4)
        pk_fp.write("\n")

    # Write result timings to CSV file.
    with open(join(out_dir, "times_atk_pubkeys_gen.csv"), "a") as res_fp:
        writer(res_fp).writerows([
            [rep, num_adv_hsdirs, 1, 180, (end_atl_1[180] - start)],
            [rep, num_adv_hsdirs, 1, 360, (end_atl_1[360] - start)],
            [rep, num_adv_hsdirs, 1, 540, (end_atl_1[540] - start)],
            [rep, num_adv_hsdirs, 1, 720, (end_atl_1[720] - start)],
            [rep, num_adv_hsdirs, 1, 900, (end_atl_1[900] - start)],
            [rep, num_adv_hsdirs, 2, 180, (end_atl_2[180] - start)],
            [rep, num_adv_hsdirs, 2, 360, (end_atl_2[360] - start)],
            [rep, num_adv_hsdirs, 2, 540, (end_atl_2[540] - start)],
            [rep, num_adv_hsdirs, 2, 720, (end_atl_2[720] - start)],
            [rep, num_adv_hsdirs, 2, 900, (end_atl_2[900] - start)]])


def main(state_dir, out_dir_base, report_gen_rate):
    """Orchestrates all pieces necessary to obtain the timings it takes
    a certain adversary to compute a set of attack public keys that map to
    at least one or two adversarial HSDirs. Repeats this process multiple
    times and for different adversary settings. Writes the final result
    files into a dedicated folder in out_dir."""

    now = datetime.now()
    now_fmt = now.strftime("%Y-%m-%d_%H-%M-%S")

    # Concatenate all adversarial sizes into string.
    num_adv_hsdirs_string = "-".join([str(num) for num in NUM_ADV_HSDIRS])

    # Build final output directory name.
    out_dir = \
        join(out_dir_base, "{}_threads-{}_reps-{}_num-adv-hsdirs-{}".format(
            now_fmt, str(NUM_WORKER_PROCS),
            str(NUM_REPETITIONS), num_adv_hsdirs_string))

    # Create output directory to store this experiment's result files in.
    makedirs(out_dir, exist_ok=True)

    # Describe this experiment.
    exp = {
        "start_time": now.strftime("%Y/%m/%d %H:%M:%S"),
        "out_dir": out_dir,
        "state_dir": state_dir,
        "num_worker_procs": NUM_WORKER_PROCS,
        "num_repetitions": NUM_REPETITIONS,
        "num_adv_hsdirs": NUM_ADV_HSDIRS,
        "period_length": PERIOD_LENGTH,
        "hsdir_n_replicas": HSDIR_N_REPLICAS,
        "hsdir_spread_fetch": HSDIR_SPREAD_FETCH,
    }

    # Dump experiment configuration into output directory.
    with open(join(out_dir, "experiment.json"), "w") as exp_fp:
        dump(exp, exp_fp, indent=4)
        exp_fp.write("\n")

    # Write column names as first line to timings file.
    with open(join(out_dir, "times_atk_pubkeys_gen.csv"), "w") as res_fp:
        writer(res_fp).writerow(
            ["repetition", "num_adv_hsdirs", "hsdir_matches_at_least",
             "pubkeys_list_size", "time"])

    # Load consensus and HSDirs from file.
    shared_rand_cur_val, period_num = load_consensus_from_file(state_dir)
    hsdirs = load_hsdirs_from_file(state_dir)

    # Obtain sorted list of all HSDirs' indexes.
    hsdir_idx = \
        calc_all_hsdir_idx(state_dir, hsdirs, shared_rand_cur_val, period_num)

    for rep in range(1, (NUM_REPETITIONS + 1)):

        for num_adv_hsdirs in NUM_ADV_HSDIRS:

            # Run this particular experiment with multiple processes.
            run_single_exp(out_dir, hsdir_idx, rep, num_adv_hsdirs,
                           period_num, report_gen_rate)


if __name__ == "__main__":

    # Define and parse command-line arguments.
    parser = ArgumentParser()
    parser.add_argument("--state_dir", type=str, required=True,
                        help="Path to directory containing the 'consensus', "
                        "'descriptors', and 'hsdirs' files.")
    parser.add_argument("--out_dir", type=str, required=True,
                        help="Path to directory in which the result folder "
                        "is supposed to be created.")
    parser.add_argument("--report_gen_rate", dest="report_gen_rate",
                        action="store_true", default=False,
                        help="Pass flag to report rate of generated public "
                        "keys per second when each experiment ends.")
    args = parser.parse_args()

    # Run all parts of this experiment.
    main(abspath(args.state_dir), abspath(args.out_dir), args.report_gen_rate)
