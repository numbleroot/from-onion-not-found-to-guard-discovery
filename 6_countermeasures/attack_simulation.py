import sys
import json
import numpy as np
from statistics import mean
from collections import defaultdict, deque
from numpy.random import choice as np_choice
from random import randint, random, choice, randrange


DEBUG = False

# Time we spent on the attack website.
HSDESC_LOOKUP_EXP_DURATION = 60
HSDESC_LOOKUP_EXP_DURATION_HALF = HSDESC_LOOKUP_EXP_DURATION / 2

# Based on MAX_HSDESC_RATE crawls, including all rates.
# 9703211 lookups, avg=0.686, 0.493.
MEDIAN_HSDESC_LOOKUP_DURATION = 0.493

N_HSDIRS_PER_ONION = 6

# Sep 2020 consensus from CollecTor:
# https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2020-09.tar.xz
# grep -cE "^s.*HSDir.*$" 22/2020-09-22-16-00-00-consensus
N_HSDIRS = 3905

VICTIM_CCT = "VICTIM"
NOISE_CCT = "NOISE"

NOISE_LOOKUPS_PER_S = 1052.27
TIME_BETWEEN_NOISE_LOOKUPS = 1 / NOISE_LOOKUPS_PER_S

R3 = "R3"
R5 = "R5"  # malicious
MALICIOUS_SECOND = R5

G1 = "G1"  # victim's guard
G2 = "G2"

VICTIM_CCT_GUARD = G1
NOISE_CCT_GUARD = G2

SECOND_HOP_RELAYS = [R3, R5]
RELAY_CSV = "2020-09-22-18-36-48_relays.csv"

# Based on rate=3 MAX_HSDESC_RATE crawl data.
HSDESC_LOOKUPS_JSON_FILE = "hsdesc_lookup_details.json"

# Optimization to exclude irrelevant circuits.
IGNORE_UNOBSERVABLE_NOISE_CCTS = True

# Cache some extra relays just in case.
N_RELAY_CACHE_BUFFER = 100

NO_CALL = -1
TRUE_GUARD_FOUND = 1
FALSE_GUARD_FOUND = 0

# Require two matches of the same guard to make a call.
DECISION_THRESHOLD = 2

SIMULATION_DURATION_DEFENSE_EVAL = 300
SIMULATION_DURATION_NO_DEFENSE = 300

NUM_VANGUARDSLITE_L2_GUARDS = 4


class OnionAttackSimulation:

    def __init__(self, simulation_info, lookup_times_dict,
                 decision_threshold=DECISION_THRESHOLD):

        self.decision_threshold = decision_threshold
        self.adv_bw_share = simulation_info['adv_bw_share']
        self.second_hop_weights = [1 - self.adv_bw_share, self.adv_bw_share]
        self.vanguardslite_enabled = simulation_info["vanguardslite_enabled"]

        self.victim_circuits = defaultdict(list)
        self.noise_circuits = defaultdict(list)

        self.matches = set()
        self.match_counts = defaultdict(int)

        # attack duration is set to simulation duration by default
        self.attack_duration = simulation_info['simulation_duration']
        self.outcome = NO_CALL
        self.sim_completed = False

        self.lookup_timestamps = lookup_times_dict['lookup_times']
        self.attack_start_time = lookup_times_dict["attack_start_time"]
        self.victim_guard_fp = lookup_times_dict["guard_fp"]

        self.duration = simulation_info['simulation_duration']
        self.n_adv_hsdirs = simulation_info['n_adv_hsdirs']
        self.adb_hsdir_prob = self.n_adv_hsdirs / N_HSDIRS_PER_ONION

        self.pre_sample_hops()

        # token bucket defense
        # token counter
        self.circuit_tokens = simulation_info['n_initial_tokens']
        self.token_refill_rate = simulation_info['token_refill_rate']
        if self.token_refill_rate:
            self.time_between_rate_limited_lookups = 1 / token_refill_rate

        self.rate_limited = False
        self.token_bucket_enabled = (self.circuit_tokens > 0)

    def pre_sample_hops(self):
        """Pre-sample (for speed) hops to be used in circuit building."""

        n_estimated_noise_lookups = int(NOISE_LOOKUPS_PER_S * self.duration)
        n_estimated_noise_lookups += N_RELAY_CACHE_BUFFER
        n_victim_lookups = len(self.lookup_timestamps)
        n_total_lookups = n_estimated_noise_lookups + n_victim_lookups

        # read the relay list
        __, guard_probs_dict, middle_probs_dict, _ = read_relay_list(RELAY_CSV)

        self.middle_relay_fps = []
        self.middle_relay_probs = []

        for fp, prob in middle_probs_dict.items():
            self.middle_relay_fps.append(fp)
            self.middle_relay_probs.append(prob)

        # Pick this run's set of adversarial middle relays.
        self.pick_adv_relays()

        # cache the weighted random sample of guard and third hops
        # calling random.choice one by one is slow
        # https://github.com/numpy/numpy/issues/11476
        self.pick_guard_nodes(n_estimated_noise_lookups, guard_probs_dict)

        if self.vanguardslite_enabled:
            self.pick_second_hops_vanguardslite_noise(
                n_estimated_noise_lookups)
            self.pick_second_hops_vanguardslite_victim()
        else:
            self.pick_second_hops_regular(n_total_lookups)

        self.pick_third_hops(n_total_lookups)

    def pick_adv_relays(self):
        """Picks middle relays as part of the adversarially controlled set
        of middle relays until they cumulatively provide adv_bw_share."""

        self.adv_relays_fps = set()
        self.adv_middle_prob_cum = 0.0

        while self.adv_middle_prob_cum < self.adv_bw_share:

            # Pick a random middle.
            middle_relay_idx = randrange(len(self.middle_relay_fps))
            middle_relay_fp = self.middle_relay_fps[middle_relay_idx]
            middle_relay_prob = self.middle_relay_probs[middle_relay_idx]

            # Don't consider relays that are not eligible
            # in the middle (rather: non-exit) position.
            if middle_relay_prob <= 0.0:
                continue

            # Skip relays we already picked.
            if middle_relay_fp in self.adv_relays_fps:
                continue

            # Add middle to adversarial relays set.
            self.adv_relays_fps.add(middle_relay_fp)

            # Increase adversarial cumulative probability.
            self.adv_middle_prob_cum += middle_relay_prob

        if DEBUG:

            for relay in self.adv_relays_fps:
                print(relay)

            print()
            print("len(relays):", len(self.middle_relay_fps))
            print("len(self.adv_relays_fps):", len(self.adv_relays_fps))
            print("self.adv_middle_prob_cum:", self.adv_middle_prob_cum)
            print()

    def pick_guard_nodes(self, n, guard_probs_dict):
        guard_fps = list(guard_probs_dict.keys())
        guard_probs = list(guard_probs_dict.values())
        self.guard_nodes = deque(np_choice(
            guard_fps,
            size=n,
            p=guard_probs))

    def pick_a_guard(self):
        return self.guard_nodes.pop()

    def pick_second_hops_vanguardslite_noise(self, n):
        """Pre-samples an appropriately large number of second-hop relays
        according to the relays' middle probabilities."""

        # Pick a large enough number of relays (adversarial and honest).
        self.second_hops_noise = deque(np_choice(
            self.middle_relay_fps,
            size=n,
            p=self.middle_relay_probs))

    def pick_a_second_hop_vanguardslite_noise(self, chosen_guard):
        """Pops the first element from prepared list of second-hop relays
        for noise circuits when Vanguards-lite is enabled and returns it."""

        second_hop = self.second_hops_noise.pop()

        # As long as the currently selected second hop is the first relay
        # already chosen for the circuit, reappend the pop'ed value at the
        # other end of the queue and pop again.
        # Note: This may slightly skew relay selection probabilities.
        while second_hop == chosen_guard:

            if DEBUG:
                print("Repicking second hop noise, because",
                      chosen_guard, second_hop)

            self.second_hops_noise.appendleft(second_hop)
            second_hop = self.second_hops_noise.pop()

        return second_hop

    def pick_second_hops_vanguardslite_victim(self):
        """In Vanguards-lite, four L2 guards are selected from the list of
        all running relays weighted by bandwidth:
          https://gitlab.torproject.org/tpo/core/tor/-/blob/1015b347d8d532d9caf96d21c0e5c9a8cd3034de/src/feature/client/entrynodes.c#L4055"""

        second_hops = set()

        # Calculate the intersection of the current selection of
        # second-hop relays with the list of adversarial relays.
        second_hops_adv = second_hops.intersection(self.adv_relays_fps)

        # The selected second-hop relays need to feature at least
        # one adversarial relay. Repick until condition met.
        while len(second_hops_adv) < 1:

            second_hops = set(np_choice(
                self.middle_relay_fps,
                size=NUM_VANGUARDSLITE_L2_GUARDS,
                replace=False,
                p=self.middle_relay_probs))

            second_hops_adv = second_hops.intersection(self.adv_relays_fps)

        self.second_hops_victim = list(second_hops)

        if DEBUG:
            print(self.second_hops_victim)
            print()

    def pick_a_second_hop_vanguardslite_victim(self):
        """In Vanguards-lite, second-hop relays on onion service circuits
        are picked uniformly at random for small L2 guard sets:
          https://gitlab.torproject.org/tpo/core/tor/-/blob/1015b347d8d532d9caf96d21c0e5c9a8cd3034de/src/core/or/circuitbuild.c#L1832
        Return one of the four L2 guards, chosen uniformly at random."""

        second_hop = choice(self.second_hops_victim)

        # As in Tor's circuit relay selection process, exclude
        # the guard from being eligible in the second hop.
        while second_hop == self.victim_guard_fp:

            if DEBUG:
                print("Repicking second hop victim, because",
                      self.victim_guard_fp, second_hop)

            second_hop = choice(self.second_hops_victim)

        return second_hop

    def pick_second_hops_regular(self, n):
        self.second_hops = deque(np_choice(
            SECOND_HOP_RELAYS,
            size=n,
            p=self.second_hop_weights))

    def pick_a_second_hop_regular(self):
        return self.second_hops.pop()

    def pick_third_hops(self, n):

        self.third_hops = deque(np_choice(
            self.middle_relay_fps,
            size=n,
            p=self.middle_relay_probs))

    def pick_a_third_hop(self, chosen_guard, chosen_second):

        third_hop = self.third_hops.pop()

        # As long as the currently selected third hop is either
        # the first or second relay already chosen for the circuit,
        # reappend the pop'ed value at the other end of the queue
        # and pop again.
        # Note: This may slightly skew relay selection probabilities.
        while third_hop in (chosen_guard, chosen_second):

            if DEBUG:
                print("Repicking third hop, because",
                      chosen_guard, chosen_second, third_hop)

            self.third_hops.appendleft(third_hop)
            third_hop = self.third_hops.pop()

        return third_hop

    def is_hsdir_malicious(self, hsdir_index):
        return hsdir_index <= self.n_adv_hsdirs

    def pick_a_victim_cct_hsdir(self):
        if random() < self.adb_hsdir_prob:
            # pick a malicious HSdir
            hsdir_index = randint(1, self.n_adv_hsdirs)
            assert self.is_hsdir_malicious(hsdir_index)
        else:
            # pick a benign HSdir
            hsdir_index = randint(self.n_adv_hsdirs + 1, N_HSDIRS)
            assert not self.is_hsdir_malicious(hsdir_index)
        return hsdir_index

    def pick_a_noise_cct_hsdir(self):
        return randint(1, N_HSDIRS)

    def pick_an_hsdir(self, cct_type):
        if cct_type == NOISE_CCT:
            return self.pick_a_noise_cct_hsdir()
        elif cct_type == VICTIM_CCT:
            return self.pick_a_victim_cct_hsdir()

    def generate_rate_limited_victim_circuits(self, t_now, lookup_index):
        # sample lookup durations from experiment lookup timestamps
        # exclude the ones we've used before hitting the rate limit
        unused_lookup_durations = [
            end - start for (start, end) in self.lookup_timestamps[
                lookup_index:]
        ]

        while t_now < self.duration:

            if self.sim_completed:
                return

            t_end = t_now + choice(unused_lookup_durations)
            self.generate_victim_circuit(t_now, t_end)
            t_now += self.time_between_rate_limited_lookups

    def generate_victim_circuits(self):
        """Generate victim lookups and associated circuits.

        Use timestamps extracted from earlier experiments for realistic
        simulation.

        If token bucket defense is enabled, we send lookups
        based on refill_rate until the end of the simulation.
        """
        assert len(self.noise_circuits) > 0

        for lookup_idx, (t_start, t_end) in enumerate(self.lookup_timestamps):

            if self.sim_completed:
                return

            # Make start and end timestamp relative to attack start time.
            t_start -= self.attack_start_time
            t_end -= self.attack_start_time

            # Generate a victim lookup circuit and decrement token counter.
            self.generate_victim_circuit(t_start, t_end)
            self.circuit_tokens -= 1

            if DEBUG:
                print("Remaining circuit tokens:", self.circuit_tokens)

            # If Token Bucket defense is active and the tokens are
            # exhausted, go into rate-limited lookup creation mode
            # for the rest of the simulation.
            if self.token_bucket_enabled and (self.circuit_tokens <= 0):
                print("Rate limiting enabled at %0.3fs" % t_start)
                self.rate_limited = True

                # If eventually new tokens will be made available for
                # circuit creation, continue simulation. Otherwise, the
                # Token Bucket was actually an upper bound on the total
                # number of allowed circuits to be created, and we are done.
                if self.token_refill_rate > 0.0:

                    # set the time of the first rate-limited lookup
                    t_now = t_start + self.time_between_rate_limited_lookups

                    # lookup_idx is used to determine the unused lookups
                    self.generate_rate_limited_victim_circuits(
                        t_now, lookup_idx + 1)

                # do not continue the loop
                return

    def generate_victim_circuit(self, t_now, t_end):

        if self.vanguardslite_enabled:
            second_hop = self.pick_a_second_hop_vanguardslite_victim()
        else:
            second_hop = self.pick_a_second_hop_regular()

        third_hop = self.pick_a_third_hop(self.victim_guard_fp, second_hop)
        hsdir_index = self.pick_an_hsdir(VICTIM_CCT)
        is_hsdir_malicious = self.is_hsdir_malicious(hsdir_index)

        t_access = (t_now + t_end) / 2

        cct = [VICTIM_CCT, self.victim_guard_fp, second_hop,
               third_hop, hsdir_index, is_hsdir_malicious,
               t_now, t_end, t_access]

        if DEBUG:
            print(cct)

        self.victim_circuits[(second_hop, third_hop)].append(cct)

        # the victim lookup is handled by the adversary's HSDir.
        # check match by comparing adv. middle's matches.
        if is_hsdir_malicious:
            self.check_for_match(t_access, third_hop)

    def get_circuits_by_seconds_and_third_hop(self, second_hops, third_hop):
        """Sort and return circuits that use any of the second and the one
        third hop."""

        circuits = []
        cct_keys = []

        for second_hop in second_hops:
            cct_keys.append((second_hop, third_hop))

        for cct_key in cct_keys:
            circuits.extend(self.victim_circuits[cct_key])
            circuits.extend(self.noise_circuits[cct_key])

        if DEBUG:
            print("Selecting circuits by the following (sec, third) keys:")
            print(cct_keys)
            print()
            print("Found these matching circuits:")
            print(circuits)
            print()

        return sorted(circuits, key=lambda x: x[-1])  # sort by access time

    def check_for_match(self, hsdir_t_access, hsdir_third_hop):
        """Compare HSDir's access log with adv. middle's matches."""

        if self.vanguardslite_enabled:
            malicious_second_hops = self.adv_relays_fps
        else:
            malicious_second_hops = [MALICIOUS_SECOND]

        # get circuits that use an adversarial middle and the third hop
        adv_middle_circuits = self.get_circuits_by_seconds_and_third_hop(
            malicious_second_hops, hsdir_third_hop)

        for circuit in adv_middle_circuits:

            cct_type, guard_node, second_hop, third_node_index, \
                __, __, t_start, t_end, __ = circuit

            # only consider lookups sent over our adv. middle
            if self.vanguardslite_enabled:
                assert second_hop in self.adv_relays_fps
            else:
                assert second_hop == R5
            assert third_node_index == hsdir_third_hop

            # compare lookup and circuit times.
            # don't check lookups that happenned after the HSDir access.
            if t_start >= hsdir_t_access:
                return

            # make sure the access time is between lookup start and end
            if t_end <= hsdir_t_access:
                continue

            # we have a match
            correct_match = self.victim_guard_fp == guard_node
            if DEBUG:
                print(
                    "Single match", correct_match, guard_node, hsdir_t_access)

            self.matches.add((guard_node, hsdir_t_access))
            self.match_counts[guard_node] += 1

            if DEBUG and correct_match and cct_type == NOISE_CCT:
                print("Lucky match: noise lookup used the victim's guard.")

            if self.match_counts[guard_node] < self.decision_threshold:
                continue

            # double-match is found
            self.sim_completed = True  # to quit the simulation
            self.attack_duration = hsdir_t_access

            if correct_match:
                self.outcome = TRUE_GUARD_FOUND
            else:
                self.outcome = FALSE_GUARD_FOUND

            if DEBUG:
                print("//// FINAL-MATCH ////", correct_match,
                      guard_node, hsdir_t_access)
            return

    def generate_noise_circuit(self, t_now):
        noise_guard = self.pick_a_guard()

        if self.vanguardslite_enabled:
            second_hop = \
                self.pick_a_second_hop_vanguardslite_noise(noise_guard)

            if (IGNORE_UNOBSERVABLE_NOISE_CCTS
                    and (second_hop not in self.adv_relays_fps)):
                return

        else:
            second_hop = self.pick_a_second_hop_regular()

            if (IGNORE_UNOBSERVABLE_NOISE_CCTS
                    and (second_hop != MALICIOUS_SECOND)):
                return

        third_hop = self.pick_a_third_hop(noise_guard, second_hop)
        hsdir_index = self.pick_an_hsdir(NOISE_CCT)
        is_hsdir_malicious = self.is_hsdir_malicious(hsdir_index)

        t_end = t_now + MEDIAN_HSDESC_LOOKUP_DURATION
        t_access = (t_now + t_end) / 2

        cct = [NOISE_CCT, noise_guard, second_hop,
               third_hop, hsdir_index, is_hsdir_malicious,
               t_now, t_end, t_access]

        DEBUG_NOISE_CCTS = False
        if DEBUG and DEBUG_NOISE_CCTS:
            print(cct)

        self.noise_circuits[(second_hop, third_hop)].append(cct)

    def generate_noise_circuits(self):
        t_now = 0
        while (t_now < self.duration):
            self.generate_noise_circuit(t_now)
            t_now += TIME_BETWEEN_NOISE_LOOKUPS

    def run_simulation(self):
        self.generate_noise_circuits()  # this must happen first
        self.generate_victim_circuits()
        self.compute_fp_rate()
        return self.outcome, self.attack_duration, self.fp_pct

    def compute_fp_rate(self):
        """Compute the single decision FP rate."""
        fp_cnt = 0

        if not self.matches:
            self.fp_pct = 0
            return

        for matched_guard, __ in self.matches:
            if matched_guard != self.victim_guard_fp:
                fp_cnt += 1

        self.fp_pct = 100 * fp_cnt / len(self.matches)


def load_hsdesc_lookup_times(lookups_json):
    """Load HSDesc lookups times we extracted from MAX_HS_DESC experiments."""
    return json.loads(open(lookups_json).read())


def read_relay_list(relay_csv):
    """Read in the relay list and weights."""
    relays = {}
    guard_probs = {}
    middle_probs = {}
    exit_probs = {}
    skipped_first = False
    for line in open(relay_csv):
        if not skipped_first:
            skipped_first = True
            continue

        columns = line.rstrip().split(",")

        nickname, fingerprint, is_guard_str, is_exit_str, \
            advertised_bandwidth_str, guard_prob_str, \
            middle_prob_str, exit_prob_str = \
            columns[0], columns[1], columns[2], columns[3], \
            columns[10], columns[11], columns[12], columns[13]

        is_guard = is_guard_str == "True"
        is_exit = is_exit_str == "True"

        advertised_bandwidth = int(advertised_bandwidth_str)
        guard_prob = float(guard_prob_str)
        middle_prob = float(middle_prob_str)
        exit_prob = float(exit_prob_str)

        relays[fingerprint] = {
            "nickname": nickname,
            "is_guard": is_guard,
            "is_exit": is_exit,
            "advertised_bandwidth": advertised_bandwidth,
            "guard_prob": guard_prob,
            "middle_prob": middle_prob,
            "exit_prob": exit_prob
        }

        if is_guard:
            guard_probs[fingerprint] = guard_prob

        middle_probs[fingerprint] = middle_prob

        if is_exit:
            exit_probs[fingerprint] = exit_prob

        if guard_prob > 0.0:
            assert middle_prob > 0.0
            assert exit_prob == 0.0

        if middle_prob > 0.0:
            assert exit_prob == 0.0

        if exit_prob > 0.0:
            assert guard_prob == 0.0
            assert middle_prob == 0.0

    return relays, guard_probs, middle_probs, exit_probs


def dump_results(simulation_info, n_total_sim_runs,
                 fp_rates, outcome_cnts):
    # dump the json resuls for analysis notebooks
    dump_multi_run_results(simulation_info)

    # n_true_call, n_no_call, n_false_call
    # just a shorthand
    attack_durations = simulation_info["attack_durations"]

    # *_call_rate variables below are based on double match,
    # i.e. they pertain to the final output of the adversary.
    false_call_rate = (
        100 *
        outcome_cnts[FALSE_GUARD_FOUND] /
        n_total_sim_runs)
    no_call_rate = (100 * outcome_cnts[NO_CALL] / n_total_sim_runs)
    true_call_rate = (100 * outcome_cnts[TRUE_GUARD_FOUND] / n_total_sim_runs)

    # OTOH, fp_rate_avg is based on single matches
    fp_rate_avg = mean(fp_rates)

    # 2 -> 1/3, 6 -> 1
    adb_hsdir_prob = simulation_info["n_adv_hsdirs"] / N_HSDIRS_PER_ONION

    if DEBUG:
        print("List of attack durations:", attack_durations)

    # attack duration percentiles
    if len(attack_durations):
        p50 = np.percentile(attack_durations, 50)
        p90 = np.percentile(attack_durations, 90)
        p99 = np.percentile(attack_durations, 99)
    else:
        p50 = p90 = p99 = 0

    print(
        "Runs: %d: (h: %0.2f, bw: %0.2f, tb_iv: %d, tb_rr:  %0.2f) "
        "Median: %0.3f, P90: %0.3f, P99: %0.3f (FP-single: %0.2f%%)"
        " FINAL-CALLS - T: %0.2f%% F: %0.2f%% Nocall: %0.2f%%" % (
            n_total_sim_runs, adb_hsdir_prob,
            simulation_info["adv_bw_share"],
            simulation_info["n_initial_tokens"],
            simulation_info["token_refill_rate"],
            p50, p90, p99, fp_rate_avg,
            true_call_rate, false_call_rate, no_call_rate
        ))


def run_single_simulation(simulation_info, lookup_times_dict):
    """Run a single simulation with given parameters."""
    # initialize a simulation instance
    sim = OnionAttackSimulation(simulation_info, lookup_times_dict)
    return sim.run_simulation()


def run_multiple_simulations(
        n_adv_hsdirs, adv_bw_share, n_experiments, n_runs,
        n_initial_tokens=0, token_refill_rate=0, vanguardslite_enabled=False):

    fp_rates = []  # single FP rates
    n_total_sim_runs = 0  # total number of simulations we run
    outcome_cnts = defaultdict(int)

    simulation_info = dict()
    simulation_info["n_experiments"] = n_experiments
    simulation_info["n_runs"] = n_runs
    simulation_info["n_adv_hsdirs"] = n_adv_hsdirs
    simulation_info["adv_bw_share"] = adv_bw_share
    simulation_info["n_initial_tokens"] = n_initial_tokens
    simulation_info["token_refill_rate"] = token_refill_rate
    simulation_info["vanguardslite_enabled"] = vanguardslite_enabled
    simulation_info["attack_durations"] = []

    lookup_times_dicts = sample_experiments(n_experiments)

    # set the simulation duration based on what we are evaluating
    if not n_initial_tokens:  # no defense, 60s
        simulation_duration = SIMULATION_DURATION_NO_DEFENSE
    else:  # run a longer simulation to evaluate the defense
        simulation_duration = SIMULATION_DURATION_DEFENSE_EVAL

    simulation_info["simulation_duration"] = simulation_duration

    print("Simulation params", simulation_info)

    for lookup_times_dict in lookup_times_dicts:  # for each experiment

        if not lookup_times_dict['lookup_times']:
            continue

        if simulation_duration > HSDESC_LOOKUP_EXP_DURATION:
            generate_lookups_to_cover_sim_duration(
                lookup_times_dict, simulation_duration)

        for __ in range(n_runs):  # loop n_runs times
            n_total_sim_runs += 1
            ###################################################################
            outcome, attack_duration, fp_rate = run_single_simulation(
                simulation_info, lookup_times_dict)
            ###################################################################
            fp_rates.append(fp_rate)  # based on single matches
            # we append max simulation duration for "no call" simulations
            simulation_info["attack_durations"].append(attack_duration)
            outcome_cnts[outcome] += 1

    dump_results(simulation_info, n_total_sim_runs,
                 fp_rates, outcome_cnts)


def generate_lookups_to_cover_sim_duration(
        lookup_times_dict, simulation_duration):
    """Given 60s of lookups, expand them to match the simulation duration."""

    attack_start_time = lookup_times_dict['attack_start_time']
    lookup_times = lookup_times_dict['lookup_times']

    # get the lookup times in the last 30s
    # subtract attack start time and 30s to get the lookups
    # from the last 30s
    lookup_times_last_30s = list(filter(
        lambda x:
        (x[0] - attack_start_time - HSDESC_LOOKUP_EXP_DURATION_HALF) > 0,
        lookup_times)
    )
    n_lookups_last_30s = len(lookup_times_last_30s)
    # rate of lookups in the last 30s
    avg_lookups_last_30s = n_lookups_last_30s / HSDESC_LOOKUP_EXP_DURATION_HALF
    avg_lookup_duration_last_30s = mean(
        [(end - start) for (start, end) in lookup_times_last_30s]
    )
    avg_lookup_duration_60s = mean(
        [(end - start) for (start, end) in lookup_times]
    )

    avg_lookups_60s = \
        len(lookup_times) / HSDESC_LOOKUP_EXP_DURATION
    if DEBUG:
        # avg_lookups_last_30s is -0.73s	lower than the whole
        # avg_lookup_duration_last_30s is 0.15s longer than the whole

        print("avg_lookups_per_sec (30)", avg_lookups_last_30s,
              "avg_lookups_per_sec (60)", avg_lookups_60s,
              "avg_lookup_duration (30)", avg_lookup_duration_last_30s,
              "avg_lookup_duration (60)", avg_lookup_duration_60s,
              )
        print("half - full avg diff",
              (avg_lookups_last_30s - avg_lookups_60s),
              (avg_lookup_duration_last_30s - avg_lookup_duration_60s))

    last_lookup_time = attack_start_time + HSDESC_LOOKUP_EXP_DURATION
    # interval is the inverse of rate
    interval_between_lookups = 1 / avg_lookups_last_30s
    if DEBUG:
        time_to_fill = simulation_duration - HSDESC_LOOKUP_EXP_DURATION
        print("Will add lookups for %ss" % time_to_fill)
        print("interval_between_lookups", interval_between_lookups)
        n_lookups_before = len(lookup_times_dict['lookup_times'])

    # append the generated lookups
    generated_lookups = []
    while (last_lookup_time - attack_start_time) < simulation_duration:
        generated_lookups.append(
            (last_lookup_time, last_lookup_time + avg_lookup_duration_last_30s))
        last_lookup_time += interval_between_lookups

    lookup_times_dict['lookup_times'] += generated_lookups

    if DEBUG:
        print("n_lookups_before, n_lookups_after expansion", n_lookups_before,
              len(lookup_times_dict['lookup_times']))


def sample_experiments(n_experiments):
    """Sample the experiments, return their lookup times."""
    hsdesc_lookup_times = load_hsdesc_lookup_times(HSDESC_LOOKUPS_JSON_FILE)

    # for the paper, we include all available experiments
    if n_experiments == -1:  # no sampling
        return hsdesc_lookup_times
    else:  # sample a subset for debugging and development
        return np_choice(hsdesc_lookup_times, size=n_experiments)


def dump_multi_run_results(simulation_info):
    out_filename = "time_to_double_comp_%s_%s_%d_%0.3f.json" % (
        simulation_info["n_adv_hsdirs"],
        simulation_info["adv_bw_share"],
        simulation_info["n_initial_tokens"],
        simulation_info["token_refill_rate"]
    )
    print("Results will be written to", out_filename)
    with open(out_filename, 'w') as f:
        json.dump(simulation_info, f)
        f.write("\n")


if __name__ == "__main__":
    n_initial_tokens = 0
    token_refill_rate = 0
    vanguardslite_enabled = False

    # n_adv_hsdirs = 1/h
    # adv_bw_share = b
    n_adv_hsdirs, adv_bw_share = int(sys.argv[1]), float(sys.argv[2])
    assert n_adv_hsdirs <= N_HSDIRS_PER_ONION
    assert adv_bw_share <= 1

    # n_experiments: number of samples (-1 for all experiments)
    # n_runs: number of times to run each simulation
    n_experiments, n_runs = int(sys.argv[3]), int(sys.argv[4])

    # Token Bucket defense.
    if len(sys.argv) == 7:
        n_initial_tokens, token_refill_rate = \
            int(sys.argv[5]), float(sys.argv[6])

    # Vanguards-lite defense. If Token Bucket values supplied,
    # both countermeasures will be applied simultaneously.
    elif len(sys.argv) == 8:
        n_initial_tokens, token_refill_rate, vanguardslite_enabled = \
            int(sys.argv[5]), float(sys.argv[6]), (int(sys.argv[7]) == 1)

    run_multiple_simulations(
        n_adv_hsdirs, adv_bw_share, n_experiments, n_runs,
        n_initial_tokens, token_refill_rate, vanguardslite_enabled)
