#!/usr/bin/env python3

"""
Downloads the current consensus and server descriptors of all routers
carrying the 'HSDir' in the consensus. Stores consensus and server
descriptors to files.
"""

from os import makedirs
from os.path import abspath, join
from json import dump
from datetime import datetime
from collections import OrderedDict
from stem import DirPort
from stem.descriptor import DocumentHandler, remote


# Specify preferred Tor directory connection details.
TOR_DIR_IP = "45.66.33.45"
TOR_DIR_PORT = "80"


def download_and_save_consensus(state_dir):
    """Downloads current consensus from the specified directory relay
    and saves the response to a file in the supplied output directory."""

    # Blocking call that downloads the latest consensus from
    # the specified directory relay.
    consensus = remote.get_consensus(
        endpoints=[DirPort(TOR_DIR_IP, TOR_DIR_PORT)],
        document_handler=DocumentHandler.DOCUMENT,
    ).run()[0]

    with open(join(state_dir, "consensus"), "w") as cns_fp:
        cns_fp.write(str(consensus))

    return consensus


def download_and_save_all_descriptors(state_dir):
    """Downloads all server descriptors from the specified directory relay
    and saves the response to a file in the supplied output directory."""

    descriptors = OrderedDict()

    # Blocking call that downloads all server descriptors known
    # to the specified directory relay.
    descriptors_raw = remote.get_server_descriptors(
        endpoints=[DirPort(TOR_DIR_IP, TOR_DIR_PORT)],
    ).run()

    with open(join(state_dir, "descriptors"), "a") as descs_fp:

        for descriptor in descriptors_raw:

            # Append descriptor to file.
            descs_fp.write(str(descriptor))

            # Ensure each identity public key is present and of correct length.
            assert len(descriptor.ed25519_master_key) == 43

            # Insert identity public key of descriptor into dictionary.
            descriptors[descriptor.fingerprint] = descriptor.ed25519_master_key

    return descriptors


def select_all_hsdirs(state_dir, consensus, descriptors):
    """Iterates over routers in consensus and selects all that carry
    the 'HSDir' flag. Augments each HSDir entry with its base64-encoded
    identity public key and writes dictionary to file."""

    hsdirs = OrderedDict()

    for _, relay in consensus.routers.items():

        if "HSDir" in relay.flags:

            hsdirs[relay.fingerprint] = {
                "nickname": relay.nickname,
                "identity_pubkey": descriptors[relay.fingerprint],
            }

    with open(join(state_dir, "hsdirs"), "w") as hsdirs_fp:
        dump(hsdirs, hsdirs_fp, indent=4)
        hsdirs_fp.write("\n")


def load_hsdirs():
    """Downloads current consensus, selects all relays in it
    that carry the 'HSDir' flag, and downloads all their server
    descriptors to directory."""

    now = datetime.now()
    now_fmt = now.strftime("%Y-%m-%d_%H-%M-%S")
    state_dir = abspath("./{}_consensus_descriptors".format(now_fmt))

    # Create output directory to store consensus and
    # server descriptors for subsequent use.
    makedirs(state_dir, exist_ok=True)

    # Download latest consensus and save it to file.
    consensus = download_and_save_consensus(state_dir)

    # Download all known relay descriptors and save them to file.
    descriptors = download_and_save_all_descriptors(state_dir)

    # Read consensus, extract HSDirs, augment with their identity keys.
    select_all_hsdirs(state_dir, consensus, descriptors)


if __name__ == "__main__":
    load_hsdirs()
