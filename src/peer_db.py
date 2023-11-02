from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    if existing_peers is None:
        existing_peers = load_peers()
    # avoid duplicates
    if peer in existing_peers:
        return

    with open(PEER_DB_FILE, 'a') as file:
        file.write(f"{peer.host_formated},{peer.port}\n")

def remove_peer(peer: Peer):
    existing_peers = load_peers()
    if not peer in existing_peers:
        return False

    with open(PEER_DB_FILE, 'w') as file:
        for p in existing_peers:
            if not p == peer:
                file.write(f"{p.host_formated},{p.port}\n")

def load_peers() -> Set[Peer]:
    with open(PEER_DB_FILE, 'r') as file:
        # skip the header
        peers_str = file.readlines()[1:]

    result = set()
    for line in peers_str:
        host, port = line.split(',')
        result.add(Peer(host, int(port.strip())))
    return result
