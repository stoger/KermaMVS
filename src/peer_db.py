import csv

from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"


# Function to check if the string exists in the CSV
def string_exists(string_to_add):
    with open(PEER_DB_FILE, "r", newline="") as file:
        lines = file.readlines()
        for line in lines:
            if string_to_add.__eq__(line.strip()):
                return True
    return False


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    # append to file
    if not string_exists(peer.host + ',' + str(peer.port)):
        if existing_peers:
            file = open(PEER_DB_FILE, "w")
            data = ""
            for p in existing_peers:
                data += p.host + ',' + str(p.port) + "\n"

            data += peer.host + ',' + str(peer.port) + "\n"
            file.write(data)
        else:
            with open(PEER_DB_FILE, "a", newline="") as file:
                writer = csv.writer(file, delimiter=",")
                writer.writerow([peer.host, peer.port])
    pass


def load_peers() -> Set[Peer]:
    max_peers = 30
    try:
        file = open(PEER_DB_FILE, "r")
        lines = file.readlines()
        file.close()
        lines.reverse()
        result = []
        for line in lines:
            if max_peers > 0:
                max_peers = max_peers - 1
                line = line.strip()
                if line == "":
                    continue
                content = line.split(",")
                peer = Peer(host_str=content[0], port=int(content[1]))
                # result.append(peer.host + ':' + str(peer.port))
                result.append(peer)
            else:
                file.close()
                break
        return set(result)
    except FileNotFoundError:
        file = open(PEER_DB_FILE, "w")
        file.close()
        return set()


def forget_peer(peer: Peer):
    with open(PEER_DB_FILE, "r") as f:
        lines = f.readlines()
    with open(PEER_DB_FILE, "w") as f:
        for line in lines:
            if not line.strip("\n").__contains__(peer.host + ',' + str(peer.port)):
                f.write(line)
