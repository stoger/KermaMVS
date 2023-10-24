from typing import List

from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize
import csv
import socket

from datetime import datetime

import mempool
import objects
import peer_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = peer_db.load_peers()
CONNECTIONS = dict()
BACKGROUND_TASKS = set()
BLOCK_VERIFY_TASKS = dict()
BLOCK_WAIT_LOCK = None
TX_WAIT_LOCK = None
CSV_FILE = "peers.csv"
MEMPOOL = mempool.Mempool(const.GENESIS_BLOCK_ID, {})
LISTEN_CFG = {
    "address": const.ADDRESS,
    "port": const.PORT
}

NODE_VERSION = "0.10.1"
NODE_NAME = "NodeJS"


# Add peer to your list of peers
def add_peer(peer):
    peer_str = peer.host
    if peer_str.__contains__("localhost") or peer_str.__contains__("0.0.0.0") or peer_str.__contains__("127.0.0.1"):
        log(f"{peer_str} may be our own address")
        return
    if peer not in PEERS:
        peer_db.store_peer(peer, PEERS)
        PEERS.add(peer)
        log(f"Added peer {peer} to file and PEERS, new peers: {PEERS}")


def remove_peer(peer):
    if peer in PEERS:
        PEERS.remove(peer)
        log(f"Removed peer {peer}, new peers: {PEERS}")
        peer_db.forget_peer(peer)


# Add connection if not already open
def add_connection(peer, queue):
    if peer not in CONNECTIONS.keys():
        CONNECTIONS.update({peer: dict(queue=queue)})
        add_peer(peer)
    pass


# Delete connection
def del_connection(peer):
    if peer in CONNECTIONS:
        CONNECTIONS.pop(peer)
    pass


# Make msg objects
def mk_error_msg(error_str, error_name):
    return dict(type="error", name=error_name, msg=error_str)


def mk_hello_msg():
    return dict(type="hello", version=NODE_VERSION, agent=NODE_NAME)


def mk_getpeers_msg():
    return dict(type="getpeers")


def mk_peers_msg():
    peers_available = len(PEERS)
    peers = PEERS
    log(f"Available PEERS: {peers}")
    if peers_available < 30:
        additional = peer_db.load_peers()
        log(f"Loaded additional: {additional}")
        peers.update(additional)
    # peers = peer_db.load_peers()
    peers = set(list(peers)[:-1])
    str_peers = []

    log(f"Peers {len(peers)} loaded: {peers}")
    i = 0
    for peer in reversed(list(peers)):
        i += 1
        if i < 30:
            str_peers.append(str(peer))
    str_peers.append(const.OWN_IP + ':' + str(LISTEN_CFG["port"]))
    return dict(type="peers", peers=str_peers)


def mk_getobject_msg(objid):
    pass  # TODO


def mk_object_msg(obj_dict):
    pass  # TODO


def mk_ihaveobject_msg(objid):
    pass  # TODO


def mk_chaintip_msg(blockid):
    pass  # TODO


def mk_mempool_msg(txids):
    pass  # TODO


def mk_getchaintip_msg():
    pass  # TODO


def mk_getmempool_msg():
    pass  # TODO


# parses a message as json. returns decoded message
def parse_msg(msg_str):
    try:
        return json.loads(msg_str)
    except json.decoder.JSONDecodeError:
        raise MsgParseException("INVALID_FORMAT", "Invalid JSON message provided")


# Send data over the network as a message
async def write_msg(writer, msg_dict: dict[str: str]):
    log(f"writing {msg_dict}")
    bytes_json = canonicalize(msg_dict)
    writer.write(bytes_json)
    writer.write(b"\n")
    await writer.drain()
    pass  # TODO


# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    pass  # TODO


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    # ensure keys are ordered alphabetically
    canon_hello = json.loads(canonicalize(msg_dict))
    if not (["agent", "type", "version"] == list(canon_hello.keys())):
        raise MalformedMsgException("INVALID_FORMAT",
                                    "Unexpected set of keys received, only 'type', 'agent' and 'version' are allowed")

    agent_pattern = re.compile(r"^[ -~]{1,128}$")
    version_pattern = re.compile(r"^0.10.\d$")

    if not agent_pattern.match(msg_dict["agent"]):
        raise MalformedMsgException("INVALID_FORMAT", "Invalid agent-string provided")

    if not version_pattern.match(msg_dict["version"]):
        raise MalformedMsgException("INVALID_FORMAT", "Invalid kerma-node version string provided")


# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    hostname_pattern = re.compile(r"^[a-zA-Z\d\.\-\_]{3,50}$")
    assure_az_pattern = re.compile(r".*?[a-zA-Z]{1,}.*?")

    if not hostname_pattern.match(host_str):
        return False

    if not assure_az_pattern.match(host_str):
        return False

    if "." not in host_str or (host_str.startswith(".") or host_str.endswith(".")):
        return False

    return True


# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    try:
        socket.inet_aton(host_str)
        return True
    except socket.error:
        return False


# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    peer_str_pattern = re.compile(r"^[\w\.]+?\w+:\d+$")
    if not peer_str_pattern.match(peer_str):
        log(f"{peer_str} did not match basic regex")
        return False

    host, port = peer_str.split(":")
    host = host.strip()
    port = int(port)
    if port <= 0 or port > 65535:
        log(f"{port} is not in desirable range")
        return False

    if validate_ipv4addr(host) or validate_hostname(host):
        return True
    else:
        return False


# raise an exception if not valid
def validate_peers_msg(msg_dict):
    canon_dict = json.loads(canonicalize(msg_dict))
    if not ["peers", "type"] == list(canon_dict.keys()):
        if "peers" in canon_dict:
            for peer in msg_dict["peers"]:
                remove_peer(peer)
                del_connection(peer)
                peer_db.forget_peer(peer)
        raise MalformedMsgException("INVALID_FORMAT", "Invalid peers-dictionary provided")
    else:
        peers = msg_dict["peers"]
        for peer in peers:
            if not validate_peer_str(peer):
                raise MalformedMsgException("INVALID_FORMAT", "Invalid peer_str provided")


# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    if not (len(msg_dict.keys()) == 1 and "type" in msg_dict.keys()):
        raise MalformedMsgException("INVALID_FORMAT", "Invalid set of keys provided for getpeers message")


# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_error_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_object_msg(msg_dict):
    pass  # TODO


# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    pass  # todo


# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    pass  # todo


def validate_msg(msg_dict):
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        log("validating peers")
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        raise UnsupportedMsgException("INVALID_FORMAT", "Invalid message received (unknown type)")


def handle_peers_msg(msg_dict):
    # all is validated when reaching here
    for peer in msg_dict["peers"]:
        if validate_peer_str(peer):
            log(f"adding peer: {peer}")
            host, port = peer.split(":")
            add_peer(Peer(host_str=host, port=port))


def handle_error_msg(msg_dict, peer_self):
    pass  # TODO


async def handle_ihaveobject_msg(msg_dict, writer):
    pass  # TODO


async def handle_getobject_msg(msg_dict, writer):
    pass  # TODO


# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    pass  # TODO


# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    # TODO
    block = ''
    utxo = ''
    height = ''
    return (block, utxo, height)


# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass  # TODO


# Stores for a block its utxoset and height
def store_block_utxo_height(block, utxo, height: int):
    pass  # TODO


# runs a task to verify a block
# raises blockverifyexception
async def verify_block_task(block_dict):
    pass  # TODO


# adds a block verify task to queue and starting it
def add_verify_block_task(objid, block, queue):
    pass  # TODO


# abort a block verify task
async def del_verify_block_task(task, objid):
    pass  # TODO


# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
    pass  # TODO


# returns the chaintip blockid
def get_chaintip_blockid():
    pass  # TODO


async def handle_getchaintip_msg(msg_dict, writer):
    pass  # TODO


async def handle_getmempool_msg(msg_dict, writer):
    pass  # TODO


async def handle_chaintip_msg(msg_dict):
    pass  # TODO


async def handle_mempool_msg(msg_dict):
    pass  # TODO


# Helper function
async def handle_queue_msg(msg_dict, writer):
    validate_msg(msg_dict)
    peer = Peer(*writer.get_extra_info('peername'))
    handshake_complete = CONNECTIONS[peer]["handshake_complete"]

    match msg_dict["type"]:
        case "hello":
            if handshake_complete:
                raise UnexpectedMsgException("INVALID_HANDSHAKE", "hello message received after successful handshake")
            else:
                CONNECTIONS[peer]["handshake_fail_task"].cancel()
                CONNECTIONS[peer]["handshake_fail_task"] = None
                CONNECTIONS[peer]["handshake_complete"] = True
            pass
        case "getpeers":
            if not handshake_complete:
                raise UnexpectedMsgException("INVALID_HANDSHAKE", "Non-hello message received before hello message")
            await write_msg(writer, mk_peers_msg())
        case "peers":
            if not handshake_complete:
                raise UnexpectedMsgException("INVALID_HANDSHAKE", "Non-hello message received before hello message")
            handle_peers_msg(msg_dict)
        case _:
            if not handshake_complete:
                raise UnexpectedMsgException("INVALID_HANDSHAKE", "Non-hello message received before hello message")
    pass  # should not die :)


async def handle_handshake_fail(writer):
    await write_msg(writer, mk_error_msg("No handshake message received in 20s", "INVALID_HANDSHAKE"))
    writer.close()
    await writer.wait_closed()
    pass


# how to handle a connection
async def handle_connection(reader, writer):
    read_task = None
    queue_task = None

    peer = None
    queue = asyncio.Queue()
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")

        peer = Peer(*peer)
        log("New connection with {}".format(peer))
        add_connection(peer, queue)
    except Exception as e:
        log(str(e))
        try:
            writer.close()
        except:
            pass
        return

    handshake_fail_task = None
    try:
        # perform our side of handshake
        await write_msg(writer, mk_hello_msg())
        await write_msg(writer, mk_getpeers_msg())

        # handle handshake failure: 20s no handshake received
        event_loop = asyncio.get_event_loop()
        handshake_fail_task = event_loop.call_later(20, lambda w: asyncio.ensure_future(handle_handshake_fail(w)),
                                                    writer)
        CONNECTIONS[peer]["handshake_fail_task"] = handshake_fail_task
        CONNECTIONS[peer]["handshake_complete"] = False

        # Complete handshake
        msg_str = None
        parts = []

        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                                               return_when=asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            if msg_str == b"":
                continue

            # TODO
            if not msg_str.endswith(b"\n"):
                parts.append(msg_str)
            else:
                if len(parts) > 0:
                    parts.append(msg_str)
                    msg_str = "".join(parts)
                    parts = []

                parsed_msg = parse_msg(msg_str)
                await queue.put(parsed_msg)

            log(f"Received: {msg_str}, stored parts = {parts}")
    except asyncio.exceptions.TimeoutError:
        log("{}: Timeout".format(peer))
        try:
            await write_msg(writer, mk_error_msg("Timeout", ""))
        except:
            pass
    except MessageException as e:
        log("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, mk_error_msg(e.NETWORK_ERROR_MESSAGE, e.NETWORK_ERROR_NAME))
        except:
            pass
        remove_peer(peer)
    except Exception as e:
        log("{}: {}".format(peer, str(e)))
    finally:
        if CONNECTIONS[peer]["handshake_fail_task"] is not None:
            CONNECTIONS[peer]["handshake_fail_task"] = handshake_fail_task.cancel()

        log("Closing connection with {}".format(peer))
        writer.close()
        await writer.wait_closed()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                                                       limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        log(str(e))
        remove_peer(peer)
        return

    await handle_connection(reader, writer)


async def listen():
    log("listening!")
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
                                        LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    log("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()


# bootstrap peers. connect to hardcoded peers
async def bootstrap():
    boot_peer = const.PRELOADED_PEERS[0]
    if boot_peer not in PEERS:
        # add_peer(boot_peer)
        await connect_to_node(boot_peer)
        log("Connected to bootstrap node!")
        log("bootstrapping")
    else:
        pass


# connect to some peers
async def resupply_connections():
    log("connecting to peers :)")
    log(PEERS)
    pcopy = set(PEERS)
    for candidate in pcopy:
        ckeys = CONNECTIONS.keys()
        log(f"Candidate: {candidate}, ckeys: {ckeys}")
        if candidate not in ckeys:
            # add_peer(candidate)
            log("Resupplied connection to candidate node!")
            await connect_to_node(candidate)
    pass


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    PEERS.update(peer_db.load_peers())
    log(f"Loaded initial peers: {PEERS}")

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    boot_peer = const.PRELOADED_PEERS[0]
    log(f'boot_peer: {boot_peer}')
    # await connect_to_node(boot_peer)

    # Service loop
    while True:
        log("Service loop reporting in.")
        log("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        log(f"connections open: {len(CONNECTIONS)}, max connections: {const.MAX_CONNECTIONS}")
        if len(CONNECTIONS) < const.MAX_CONNECTIONS:
            await resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    log("running main")
    asyncio.run(init())


def log(msg, flush=True):
    print(f"[{datetime.now()}] {msg}", flush=flush)
    pass


if __name__ == "__main__":
    log("booting up")
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
