from Peer import Peer
import socket

MAX_CONNECTIONS = 5
PORT = 18018
ADDRESS = '0.0.0.0'
OWN_IP = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
SERVICE_LOOP_DELAY = 10
VERSION = '0.10.0'
AGENT = ''
LOW_CONNECTION_THRESHOLD = 3
HELLO_MSG_TIMEOUT = 20.0
DB_NAME = 'db.db'
RECV_BUFFER_LIMIT = 512 * 1024
BLOCK_TARGET = ""
BLOCK_VERIFY_WAIT_FOR_PREV_MUL = 10
BLOCK_VERIFY_WAIT_FOR_PREV = 1
BLOCK_VERIFY_WAIT_FOR_TXS_MUL = 10
BLOCK_VERIFY_WAIT_FOR_TXS = 1
BLOCK_REWARD = 50_000_000_000_000
GENESIS_BLOCK_ID = "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"
GENESIS_BLOCK = {
    "T": "00000000abc00000000000000000000000000000000000000000000000000000",
    "created": 1671062400,
    "miner": "Marabu",
    "nonce": "000000000000000000000000000000000000000000000000000000021bea03ed",
    "note": "The New York Times 2022-12-13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers",
    "previd": None,
    "txids": [],
    "type": "block"
}

BANNED_HOSTS = [
]

# was { Peer(...) }
PRELOADED_PEERS = [
    Peer("128.130.122.101", 18018),  # lecturers node
]
