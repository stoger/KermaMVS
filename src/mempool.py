import copy
import sqlite3

import constants as const
import objects

# get expanded object for 
def fetch_object(oid, cur):
    pass # TODO

# get utxo for block
def fetch_utxo(bid, cur):
    pass # TODO

# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tip, blockids):
    pass # TODO

# return a list of transactions by index
def find_all_txs(txids):
    pass # TODO

# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    pass # TODO

# get (id of lca, list of old blocks from lca, list of new blocks from lca) 
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    pass # TODO

def rebase_mempool(old_tip, new_tip, mptxids):
    pass # TODO

class Mempool:
    def __init__(self, bbid: str, butxo: set):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        if tx["inputs"] == []:
            return False
# This is possible if Tx spends only from unspent outputs that are also not spent by any transaction currently in the mempool.

        for item in tx["inputs"]:
            spending_tx = item["outpoint"]["txid"]
            if spending_tx not in self.utxo:
                return False  # already spent or something

            self.utxo.remove(spending_tx)
            self.txs.append(spending_tx)
        return True  # TODO

    def rebase_to_block(self, bid: str):
        self.base_block_id = bid
        (_, utxo, _) = objects.get_block_utxo_height(bid)
        self.utxo = utxo
        tx_to_reapply = self.txs
        self.txs = []

        for item in tx_to_reapply:
            self.try_add_tx(item)
        pass  # TODO

    def printMempool(self): #debuuggg
        print(self.txs)
        print(self.utxo)