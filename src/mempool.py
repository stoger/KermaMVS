import copy
import sqlite3

import constants as const
import objects


# get expanded object for
def fetch_object(oid, cur):
    pass  # TODO


# get utxo for block
def fetch_utxo(bid, cur):
    pass  # TODO


# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tip, blockids):
    pass  # TODO


# return a list of transactions by index
def find_all_txs(txids):
    pass  # TODO


# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    txs = list()
    for block in blocks:
        txs += block['txids']
    return set(txs)


def get_all_blocks_from_chain(chaintip, end_block):
    tip = objects.get_object(chaintip)
    if tip == None:
        return []

    if tip == end_block or tip['previd'] == None:
        return [tip]

    blocks = list()
    next_block = objects.get_object(tip['previd'])
    blocks.append(next_block)
    while next_block is not end_block:
        next_block = objects.get_object(next_block['previd'])
        if next_block is None:
            break
        blocks.append(next_block)
    return blocks[::-1]


def get_common_ancestor(old_chaintip, new_chaintip):
    old_blocks = get_all_blocks_from_chain(old_chaintip, const.GENESIS_BLOCK)
    new_blocks = get_all_blocks_from_chain(new_chaintip, const.GENESIS_BLOCK)
    greatest_index = -1
    for block in old_blocks:
        if block in new_blocks and old_blocks.index(block) > greatest_index:
            greatest_index = old_blocks.index(block)

    return objects.get_object(old_blocks[greatest_index]) if greatest_index != -1 else objects.get_object(
        const.GENESIS_BLOCK_ID)


# get (id of lca, list of old blocks from lca, list of new blocks from lca)
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    ancestor = get_common_ancestor(old_tip, new_tip)
    old_blocks = get_all_blocks_from_chain(old_tip, ancestor)
    new_blocks = get_all_blocks_from_chain(new_tip, ancestor)

    return ancestor, old_blocks, new_blocks


def rebase_mempool(old_tip, new_tip, mptxids):
    ancestor = get_common_ancestor(old_tip, new_tip)
    print(f"found ancestor: {ancestor}", flush=True)

    # cur_block = objects.get_object(old_tip)
    # oid = old_tip
    # reapply_tx = []
    # while cur_block != ancestor:
    #     reapply_tx += objects.get_block_txs()


    pass  # TODO


class Mempool:
    def __init__(self, bbid: str, butxo: set):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        if "inputs" not in tx or tx["inputs"] == []:
            return False
        for item in tx["inputs"]:
            spending_tx = item["outpoint"]["txid"]
            if spending_tx not in self.utxo:
                return False  # already spent or something

            self.utxo.remove(spending_tx)
            self.txs.append(spending_tx)
        return True 

    def rebase_to_block(self, bid: str):
        ancestor, old_blocks, new_blocks = get_lca_and_intermediate_blocks(self.base_block_id, bid)
        reapply_tx = get_all_txids_in_blocks(old_blocks)
        existing_tx = self.txs.copy()
        self.txs = []

        for tx in reapply_tx:
            self.try_add_tx(tx)

        for tx in existing_tx:
            self.try_add_tx(tx)

        self.base_block_id = bid

        (_, utxo, _) = objects.get_block_utxo_height(bid)
        self.utxo = utxo


    def print_mempool(self):  # debuuggg
        print(self.txs)
        print(self.utxo)
