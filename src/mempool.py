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
    pass  # TODO


def get_all_blocks_from_chain(chaintip, end_block):
    tip = objects.get_object(chaintip)
    blocks = list()
    next_block = objects.get_object(tip['previd'])
    blocks.append(objects.get_objid(next_block))
    while next_block is not end_block:
        next_block = objects.get_object(next_block['previd'])
        blocks.append(objects.get_objid(next_block))
    return blocks[::-1]


def get_common_ancestor(old_chaintip, new_chaintip):
    old_blocks = get_all_blocks_from_chain(old_chaintip, const.GENESIS_BLOCK_ID)
    new_blocks = get_all_blocks_from_chain(new_chaintip, const.GENESIS_BLOCK_ID)
    greatest_index = 0
    for block in old_blocks:
        if block in new_blocks and old_blocks.index(block) > greatest_index:
            greatest_index = old_blocks.index(block)

    return objects.get_object(old_blocks[greatest_index]) if greatest_index != 0 else objects.get_object(
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
        if tx["inputs"] == []:
            return False
        for item in tx["inputs"]:
            spending_tx = item["outpoint"]["txid"]
            if spending_tx not in self.utxo:
                return False  # already spent or something

            self.utxo.remove(spending_tx)
            self.txs.append(spending_tx)
        return True  # TODO

    def rebase_to_block(self, bid: str):
        rebase_mempool(self.base_block_id, bid, [])
        (block, utxo, _) = objects.get_block_utxo_height(bid)

        # gather all blocks between bid & latest state
        now_pending = []
        while block["previd"] != self.base_block_id:
            now_pending.append(block)
            (block, _, _) = objects.get_block_utxo_height(block["previd"])

        # try to reapply all from earliest to latest
        for item in now_pending[::-1]:
            pass

        self.base_block_id = bid
        self.utxo = utxo
        tx_to_reapply = self.txs
        self.txs = []

        for item in tx_to_reapply:
            self.try_add_tx(item)
        pass  # TODO

    def print_mempool(self):  # debuuggg
        print(self.txs)
        print(self.utxo)
