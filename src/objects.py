from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

from message.msgexceptions import *

import copy
import hashlib
import json
import re

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        return False
    return OBJECTID_REGEX.match(objid_str)


PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        return False
    return PUBKEY_REGEX.match(pubkey_str)


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")


def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        return False
    return SIGNATURE_REGEX.match(sig_str)


NONCE_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    return NONCE_REGEX.match(nonce_str)


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return TARGET_REGEX.match(target_str)


# syntactic checks
def validate_transaction_input(in_dict):
    if not isinstance(in_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'sig' not in in_dict:
        raise ErrorInvalidFormat("sig not set!")
    if not isinstance(in_dict['sig'], str):
        raise ErrorInvalidFormat("sig not a string!")
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat("sig not syntactically valid!")

    if 'outpoint' not in in_dict:
        raise ErrorInvalidFormat("outpoint not set!")
    if not isinstance(in_dict['outpoint'], dict):
        raise ErrorInvalidFormat("outpoint not a dictionary!")

    outpoint = in_dict['outpoint']
    if 'txid' not in outpoint:
        raise ErrorInvalidFormat("txid not set!")
    if not isinstance(outpoint['txid'], str):
        raise ErrorInvalidFormat("txid not a string!")
    if not validate_objectid(outpoint['txid']):
        raise ErrorInvalidFormat("txid not a valid objectid!")
    if 'index' not in outpoint:
        raise ErrorInvalidFormat("index not set!")
    if not isinstance(outpoint['index'], int):
        raise ErrorInvalidFormat("index not an integer!")
    if outpoint['index'] < 0:
        raise ErrorInvalidFormat("negative index!")
    if len(set(outpoint.keys()) - set(['txid', 'index'])) != 0:
        raise ErrorInvalidFormat("Additional keys present in outpoint!")

    if len(set(in_dict.keys()) - set(['sig', 'outpoint'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True  # syntax check done


# syntactic checks
def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'pubkey' not in out_dict:
        raise ErrorInvalidFormat("pubkey not set!")
    if not isinstance(out_dict['pubkey'], str):
        raise ErrorInvalidFormat("pubkey not a string!")
    if not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat("pubkey not syntactically valid!")

    if 'value' not in out_dict:
        raise ErrorInvalidFormat("value not set!")
    if not isinstance(out_dict['value'], int):
        raise ErrorInvalidFormat("value not an integer!")
    if out_dict['value'] < 0:
        raise ErrorInvalidFormat("negative value!")

    if len(set(out_dict.keys()) - set(['pubkey', 'value'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True  # syntax check done


# syntactic checks
def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        raise ErrorInvalidFormat("Transaction object invalid: Not a dictionary!")  # assert: false

    if 'type' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: Type not set")  # assert: false
    if not isinstance(trans_dict['type'], str):
        raise ErrorInvalidFormat("Transaction object invalid: Type not a string")  # assert: false
    if not trans_dict['type'] == 'transaction':
        raise ErrorInvalidFormat("Transaction object invalid: Type not 'transaction'")  # assert: false

    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: No outputs key set")
    if not isinstance(trans_dict['outputs'], list):
        raise ErrorInvalidFormat("Transaction object invalid: Outputs key not a list")

    index = 0
    for output in trans_dict['outputs']:
        try:
            validate_transaction_output(output)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Transaction object invalid: Output at index {index} invalid: {e.message}")
        index += 1

    # check for coinbase transaction
    if 'height' in trans_dict:
        # this is a coinbase transaction
        if not isinstance(trans_dict['height'], int):
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Height not an integer")
        if trans_dict['height'] < 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Negative height")

        if len(trans_dict['outputs']) > 1:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: More than one output set")

        if len(set(trans_dict.keys()) - set(['type', 'height', 'outputs'])) != 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Additional keys present")
        return

    # this is a normal transaction
    if not 'inputs' in trans_dict:
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not set")

    if not isinstance(trans_dict['inputs'], list):
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not a list")
    for input in trans_dict['inputs']:
        try:
            validate_transaction_input(input)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Normal transaction object invalid: Input at index {index} invalid: {e.message}")
        index += 1
    if len(trans_dict['inputs']) == 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: No input set")

    if len(set(trans_dict.keys()) - set(['type', 'inputs', 'outputs'])) != 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: Additional key present")

    return True  # syntax check done


# syntactic checks
def validate_block(block_dict):
    # todo
    valid_keys = set(['type', 'T', 'created', 'miner', 'note', 'nonce', 'previd', 'txids'])

    if not isinstance(block_dict, dict):
        raise ErrorInvalidFormat("Block object not valid: Not a Dictionary!")  # assert false

    if "type" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Missing field 'type'!")
    if not isinstance(block_dict["type"], str):
        raise ErrorInvalidFormat("Block object invalid: Field 'type' must be of type str!")
    if not block_dict["type"] == "block":
        raise ErrorInvalidFormat("Block object invalid: Type must be set to 'block'!")

    req_target = "00000000abc00000000000000000000000000000000000000000000000000000"
    if "T" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Missing field 'T'!")
    if not (validate_target(block_dict["T"]) and block_dict["T"] == req_target):
        raise ErrorInvalidFormat(f"Block object not valid: Target ('T') must be {req_target}!")

    if "created" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Missing field 'created'!")
    if not isinstance(block_dict["created"], int):
        raise ErrorInvalidFormat(
            f"Block object not valid: Invalid type ({type(block_dict['created'])}) for field 'created'!")
    try:
        create_time = datetime.fromtimestamp(block_dict["created"])
    except (OverflowError, OSError):
        raise ErrorInvalidFormat("Block object not valid: Field 'created' could not be parsed as timestamp!")
    now = datetime.now()
    if not create_time < now:
        raise ErrorInvalidFormat("Block object not valid: Field 'created' cannot be in future!")

    if "nonce" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Missing field 'nonce'!")
    if not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block object not valid: 'nonce' is not a valid 32-byte hexified value!")

    if "previd" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Missing field 'previd'!")
    if not validate_objectid(block_dict['previd']):
        # TODO: if is genesis-block, None (null) is allowed

        if not block_dict['previd'] is None:
            raise ErrorInvalidFormat("Block object not valid: Field 'previd' is invalid!")

    if "txids" not in block_dict:
        raise ErrorInvalidFormat("Block object not valid: Field 'txids' is missing!")
    if not isinstance(block_dict["txids"], list):
        raise ErrorInvalidFormat("Block object not valid: Field 'txids' must be a list!")

    # TODO: validate txids

    for tx in block_dict['txids']:
        if not validate_objectid(tx):
            raise ErrorInvalidFormat(f"Block object not valid: Transaction {tx} invalid!")

    if "miner" in block_dict:
        if not isinstance(block_dict["miner"], str):
            raise ErrorInvalidFormat("Block object not valid: Field 'miner' must be str!")
        if not re.match(r"[ -~]{1,128}", block_dict["miner"]):
            raise ErrorInvalidFormat(
                "Block object not valid: Field 'miner' must be ASCII-printable characters up to length of 128!")

    if "note" in block_dict:
        if not isinstance(block_dict["note"], str):
            raise ErrorInvalidFormat("Block object not valid: Field 'note' must be str!")
        if not re.match(r"[ -~]{1,128}", block_dict['note']):
            raise ErrorInvalidFormat(
                "Block object not valid: Field 'note' must be ASCII-printable characters up to length 128!")

    if len(set(block_dict.keys()) - valid_keys) != 0:
        raise ErrorInvalidFormat("Block object not valid: Additional keys present in object!")

    # verify PoW
    block_id = get_objid(block_dict)
    if not int(block_id, 16) < int(block_dict['T'], 16):
        raise ErrorInvalidFormat("Block object not valid: Invalid proof-of-work")

    return True


# syntactic checks
def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object invalid: Not a dictionary!")

    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object invalid: Type not set!")
    if not isinstance(obj_dict['type'], str):
        raise ErrorInvalidFormat("Object invalid: Type not a string")

    obj_type = obj_dict['type']
    if obj_type == 'transaction':
        return validate_transaction(obj_dict)
    elif obj_type == 'block':
        return validate_block(obj_dict)

    raise ErrorInvalidFormat("Object invalid: Unknown object type")


def expand_object(obj_str):
    return json.loads(obj_str)


def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()


# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    tx_local = copy.deepcopy(tx_dict)

    for i in tx_local['inputs']:
        i['sig'] = None

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)

    try:
        pubkey_obj.verify(sig_bytes, canonicalize(tx_local))
    except InvalidSignature:
        return False

    return True


class TXVerifyException(Exception):
    pass


# semantic checks
# assert: tx_dict is syntactically valid
def verify_transaction(tx_dict, input_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        if not isinstance(tx_dict['height'], int) or tx_dict['height'] < 0:
            raise ErrorInvalidFormat("Invalid Transaction: Coinbase transaction has invalid height!")
        if "inputs" in tx_dict:
            raise ErrorInvalidFormat("Invalid Transaction: Coinbase transaction has inputs!")
        if len(tx_dict['outputs']) != 1:
            raise ErrorInvalidFormat("Invalid Transaction: Coinbase transaction has none or more than one output!")
        if not validate_pubkey(tx_dict['outputs']['pubkey']):
            raise ErrorInvalidFormat("Invalid Transaction: Coinbase transaction has an invalid pubkey!")
        return True
    else:
        # regular transaction
        insum = 0  # sum of input values
        in_dict = dict()
        for i in tx_dict['inputs']:
            ptxid = i['outpoint']['txid']
            ptxidx = i['outpoint']['index']

            if ptxid in in_dict:
                if ptxidx in in_dict[ptxid]:
                    raise ErrorInvalidTxConservation(
                        f"The same input ({ptxid}, {ptxidx}) was used multiple times in this transaction")
                else:
                    in_dict[ptxid].add(ptxidx)
            else:
                in_dict[ptxid] = {ptxidx}

            if ptxid not in input_txs:
                raise ErrorUnknownObject(f"Transaction {ptxid} not known")

            ptx_dict = input_txs[ptxid]

            # just to be sure
            if ptx_dict['type'] != 'transaction':
                raise ErrorInvalidFormat("Previous TX '{}' is not a transaction!".format(ptxid))

            if ptxidx >= len(ptx_dict['outputs']):
                raise ErrorInvalidTxOutpoint("Invalid output index in previous TX '{}'!".format(ptxid))

            output = ptx_dict['outputs'][ptxidx]
            if not verify_tx_signature(tx_dict, i['sig'], output['pubkey']):
                raise ErrorInvalidTxSignature("Invalid signature from previous TX '{}'!".format(ptxid))

            insum = insum + output['value']

        if insum < sum([o['value'] for o in tx_dict['outputs']]):
            raise ErrorInvalidTxConservation("Sum of inputs < sum of outputs!")


class BlockVerifyException(Exception):
    pass


# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0


# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0
