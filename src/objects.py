from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_objectid(objid_str):
    if re.match(OBJECTID_REGEX, objid_str):
        return True
    return False


PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_pubkey(pubkey_str):
    if re.match(PUBKEY_REGEX, pubkey_str):
        return True
    return False


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")


def validate_signature(sig_str):
    if re.match(SIGNATURE_REGEX, sig_str):
        return True
    return False


NONCE_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_nonce(nonce_str):
    if re.match(NONCE_REGEX, nonce_str):
        return True
    return False


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")


def validate_target(target_str):
    if re.match(TARGET_REGEX, target_str):
        return True
    return False


def validate_transaction_input(in_dict):
    objID = get_objid(in_dict.get("id"))
    if not validate_objectid(objID):
        return False
    if not validate_signature(in_dict.get("sig")):
        return False
    return True


def validate_transaction_output(out_dict):
    # todo
    if not validate_pubkey(out_dict["pubkey"]):
        return False
    if int(out_dict["value"]) < 0:
        return False
    return True


def validate_transaction(trans_dict):
    objID = get_objid(trans_dict)
    if not validate_objectid(objID):
        return False
    for i in trans_dict.get("inputs", []):
        if not validate_transaction_input(i):
            return False
    for i in trans_dict.get("outputs", []):
        if not validate_transaction_output(i):
            return False
    return True


def validate_block(block_dict):
    objID = get_objid(block_dict)
    if not validate_objectid(objID):
        return False
    if not validate_nonce(block_dict.get("nonce")):
        return False
    if not validate_target(block_dict.get("T")):
        return False
    if block_dict.get("previd"):
        if not validate_objectid(block_dict.get("previd")):
            return False
    if len(block_dict.get("txids", [])) > 0:
        for i in block_dict.get("txids"):
            if not validate_objectid(i):
                return False
    return True


def validate_object(obj_dict):
    if obj_dict.get("type") == "block":
        return validate_block(obj_dict)
    elif obj_dict.get("type") == "transaction":
        return validate_transaction(obj_dict)
    return False #either block nor transaction


def get_objid(obj_dict):
    h = hashlib.blake2s()
    canon = canonicalize(obj_dict)
    h.update(canon)
    return h.hexdigest()


# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    try:
        # Decode the public key from its hexadecimal representation
        pubkey_bytes = bytes.fromhex(pubkey)
        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)

        # Decode the signature from its hexadecimal representation
        sig_bytes = bytes.fromhex(sig)

        # Serialize and hash the message
        message = canonicalize(tx_dict)
        print(f"==============================\nVerifying signature: {sig}\npubkey: {pubkey}\ndictionary:\t{message}\n==============================")
        h = hashlib.sha256()
        h.update(message)
        message_hash = h.digest()
        print("obtained message bytes", flush=True)

        # Verify the signature
        public_key.verify(sig_bytes, message_hash)

        print("verified!", flush=True)

        return True  # Signature is valid
    except ValueError as e:
        print(f"ValueError Exception: {e}", flush=True)
        return False  # Signature is invalid
    except InvalidSignature as e:
        print(f"Signature invalid: {e}", flush=True)
        return False  # Signature is invalid


class TXVerifyException(Exception):
    pass


def verify_transaction(tx_dict, input_txs):
    pass  # todo


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
