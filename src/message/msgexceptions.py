from abc import ABC, abstractproperty

"""
    Abstract class
"""


class MessageException(ABC, Exception):
    NETWORK_ERROR_MESSAGE = ""
    NETWORK_ERROR_NAME = ""

    def __init__(self, name="", msg=""):
        self.NETWORK_ERROR_NAME = name
        self.NETWORK_ERROR_MESSAGE = msg


class MsgParseException(MessageException):
    NETWORK_ERROR_MESSAGE = "Invalid message received"


class MalformedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Malformed message received"


class UnsupportedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unsupported message received"


class UnexpectedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unexpected message received"
