#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum.virtual_channel.dynamic_channel import CbId, DynamicChannelCommand, DynamicChannelCapability
from pyrdp.pdu import PDU


class DynamicChannelPDU(PDU):
    """
    Base for DynamicChannelPDUs
    https://msdn.microsoft.com/en-us/library/cc241267.aspx
    """

    def __init__(self, cbid: int, sp: int, cmd: int, payload=b""):
        super().__init__(payload)
        self.cbid = CbId(cbid)
        self.sp = sp
        self.cmd = DynamicChannelCommand(cmd)


class CapabilityResponsePDU(DynamicChannelPDU):

    def __init__(self, cbid: int, sp: int, capability: DynamicChannelCapability):
        super().__init__(cbid, sp, DynamicChannelCommand.CAPABILITY_REQUEST)
        self.capability = capability


class CreateRequestPDU(DynamicChannelPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241244.aspx
    """

    def __init__(self, cbid: int, sp: int, channelId: int, channelName: str):
        super().__init__(cbid, sp, DynamicChannelCommand.CREATE)
        self.channelId = channelId
        self.channelName = channelName


class CreateResponsePDU(DynamicChannelPDU):
    """
    https://msdn.microsoft.com/en-us/library/cc241245.aspx
    """

    def __init__(self, cbid: int, sp: int, channelId: int, creationStatus: int):
        super().__init__(cbid, sp, DynamicChannelCommand.CREATE)
        self.channelId = channelId
        self.creationStatus = creationStatus


class DynamicDataFirstPDU(DynamicChannelPDU):
    def __init__(self, cbid: int, sp: int, channelId: int, length: int, data: bytes):
        super().__init__(cbid, sp, DynamicChannelCommand.DATA_FIRST)
        self.channelId = channelId
        self.length = length
        self.data = data


class DynamicDataPDU(DynamicChannelPDU):
    def __init__(self, cbid: int, sp: int, channelId: int, data: bytes):
        super().__init__(cbid, sp, DynamicChannelCommand.DATA)
        self.channelId = channelId
        self.data = data


class DynamicDataFirstCompressedPDU(DynamicChannelPDU):
    def __init__(self, cbid: int, sp: int, channelId: int, length: int, data: bytes):
        super().__init__(cbid, sp, DynamicChannelCommand.DATA_FIRST_COMPRESSED)
        self.channelId = channelId
        self.length = length
        self.data = data


class DynamicDataCompressedPDU(DynamicChannelPDU):
    def __init__(self, cbid: int, sp: int, channelId: int, data: bytes):
        super().__init__(cbid, sp, DynamicChannelCommand.DATA_COMPRESSED)
        self.channelId = channelId
        self.data = data


class CloseDynamicChannelPDU(DynamicChannelPDU):
    def __init__(self, cbid: int, sp: int, channelId: int):
        super().__init__(cbid, sp, DynamicChannelCommand.CLOSE)
        self.channelId = channelId
