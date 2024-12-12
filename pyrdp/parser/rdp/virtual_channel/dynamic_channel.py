#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE, Uint8
from pyrdp.enum.virtual_channel.dynamic_channel import CbId, DynamicChannelCommand
from pyrdp.parser import Parser
from pyrdp.pdu import PDU
from pyrdp.pdu.rdp.virtual_channel.dynamic_channel import CreateRequestPDU, CreateResponsePDU, DynamicChannelPDU, CapabilityResponsePDU, CloseDynamicChannelPDU, DynamicDataCompressedPDU, DynamicDataFirstCompressedPDU, DynamicDataPDU, DynamicDataFirstPDU


class DynamicChannelParser(Parser):
    """
    Parser for the dynamic channel (drdynvc) packets.
    """

    def __init__(self):
        super().__init__()

    def doParse(self, data: bytes) -> PDU:
        stream = BytesIO(data)
        header = Uint8.unpack(stream)
        cbid = (header & 0b00000011)
        sp = (header & 0b00001100) >> 2
        cmd = (header & 0b11110000) >> 4

        if cmd == DynamicChannelCommand.CREATE:
            channelId = self.readChannelId(stream, cbid)
            channelName = ""
            char = stream.read(1).decode()
            while char != "\x00":
                channelName += char
                char = stream.read(1).decode()
            return CreateRequestPDU(cbid, sp, channelId, channelName)
        elif cmd == DynamicChannelCommand.DATA_FIRST:
            channelId = self.readChannelId(stream, cbid)
            length = self.readLength(stream, sp)
            data = stream.read()
            return DynamicDataFirstPDU(cbid, sp, channelId, length, data)
        elif cmd == DynamicChannelCommand.DATA:
            channelId = self.readChannelId(stream, cbid)
            data = stream.read()
            return DynamicDataPDU(cbid, sp, channelId, data)
        elif cmd == DynamicChannelCommand.DATA_FIRST_COMPRESSED:
            channelId = self.readChannelId(stream, cbid)
            length = self.readLength(stream, sp)
            data = stream.read()
            return DynamicDataFirstCompressedPDU(cbid, sp, channelId, length, data)
        elif cmd == DynamicChannelCommand.DATA_COMPRESSED:
            channelId = self.readChannelId(stream, cbid)
            data = stream.read()
            return DynamicDataCompressedPDU(cbid, sp, channelId, data)
        elif cmd == DynamicChannelCommand.CLOSE:
            channelId = self.readChannelId(stream, cbid)
            return CloseDynamicChannelPDU(cbid, sp, channelId)
        return DynamicChannelPDU(cbid, sp, cmd, stream.read())

    def write(self, pdu: DynamicChannelPDU) -> bytes:
        stream = BytesIO()
        header = pdu.cbid
        header |= pdu.sp << 2
        header |= pdu.cmd << 4
        Uint8.pack(header, stream)
        if isinstance(pdu, CapabilityResponsePDU):
            Uint8.pack(0, stream) # Append 1byte padding
            Uint16LE.pack(pdu.capability, stream)
        elif isinstance(pdu, CreateResponsePDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
            Uint32LE.pack(pdu.creationStatus, stream)
        elif isinstance(pdu, DynamicDataFirstPDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
            self.writeLength(stream, pdu.sp, pdu.length)
            stream.write(pdu.data)
        elif isinstance(pdu, DynamicDataPDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
            stream.write(pdu.data)
        elif isinstance(pdu, DynamicDataFirstCompressedPDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
            self.writeLength(stream, pdu.sp, pdu.length)
            stream.write(pdu.data)
        elif isinstance(pdu, DynamicDataCompressedPDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
            stream.write(pdu.data)
        elif isinstance(pdu, CloseDynamicChannelPDU):
            self.writeChannelId(stream, pdu.cbid, pdu.channelId)
        else:
            raise NotImplementedError()
        return stream.getvalue()

    def readChannelId(self, stream: BytesIO, cbid: int):
        if cbid == CbId.ONE_BYTE:
            return Uint8.unpack(stream)
        elif cbid == CbId.TWO_BYTE:
            return Uint16LE.unpack(stream)
        elif cbid == CbId.FOUR_BYTES:
            return Uint32LE.unpack(stream)
        else:
            raise ValueError(f"Invalid channel id length: {cbid}")

    def readLength(self, stream: BytesIO, len: int):
        if len == CbId.ONE_BYTE:
            return Uint8.unpack(stream)
        elif len == CbId.TWO_BYTE:
            return Uint16LE.unpack(stream)
        elif len == CbId.FOUR_BYTES:
            return Uint32LE.unpack(stream)
        else:
            raise ValueError(f"Invalid length value: {len}")

    def writeChannelId(self, stream: BytesIO, cbid: int, channelId: int):
        if cbid == CbId.ONE_BYTE:
            return Uint8.pack(channelId, stream)
        elif cbid == CbId.TWO_BYTE:
            return Uint16LE.pack(channelId, stream)
        elif cbid == CbId.FOUR_BYTES:
            return Uint32LE.pack(channelId, stream)
        else:
            raise ValueError(f"Invalid channel id length: {cbid}")
        
    def writeLength(self, stream: BytesIO, len: int, length: int):
        if len == CbId.ONE_BYTE:
            return Uint8.pack(length, stream)
        elif len == CbId.TWO_BYTE:
            return Uint16LE.pack(length, stream)
        elif len == CbId.FOUR_BYTES:
            return Uint32LE.pack(length, stream)
        else:
            raise ValueError(f"Invalid len value: {len}")
