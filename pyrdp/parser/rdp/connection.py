#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019, 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import struct
import typing
from io import BytesIO

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from pyrdp.core import decodeUTF16LE, encodeUTF16LE, StrictStream, Uint16LE, Uint32LE, Uint8
from pyrdp.enum import ColorDepth, ConnectionDataType, ConnectionType, DesktopOrientation, EncryptionLevel, \
    EncryptionMethod, HighColorDepth, RDPVersion, ServerCertificateType
from pyrdp.exceptions import ParsingError, UnknownPDUTypeError, ExploitError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import ClientChannelDefinition, ClientClusterData, ClientCoreData, ClientDataPDU, ClientNetworkData, \
    ClientSecurityData, ProprietaryCertificate, ServerCoreData, ServerDataPDU, ServerNetworkData, ServerSecurityData, \
    ServerMessageChannelData, ServerMultitransportData, ClientMonitorAttribute, ClientMonitorData, ClientMessageChannelData, \
    ClientMonitorExData, ClientMultitransportData, ClientUnused1Data


class ClientConnectionParser(Parser):
    """
    Parser for Client Data PDUs (i.e: servers).
    """
    def __init__(self):
        super().__init__()

        self.parsers = {
            ConnectionDataType.CLIENT_CORE: self.parseClientCoreData,
            ConnectionDataType.CLIENT_SECURITY: self.parseClientSecurityData,
            ConnectionDataType.CLIENT_NETWORK: self.parseClientNetworkData,
            ConnectionDataType.CLIENT_CLUSTER: self.parseClientClusterData,
            ConnectionDataType.CLIENT_MONITOR: self.parseClientMonitorData,
            ConnectionDataType.CLIENT_MSGCHANNEL: self.parseClientMessageChannelData,
            ConnectionDataType.CLIENT_MONITOR_EX: self.parseClientMonitorExData,
            ConnectionDataType.CLIENT_MULTITRANSPORT: self.parseClientMultitransportData,
            ConnectionDataType.CLIENT_UNUSED1: self.parseClientUnused1Data,
        }

        self.writers = {
            ConnectionDataType.CLIENT_CORE: self.writeClientCoreData,
            ConnectionDataType.CLIENT_SECURITY: self.writeClientSecurityData,
            ConnectionDataType.CLIENT_NETWORK: self.writeClientNetworkData,
            ConnectionDataType.CLIENT_CLUSTER: self.writeClientClusterData,
            ConnectionDataType.CLIENT_MONITOR: self.writeClientMonitorData,
            ConnectionDataType.CLIENT_MSGCHANNEL: self.writeClientMessageChannelData,
            ConnectionDataType.CLIENT_MONITOR_EX: self.writeClientMonitorExData,
            ConnectionDataType.CLIENT_MULTITRANSPORT: self.writeClientMultitransportData,
            ConnectionDataType.CLIENT_UNUSED1: self.writeClientUnused1Data,
        }

    def doParse(self, data: bytes) -> ClientDataPDU:
        """
        Decode a Client Data PDU from bytes.
        :param data: Client Data PDU data.
        """
        core = None
        security = None
        network = None
        cluster = None
        monitor = None
        messageChannel = None
        monitorEx = None
        multitransport = None
        unused1 = None

        stream = BytesIO(data)
        while stream.tell() != len(stream.getvalue()) and (core is None or security is None or network is None or cluster is None):
            structure = self.parseStructure(stream)

            if structure.header == ConnectionDataType.CLIENT_CORE:
                core = structure
            elif structure.header == ConnectionDataType.CLIENT_SECURITY:
                security = structure
            elif structure.header == ConnectionDataType.CLIENT_NETWORK:
                network = structure
            elif structure.header == ConnectionDataType.CLIENT_CLUSTER:
                cluster = structure
            elif structure.header == ConnectionDataType.CLIENT_MONITOR:
                monitor = structure
            elif structure.header == ConnectionDataType.CLIENT_MSGCHANNEL:
                messageChannel = structure
            elif structure.header == ConnectionDataType.CLIENT_MONITOR_EX:
                monitorEx = structure
            elif structure.header == ConnectionDataType.CLIENT_MULTITRANSPORT:
                multitransport = structure
            elif structure.header == ConnectionDataType.CLIENT_UNUSED1:
                unused1 = structure

            if len(stream.getvalue()) == 0:
                break

        return ClientDataPDU(core, security, network, cluster, monitor, messageChannel, monitorEx, multitransport, unused1)

    def parseStructure(self, stream: BytesIO) -> typing.Union[ClientCoreData, ClientNetworkData, ClientSecurityData, ClientClusterData]:
        header = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream) - 4
        data = stream.read(length)

        if len(data) != length:
            raise ParsingError("Client Data length field does not match actual size")

        substream = BytesIO(data)

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown client data structure %s" % header, header)

        return self.parsers[header](substream)

    def parseClientCoreData(self, stream: BytesIO) -> ClientCoreData:
        stream = StrictStream(stream)

        # 128 bytes minimum (excluding header)
        version = RDPVersion(Uint32LE.unpack(stream))
        desktopWidth = Uint16LE.unpack(stream)
        desktopHeight = Uint16LE.unpack(stream)
        colorDepth = ColorDepth(Uint16LE.unpack(stream))
        sasSequence = Uint16LE.unpack(stream)
        keyboardLayout = Uint32LE.unpack(stream)
        clientBuild = Uint32LE.unpack(stream)
        clientName = decodeUTF16LE(stream.read(32))
        keyboardType = Uint32LE.unpack(stream)
        keyboardSubType = Uint32LE.unpack(stream)
        keyboardFunctionKey = Uint32LE.unpack(stream)
        imeFileName = stream.read(64)

        core = ClientCoreData(version, desktopWidth, desktopHeight, colorDepth, sasSequence, keyboardLayout, clientBuild, clientName, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName)

        # Optional data
        # The optional fields are read in order. If one of them is not present, then all subsequent fields are also not present.
        try:
            core.postBeta2ColorDepth = Uint16LE.unpack(stream)
            core.clientProductId = Uint16LE.unpack(stream)
            core.serialNumber = Uint32LE.unpack(stream)

            # Should match HighColorDepth enum most of the time, but in order to support scanners and we script, we have to loosely accept this one
            # Anyway, the server will reject it and enforce another one
            core.highColorDepth = Uint16LE.unpack(stream)
            core.supportedColorDepths = Uint16LE.unpack(stream)
            core.earlyCapabilityFlags = Uint16LE.unpack(stream)
            core.clientDigProductId = decodeUTF16LE(stream.read(64))
            core.connectionType = ConnectionType(Uint8.unpack(stream))
            stream.read(1)
            core.serverSelectedProtocol = Uint32LE.unpack(stream)
            core.desktopPhysicalWidth = Uint32LE.unpack(stream)
            core.desktopPhysicalHeight = Uint32LE.unpack(stream)
            core.desktopOrientation = DesktopOrientation(Uint16LE.unpack(stream))
            core.desktopScaleFactor = Uint32LE.unpack(stream)
            core.deviceScaleFactor = Uint32LE.unpack(stream)
        except EOFError:
            # The stream has reached the end, we don't have any more optional fields. This exception can be ignored.
            pass

        return core

    def parseClientSecurityData(self, stream: BytesIO) -> ClientSecurityData:
        encryptionMethods = Uint32LE.unpack(stream)
        extEncryptionMethods = Uint32LE.unpack(stream)
        return ClientSecurityData(encryptionMethods, extEncryptionMethods)

    def detectBlueKeepScan(self, data: bytes):
        return b"MS_T120" in data.upper()

    def parseClientNetworkData(self, stream: BytesIO) -> ClientNetworkData:
        if self.detectBlueKeepScan(stream.getvalue()):
            raise ExploitError("BlueKeep scan or exploit attempted")

        channelCount = Uint32LE.unpack(stream)
        data = stream.getvalue()[4 :]

        if len(data) != channelCount * 12:
            raise ParsingError("Invalid channel array size")

        channelDefinitions = []

        for _ in range(channelCount):
            name = stream.read(8).strip(b"\x00").decode()
            options = Uint32LE.unpack(stream)
            channelDefinitions.append(ClientChannelDefinition(name, options))

        return ClientNetworkData(channelDefinitions)

    def parseClientClusterData(self, stream: BytesIO) -> ClientClusterData:
        flags = Uint32LE.unpack(stream)
        redirectedSessionID = Uint32LE.unpack(stream)
        return ClientClusterData(flags, redirectedSessionID)

    def parseClientMonitorAttribute(self, stream: BytesIO) -> ClientMonitorAttribute:
        physicalWidth = Uint32LE.unpack(stream)
        physicalHeight = Uint32LE.unpack(stream)
        orientation = Uint32LE.unpack(stream)
        desktopScaleFactor = Uint32LE.unpack(stream)
        deviceScaleFactor = Uint32LE.unpack(stream)
        return ClientMonitorAttribute(physicalWidth, physicalHeight, orientation, desktopScaleFactor, deviceScaleFactor)

    def parseClientMonitorData(self, stream: BytesIO) -> ClientMonitorData:
        flags = Uint32LE.unpack(stream)
        monitorAttributeSize = Uint32LE.unpack(stream)
        monitorCount = Uint32LE.unpack(stream)

        monitorAttributes = []

        for _ in range(monitorCount):
            monitorAttributes.append(self.parseClientMonitorAttribute(stream))

        return ClientMonitorData(flags, monitorAttributeSize, monitorCount, monitorAttributes)

    def parseClientMessageChannelData(self, stream: BytesIO) -> ClientMessageChannelData:
        flags = Uint32LE.unpack(stream)
        return ClientMessageChannelData(flags)

    def parseClientMonitorExData(self, stream: BytesIO) -> ClientMonitorExData:
        flags = Uint32LE.unpack(stream)
        monitorAttributeSize = Uint32LE.unpack(stream)
        monitorCount = Uint32LE.unpack(stream)

        monitorAttributes = []

        for _ in range(monitorCount):
            monitorAttributes.append(self.parseClientMonitorAttribute(stream))

        return ClientMonitorExData(flags, monitorAttributeSize, monitorCount, monitorAttributes)

    def parseClientMultitransportData(self, stream: BytesIO) -> ClientMultitransportData:
        flags = Uint32LE.unpack(stream)
        return ClientMultitransportData(flags)
    
    def parseClientUnused1Data(self, stream: BytesIO) -> ClientUnused1Data:
        pad2Octets = Uint16LE.unpack(stream)
        return ClientUnused1Data(pad2Octets)

    def write(self, pdu: ClientDataPDU) -> bytes:
        """
        Encode a Client Data PDU to bytes.
        :param pdu: the Client Data PDU
        """
        stream = BytesIO()

        if pdu.coreData:
            self.writeStructure(stream, pdu.coreData)

        if pdu.securityData:
            self.writeStructure(stream, pdu.securityData)

        if pdu.networkData:
            self.writeStructure(stream, pdu.networkData)

        if pdu.clusterData:
            self.writeStructure(stream, pdu.clusterData)

        if pdu.monitorData:
            self.writeStructure(stream, pdu.monitorData)

        if pdu.messageChannelData:
            self.writeStructure(stream, pdu.messageChannelData)

        if pdu.monitorExData:
            self.writeStructure(stream, pdu.monitorExData)

        if pdu.multitransportData:
            self.writeStructure(stream, pdu.multitransportData)

        if pdu.unused1Data:
            self.writeStructure(stream, pdu.unused1Data)

        return stream.getvalue()

    def writeStructure(self, stream: BytesIO, data: typing.Union[ClientCoreData, ClientNetworkData, ClientSecurityData, ClientClusterData, ClientMonitorData, ClientMessageChannelData, ClientMonitorExData, ClientMultitransportData, ClientUnused1Data]):
        if data.header not in self.writers:
            raise UnknownPDUTypeError("Trying to write unknown Client Data structure %s" % data.header, data.header)

        substream = BytesIO()
        self.writers[data.header](substream, data)

        substream = substream.getvalue()

        stream.write(Uint16LE.pack(data.header))
        stream.write(Uint16LE.pack(len(substream) + 4))
        stream.write(substream)

    def writeClientCoreData(self, stream: BytesIO, core: ClientCoreData):
        stream.write(Uint32LE.pack(core.version))
        stream.write(Uint16LE.pack(core.desktopWidth))
        stream.write(Uint16LE.pack(core.desktopHeight))
        stream.write(Uint16LE.pack(core.colorDepth))
        stream.write(Uint16LE.pack(core.sasSequence))
        stream.write(Uint32LE.pack(core.keyboardLayout))
        stream.write(Uint32LE.pack(core.clientBuild))
        stream.write(encodeUTF16LE(core.clientName).ljust(32, b"\x00")[: 32])
        stream.write(Uint32LE.pack(core.keyboardType))
        stream.write(Uint32LE.pack(core.keyboardSubType))
        stream.write(Uint32LE.pack(core.keyboardFunctionKey))
        stream.write(core.imeFileName)

        try:
            stream.write(Uint16LE.pack(core.postBeta2ColorDepth))
            stream.write(Uint16LE.pack(core.clientProductId))
            stream.write(Uint32LE.pack(core.serialNumber))
            stream.write(Uint16LE.pack(core.highColorDepth))
            stream.write(Uint16LE.pack(core.supportedColorDepths))
            stream.write(Uint16LE.pack(core.earlyCapabilityFlags))
            stream.write(encodeUTF16LE(core.clientDigProductId).ljust(64, b"\x00")[: 64])
            stream.write(Uint8.pack(core.connectionType))
            stream.write(b"\x00")
            stream.write(Uint32LE.pack(core.serverSelectedProtocol))
            stream.write(Uint32LE.pack(core.desktopPhysicalWidth))
            stream.write(Uint32LE.pack(core.desktopPhysicalHeight))
            stream.write(Uint16LE.pack(core.desktopOrientation))
            stream.write(Uint32LE.pack(core.desktopScaleFactor))
            stream.write(Uint32LE.pack(core.deviceScaleFactor))
        except struct.error:
            # We tried to write an optional field which was not present. Stop writing beyond this point.
            pass

    def writeClientSecurityData(self, stream: BytesIO, security: ClientSecurityData):
        stream.write(Uint32LE.pack(security.encryptionMethods))
        stream.write(Uint32LE.pack(security.extEncryptionMethods))

    def writeClientNetworkData(self, stream: BytesIO, network: ClientNetworkData):
        stream.write(Uint32LE.pack(len(network.channelDefinitions)))

        for channel in network.channelDefinitions:
            if len(channel.name) > 8:
                raise ParsingError("Channel name must have 8 characters maximum")

            stream.write(channel.name.encode().ljust(8, b"\x00")[: 8])
            stream.write(Uint32LE.pack(channel.options))

    def writeClientClusterData(self, stream: BytesIO, cluster: ClientClusterData):
        stream.write(Uint32LE.pack(cluster.flags))
        stream.write(Uint32LE.pack(cluster.redirectedSessionID))

    def writeClientMonitorAttribute(self, stream: BytesIO, monitorAttribute: ClientMonitorAttribute):
        stream.write(Uint32LE.pack(monitorAttribute.physicalWidth))
        stream.write(Uint32LE.pack(monitorAttribute.physicalHeight))
        stream.write(Uint32LE.pack(monitorAttribute.orientation))
        stream.write(Uint32LE.pack(monitorAttribute.desktopScaleFactor))
        stream.write(Uint32LE.pack(monitorAttribute.deviceScaleFactor))

    def writeClientMonitorData(self, stream: BytesIO, monitor: ClientMonitorData):
        stream.write(Uint32LE.pack(monitor.flags))
        stream.write(Uint32LE.pack(monitor.monitorAttributeSize))
        stream.write(Uint32LE.pack(monitor.monitorCount))
        for monitorAttribute in monitor.monitorAttributes:
            self.writeClientMonitorAttribute(stream, monitorAttribute)

    def writeClientMessageChannelData(self, stream: BytesIO, messageChannel: ClientMessageChannelData):
        stream.write(Uint32LE.pack(messageChannel.flags))

    def writeClientMonitorExData(self, stream: BytesIO, monitorEx: ClientMonitorExData):
        stream.write(Uint32LE.pack(monitorEx.flags))
        stream.write(Uint32LE.pack(monitorEx.monitorAttributeSize))
        stream.write(Uint32LE.pack(monitorEx.monitorCount))
        for monitorAttribute in monitorEx.monitorAttributes:
            self.writeClientMonitorAttribute(stream, monitorAttribute)

    def writeClientMultitransportData(self, stream: BytesIO, multitransport: ClientMultitransportData):
        stream.write(Uint32LE.pack(multitransport.flags))

    def writeClientUnused1Data(self, stream: BytesIO, unused1: ClientUnused1Data):
        stream.write(Uint16LE.pack(unused1.pad2Octets))

class ServerConnectionParser(Parser):
    """
    Parser for Server Data PDUs (i.e: client).
    """

    def __init__(self):
        super().__init__()
        self.parsers = {
            ConnectionDataType.SERVER_CORE: self.parseServerCoreData,
            ConnectionDataType.SERVER_NETWORK: self.parseServerNetworkData,
            ConnectionDataType.SERVER_SECURITY: self.parseServerSecurityData,
            ConnectionDataType.SERVER_MSGCHANNEL: self.parseServerMessageChannelData,
            ConnectionDataType.SERVER_MULTITRANSPORT: self.parseServerMultitransportData,
        }

        self.writers = {
            ConnectionDataType.SERVER_CORE: self.writeServerCoreData,
            ConnectionDataType.SERVER_NETWORK: self.writeServerNetworkData,
            ConnectionDataType.SERVER_SECURITY: self.writeServerSecurityData,
            ConnectionDataType.SERVER_MSGCHANNEL: self.writeServerMessageChannelData,
            ConnectionDataType.SERVER_MULTITRANSPORT: self.writeServerMultitransportData,
        }

    def doParse(self, data: bytes) -> ServerDataPDU:
        """
        Parse a Server Data PDU from bytes.
        """
        core = None
        security = None
        network = None
        messageChannel = None
        multitransport = None

        stream = BytesIO(data)
        while core is None or security is None or network is None:
            structure = self.parseStructure(stream)

            if structure.header == ConnectionDataType.SERVER_CORE:
                core = structure
            elif structure.header == ConnectionDataType.SERVER_SECURITY:
                security = structure
            elif structure.header == ConnectionDataType.SERVER_NETWORK:
                network = structure
            elif structure.header == ConnectionDataType.SERVER_MSGCHANNEL:
                messageChannel = structure
            elif structure.header == ConnectionDataType.SERVER_MULTITRANSPORT:
                multitransport = structure
            else:
                raise UnknownPDUTypeError("Trying to parse unknown server data structure %s" % structure.header, structure.header)

            if len(stream.getvalue()) == 0:
                break

        return ServerDataPDU(core, security, network, messageChannel, multitransport)

    def parseStructure(self, stream: BytesIO) -> typing.Union[ServerCoreData, ServerSecurityData, ServerNetworkData]:
        header = Uint16LE.unpack(stream)
        length = Uint16LE.unpack(stream) - 4
        data = stream.read(length)

        if len(data) < length:
            raise ParsingError("Server Data length field does not match actual size")

        substream = BytesIO(data)

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown server data structure %s" % header, header)

        return self.parsers[header](substream)

    def parseServerCoreData(self, stream: BytesIO) -> ServerCoreData:
        stream = StrictStream(stream)

        clientRequestedProtocols = None
        earlyCapabilityFlags = None
        version = Uint32LE.unpack(stream)

        try:
            clientRequestedProtocols = Uint32LE.unpack(stream)
            earlyCapabilityFlags = Uint32LE.unpack(stream)
        except EOFError:
            pass

        return ServerCoreData(version, clientRequestedProtocols, earlyCapabilityFlags)

    def parseServerNetworkData(self, stream: BytesIO) -> ServerNetworkData:
        mcsChannelID = Uint16LE.unpack(stream)
        channelCount = Uint16LE.unpack(stream)
        channels = [Uint16LE.unpack(stream) for _ in range(channelCount)]

        return ServerNetworkData(mcsChannelID, channels)

    def parseServerSecurityData(self, stream: BytesIO) -> ServerSecurityData:
        stream = StrictStream(stream)
        encryptionMethod = EncryptionMethod(Uint32LE.unpack(stream))
        encryptionLevel = EncryptionLevel(Uint32LE.unpack(stream))
        serverRandom = None
        serverCertificate = None

        try:
            serverRandomLength = Uint32LE.unpack(stream)
            serverCertificateLength = Uint32LE.unpack(stream)
            serverRandom = stream.read(serverRandomLength)
            serverCertificate = stream.read(serverCertificateLength)
            serverCertificate = self.parseServerCertificate(serverCertificate)
        except EOFError:
            pass

        return ServerSecurityData(encryptionMethod, encryptionLevel, serverRandom, serverCertificate)
    
    def parseServerMessageChannelData(self, stream: BytesIO) -> ServerMessageChannelData:
        stream = StrictStream(stream)
        channelId = Uint16LE.unpack(stream)
        return ServerMessageChannelData(channelId)
    
    def parseServerMultitransportData(self, stream: BytesIO) -> ServerMultitransportData:
        stream = StrictStream(stream)
        flags = Uint32LE.unpack(stream)
        return ServerMultitransportData(flags)

    def parseServerCertificate(self, data: bytes) -> ProprietaryCertificate:
        stream = BytesIO(data)
        version = Uint32LE.unpack(stream)

        if version == ServerCertificateType.PROPRIETARY:
            return self.parseProprietaryCertificate(stream)
        else:
            raise NotImplementedError("Unhandled certificate type")

    def parseProprietaryCertificate(self, stream: BytesIO) -> ProprietaryCertificate:
        signatureAlgorithmID = Uint32LE.unpack(stream)
        keyAlgorithmID = Uint32LE.unpack(stream)
        publicKeyType = Uint16LE.unpack(stream)
        keyLength = Uint16LE.unpack(stream)
        publicKey = stream.read(keyLength)
        signatureType = Uint16LE.unpack(stream)
        signatureLength = Uint16LE.unpack(stream)
        signature = stream.read(signatureLength - 8)
        padding = stream.read()

        publicKey = self.parsePublicKey(publicKey)

        return ProprietaryCertificate(signatureAlgorithmID, keyAlgorithmID, publicKeyType, publicKey, signatureType, signature, padding)

    def parsePublicKey(self, data: bytes) -> RSA.RsaKey:
        stream = BytesIO(data)
        _magic = stream.read(4)
        keyLength = Uint32LE.unpack(stream)
        _bitLength = Uint32LE.unpack(stream)
        _dataLength = Uint32LE.unpack(stream)
        publicExponent = Uint32LE.unpack(stream)
        modulus = stream.read(keyLength - 8)
        _padding = stream.read(8)

        # Modulus must be reversed because bytes_to_long expects it to be in big endian format
        modulus = bytes_to_long(modulus[:: -1])
        publicExponent = int(publicExponent)
        publicKey = RSA.construct((modulus, publicExponent))
        return publicKey

    def write(self, pdu: ServerDataPDU) -> bytes:
        """
        Encode a Server Data PDU to bytes
        :param pdu: the Server Data PDU
        """
        stream = BytesIO()

        if pdu.coreData:
            self.writeStructure(stream, pdu.coreData)

        if pdu.securityData:
            self.writeStructure(stream, pdu.securityData)

        if pdu.networkData:
            self.writeStructure(stream, pdu.networkData)

        if pdu.messageChannelData:
            self.writeStructure(stream, pdu.messageChannelData)

        if pdu.multitransportData:
            self.writeStructure(stream, pdu.multitransportData)

        return stream.getvalue()

    def writeStructure(self, stream: BytesIO, data: typing.Union[ServerCoreData, ServerSecurityData, ServerNetworkData]):
        """
        :param stream: BytesIO to write to
        :param data: The structure to write (ex: ServerCoreData)
        """
        if data.header not in self.writers:
            raise UnknownPDUTypeError("Trying to write unknown Server Data structure %s" % data.header, data.header)

        substream = BytesIO()
        self.writers[data.header](substream, data)

        substream = substream.getvalue()

        stream.write(Uint16LE.pack(data.header))
        stream.write(Uint16LE.pack(len(substream) + 4))
        stream.write(substream)

    def writeServerCoreData(self, stream: BytesIO, data: ServerCoreData):
        stream.write(Uint32LE.pack(data.version))

        requestedProtocols = data.clientRequestedProtocols

        if requestedProtocols is None:
            requestedProtocols = 0

        stream.write(Uint32LE.pack(requestedProtocols))

        if data.earlyCapabilityFlags is not None:
            stream.write(Uint32LE.pack(data.earlyCapabilityFlags))

    def writeServerNetworkData(self, stream: BytesIO, data: ServerNetworkData):
        """
        https://msdn.microsoft.com/en-us/library/cc240522.aspx
        """
        stream.write(Uint16LE.pack(data.mcsChannelID))
        stream.write(Uint16LE.pack(len(data.channels)))

        for channel in data.channels:
            stream.write(Uint16LE.pack(channel))

        if len(data.channels) % 2 != 0:
            stream.write(Uint16LE.pack(0))  # Write 2 empty bytes so we keep a multiple of 4.

    def writeServerSecurityData(self, stream: BytesIO, data: ServerSecurityData):
        stream.write(Uint32LE.pack(data.encryptionMethod))
        stream.write(Uint32LE.pack(data.encryptionLevel))
        if data.serverRandom is not None:
            serverCertificate = self.writeServerCertificate(data.serverCertificate)

            stream.write(Uint32LE.pack(len(data.serverRandom)))
            stream.write(Uint32LE.pack(len(serverCertificate)))
            stream.write(data.serverRandom)
            stream.write(serverCertificate)

    def writeServerMessageChannelData(self, stream: BytesIO, data: ServerMessageChannelData):
        stream.write(Uint16LE.pack(data.channelId))

    def writeServerMultitransportData(self, stream: BytesIO, data: ServerMultitransportData):
        stream.write(Uint32LE.pack(data.flags))

    def writeServerCertificate(self, certificate: ProprietaryCertificate) -> bytes:
        stream = BytesIO()

        if certificate.type == ServerCertificateType.PROPRIETARY:
            Uint32LE.pack(ServerCertificateType.PROPRIETARY, stream)
            self.writeProprietaryCertificate(stream, certificate)
        else:
            raise NotImplementedError("Unhandled certificate type")

        return stream.getvalue()

    def writeProprietaryCertificate(self, stream: BytesIO, cert: ProprietaryCertificate):
        keyBytes = self.writePublicKey(cert.publicKey)

        Uint32LE.pack(cert.signatureAlgorithmID, stream)
        Uint32LE.pack(cert.keyAlgorithmID, stream)
        Uint16LE.pack(cert.publicKeyType, stream)
        Uint16LE.pack(len(keyBytes), stream)
        stream.write(keyBytes)
        Uint16LE.pack(cert.signatureType, stream)
        Uint16LE.pack(len(cert.signature) + 8, stream)
        stream.write(cert.signature)
        stream.write(b"\x00" * 8)

    def writePublicKey(self, publicKey: RSA.RsaKey) -> bytes:
        modulus = publicKey.n
        publicExponent = publicKey.e

        # Modulus must be reversed because bytes_to_long expects it to be in big endian format
        modulusBytes = long_to_bytes(modulus)[:: -1]

        stream = BytesIO()
        stream.write(b"RSA1")
        Uint32LE.pack(len(modulusBytes) + 8, stream)
        Uint32LE.pack(2048, stream)
        Uint32LE.pack(255, stream)
        Uint32LE.pack(publicExponent, stream)
        stream.write(modulusBytes)
        stream.write(b"\x00" * 8)
        return stream.getvalue()
