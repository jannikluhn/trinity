from argparse import (
    ArgumentParser,
    _SubParsersAction,
)
import logging
from typing import (
    Tuple,
    TypeVar,
)

import async_service

from eth_keys.datatypes import (
    PrivateKey,
)

from lahja import EndpointAPI

from p2p.discv5.channel_services import (
    DatagramReceiver,
    DatagramSender,
    IncomingDatagram,
    IncomingMessage,
    IncomingPacket,
    OutgoingDatagram,
    OutgoingMessage,
    OutgoingPacket,
    PacketDecoder,
    PacketEncoder,
)
from p2p.discv5.endpoint_tracker import (
    EndpointTracker,
    EndpointVote,
)
from p2p.discv5.enr import ENR
from p2p.discv5.enr import UnsignedENR
from p2p.discv5.enr_db import MemoryEnrDb
from p2p.discv5.identity_schemes import default_identity_scheme_registry
from p2p.discv5.message_dispatcher import (
    MessageDispatcher,
)
from p2p.discv5.messages import default_message_type_registry
from p2p.discv5.packer import (
    Packer,
)
from p2p.discv5.routing_table import (
    FlatRoutingTable,
)
from p2p.discv5.routing_table_manager import (
    RoutingTableManager,
)

from trinity.boot_info import BootInfo
from trinity.extensibility import TrioIsolatedComponent

import trio
from trio.abc import (
    ReceiveChannel,
    SendChannel,
)


logger = logging.getLogger(__name__)

ChannelContentType = TypeVar("ChannelContentType")
ChannelPair = Tuple[SendChannel[ChannelContentType], ReceiveChannel[ChannelContentType]]


class DiscV5Component(TrioIsolatedComponent):
    name = "DiscV5"

    @classmethod
    def configure_parser(cls, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:
        arg_parser.add_argument(
            "--bootstrap-enr",
        )

    @property
    def is_enabled(self):
        return True

    @classmethod
    async def do_run(cls, boot_info: BootInfo, event_bus: EndpointAPI) -> None:
        identity_scheme_registry = default_identity_scheme_registry
        message_type_registry = default_message_type_registry

        host = "127.0.0.1"
        port = 9000

        local_private_key = b"\x11" * 32
        local_public_key = PrivateKey(local_private_key).public_key.to_compressed_bytes()
        local_enr = UnsignedENR(
            sequence_number=1,
            kv_pairs={
                b"id": b"v4",
                b"secp256k1": local_public_key,
                b"ip": b"\x7f\x00\x00\x01",
                b"udp": port,
            },
            identity_scheme_registry=identity_scheme_registry,
        ).to_signed_enr(local_private_key)
        local_node_id = local_enr.node_id

        routing_table = FlatRoutingTable()
        enr_db = MemoryEnrDb(default_identity_scheme_registry)
        await enr_db.insert(local_enr)

        if boot_info.args.bootstrap_enr:
            bootstrap_enr = ENR.from_repr(boot_info.args.bootstrap_enr)
            await enr_db.insert(bootstrap_enr)
            routing_table.add(bootstrap_enr.node_id)

        socket = trio.socket.socket(
            family=trio.socket.AF_INET,
            type=trio.socket.SOCK_DGRAM,
        )
        outgoing_datagram_channels: ChannelPair[OutgoingDatagram] = trio.open_memory_channel(0)
        incoming_datagram_channels: ChannelPair[IncomingDatagram] = trio.open_memory_channel(0)
        outgoing_packet_channels: ChannelPair[OutgoingPacket] = trio.open_memory_channel(0)
        incoming_packet_channels: ChannelPair[IncomingPacket] = trio.open_memory_channel(0)
        outgoing_message_channels: ChannelPair[OutgoingMessage] = trio.open_memory_channel(0)
        incoming_message_channels: ChannelPair[IncomingMessage] = trio.open_memory_channel(0)
        endpoint_vote_channels: ChannelPair[EndpointVote] = trio.open_memory_channel(0)

        datagram_sender = DatagramSender(
            outgoing_datagram_channels[1],
            socket,
        )
        datagram_receiver = DatagramReceiver(
            socket,
            incoming_datagram_channels[0],
        )

        packet_encoder = PacketEncoder(
            outgoing_packet_channels[1],
            outgoing_datagram_channels[0],
        )
        packet_decoder = PacketDecoder(
            incoming_datagram_channels[1],
            incoming_packet_channels[0],
        )

        packer = Packer(
            local_private_key=local_private_key,
            local_node_id=local_node_id,
            enr_db=enr_db,
            message_type_registry=message_type_registry,
            incoming_packet_receive_channel=incoming_packet_channels[1],
            incoming_message_send_channel=incoming_message_channels[0],
            outgoing_message_receive_channel=outgoing_message_channels[1],
            outgoing_packet_send_channel=outgoing_packet_channels[0],
        )

        message_dispatcher = MessageDispatcher(
            enr_db=enr_db,
            incoming_message_receive_channel=incoming_message_channels[1],
            outgoing_message_send_channel=outgoing_message_channels[0],
        )

        endpoint_tracker = EndpointTracker(
            local_private_key=local_private_key,
            local_node_id=local_node_id,
            enr_db=enr_db,
            identity_scheme_registry=identity_scheme_registry,
            vote_receive_channel=endpoint_vote_channels[1],
        )

        routing_table_manager = RoutingTableManager(
            local_node_id=local_node_id,
            routing_table=routing_table,
            message_dispatcher=message_dispatcher,
            enr_db=enr_db,
            outgoing_message_send_channel=outgoing_message_channels[0],
            endpoint_vote_send_channel=endpoint_vote_channels[0],
        )

        logger.info(f"Beginning discovery, listening on {host}:{port}")
        logger.info(f"Local ENR: {local_enr}")

        await socket.bind((host, port))
        services = (
            datagram_sender,
            datagram_receiver,
            packet_encoder,
            packet_decoder,
            packer,
            message_dispatcher,
            endpoint_tracker,
            routing_table_manager
        )
        async with trio.open_nursery() as nursery:
            for service in services:
                nursery.start_soon(async_service.TrioManager.run_service, service)
