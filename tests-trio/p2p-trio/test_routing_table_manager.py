import pytest

import pytest_trio

import rlp

import trio
from trio.testing import (
    wait_all_tasks_blocked,
)

from p2p.discv5.channel_services import (
    IncomingMessage,
)
from p2p.discv5.constants import (
    ROUTING_TABLE_BUCKET_SIZE,
    ROUTING_TABLE_PING_INTERVAL,
)
from p2p.discv5.enr_db import (
    MemoryEnrDb,
)
from p2p.discv5.identity_schemes import (
    default_identity_scheme_registry,
)
from p2p.discv5.messages import (
    FindNodeMessage,
    NodesMessage,
    PingMessage,
    PongMessage,
)
from p2p.discv5.message_dispatcher import (
    MessageDispatcher,
)
from p2p.discv5.routing_table import (
    compute_log_distance,
    KademliaRoutingTable,
)
from p2p.discv5.routing_table_manager import (
    FindNodeHandlerService,
    PingHandlerService,
    PingSenderService,
)

from p2p.tools.factories.discovery import (
    EndpointFactory,
    ENRFactory,
    FindNodeMessageFactory,
    IncomingMessageFactory,
    PingMessageFactory,
)

from p2p.trio_service import (
    background_service,
)

from p2p.trio_utils import (
    gather,
)


@pytest.fixture
def incoming_message_channels():
    return trio.open_memory_channel(0)


@pytest.fixture
def outgoing_message_channels():
    return trio.open_memory_channel(0)


@pytest.fixture
def endpoint_vote_channels():
    return trio.open_memory_channel(0)


@pytest.fixture
def local_enr():
    return ENRFactory()


@pytest.fixture
def remote_enr(remote_endpoint):
    return ENRFactory(
        custom_kv_pairs={
            b"ip": remote_endpoint.ip_address,
            b"udp": remote_endpoint.port,
        },
    )


@pytest.fixture
def remote_endpoint():
    return EndpointFactory()


@pytest.fixture
def routing_table(local_enr, remote_enr):
    routing_table = KademliaRoutingTable(local_enr.node_id, ROUTING_TABLE_BUCKET_SIZE)
    routing_table.update(remote_enr.node_id)
    return routing_table


@pytest_trio.trio_fixture
async def enr_db(local_enr, remote_enr):
    enr_db = MemoryEnrDb(default_identity_scheme_registry)
    await enr_db.insert(local_enr)
    await enr_db.insert(remote_enr)
    return enr_db


@pytest_trio.trio_fixture
async def message_dispatcher(enr_db, incoming_message_channels, outgoing_message_channels):
    message_dispatcher = MessageDispatcher(
        enr_db=enr_db,
        incoming_message_receive_channel=incoming_message_channels[1],
        outgoing_message_send_channel=outgoing_message_channels[0],
    )
    async with background_service(message_dispatcher):
        yield message_dispatcher


@pytest_trio.trio_fixture
async def ping_handler_service(local_enr,
                               routing_table,
                               message_dispatcher,
                               enr_db,
                               incoming_message_channels,
                               outgoing_message_channels):
    ping_handler_service = PingHandlerService(
        local_node_id=local_enr.node_id,
        routing_table=routing_table,
        message_dispatcher=message_dispatcher,
        enr_db=enr_db,
        outgoing_message_send_channel=outgoing_message_channels[0],
    )
    async with background_service(ping_handler_service):
        yield ping_handler_service


@pytest_trio.trio_fixture
async def find_node_handler_service(local_enr,
                                    routing_table,
                                    message_dispatcher,
                                    enr_db,
                                    incoming_message_channels,
                                    outgoing_message_channels,
                                    endpoint_vote_channels):
    find_node_handler_service = FindNodeHandlerService(
        local_node_id=local_enr.node_id,
        routing_table=routing_table,
        message_dispatcher=message_dispatcher,
        enr_db=enr_db,
        outgoing_message_send_channel=outgoing_message_channels[0],
    )
    async with background_service(find_node_handler_service):
        yield find_node_handler_service


@pytest_trio.trio_fixture
async def ping_sender_service(local_enr,
                              routing_table,
                              message_dispatcher,
                              enr_db,
                              incoming_message_channels,
                              endpoint_vote_channels):
    ping_sender_service = PingSenderService(
        local_node_id=local_enr.node_id,
        routing_table=routing_table,
        message_dispatcher=message_dispatcher,
        enr_db=enr_db,
        endpoint_vote_send_channel=endpoint_vote_channels[0],
    )
    async with background_service(ping_sender_service):
        yield ping_sender_service


@pytest.mark.trio
async def test_ping_handler_sends_pong(ping_handler_service,
                                       incoming_message_channels,
                                       outgoing_message_channels,
                                       local_enr):
    ping = PingMessageFactory()
    incoming_message = IncomingMessageFactory(message=ping)
    await incoming_message_channels[0].send(incoming_message)
    await wait_all_tasks_blocked()

    outgoing_message = outgoing_message_channels[1].receive_nowait()
    assert isinstance(outgoing_message.message, PongMessage)
    assert outgoing_message.message.request_id == ping.request_id
    assert outgoing_message.message.enr_seq == local_enr.sequence_number
    assert outgoing_message.receiver_endpoint == incoming_message.sender_endpoint
    assert outgoing_message.receiver_node_id == incoming_message.sender_node_id


@pytest.mark.trio
async def test_ping_handler_requests_updated_enr(ping_handler_service,
                                                 incoming_message_channels,
                                                 outgoing_message_channels,
                                                 local_enr,
                                                 remote_enr,
                                                 routing_table):
    ping = PingMessageFactory(enr_seq=remote_enr.sequence_number + 1)
    incoming_message = IncomingMessageFactory(message=ping)
    await incoming_message_channels[0].send(incoming_message)

    await wait_all_tasks_blocked()
    first_outgoing_message = outgoing_message_channels[1].receive_nowait()
    await wait_all_tasks_blocked()
    second_outgoing_message = outgoing_message_channels[1].receive_nowait()

    assert {
        first_outgoing_message.message.__class__,
        second_outgoing_message.message.__class__,
    } == {PongMessage, FindNodeMessage}

    outgoing_find_node = (
        first_outgoing_message if isinstance(first_outgoing_message.message, FindNodeMessage)
        else second_outgoing_message
    )

    assert outgoing_find_node.message.distance == 0
    assert outgoing_find_node.receiver_endpoint == incoming_message.sender_endpoint
    assert outgoing_find_node.receiver_node_id == incoming_message.sender_node_id


@pytest.mark.trio
async def test_find_node_handler_sends_local_enr(find_node_handler_service,
                                                 incoming_message_channels,
                                                 outgoing_message_channels,
                                                 local_enr):
    find_node = FindNodeMessageFactory(distance=0)
    incoming_message = IncomingMessageFactory(message=find_node)
    await incoming_message_channels[0].send(incoming_message)
    await wait_all_tasks_blocked()

    outgoing_message = outgoing_message_channels[1].receive_nowait()
    assert isinstance(outgoing_message.message, NodesMessage)
    assert outgoing_message.message.request_id == find_node.request_id
    assert outgoing_message.message.total == 1
    assert outgoing_message.message.enrs == (local_enr,)


@pytest.mark.trio
async def test_find_node_handler_sends_remote_enrs(find_node_handler_service,
                                                   routing_table,
                                                   enr_db,
                                                   incoming_message_channels,
                                                   outgoing_message_channels,
                                                   local_enr,
                                                   remote_enr):
    # fill the routing table and ENR db with some nodes at distance 255
    enrs_at_255 = []
    for _ in range(100):
        enr = ENRFactory()
        log_distance = compute_log_distance(enr.node_id, local_enr.node_id)
        if log_distance == 255:
            # 50% of all generated ENRs
            enrs_at_255.append(enr)

        await enr_db.insert(enr)
        routing_table.update(enr.node_id)

        if len(enrs_at_255) >= 3:
            break

    # query for node ids at distance 255
    find_node = FindNodeMessageFactory(distance=255)
    incoming_message = IncomingMessageFactory(message=find_node, sender_node_id=remote_enr.node_id)
    await incoming_message_channels[0].send(incoming_message)

    with trio.fail_after(1):
        outgoing_messages = await gather(
            *(outgoing_message_channels[1].receive,) * len(enrs_at_255),
        )

    for outgoing_message in outgoing_messages:
        assert isinstance(outgoing_message.message, NodesMessage)
        assert outgoing_message.message.request_id == find_node.request_id
        assert outgoing_message.message.total == len(enrs_at_255)

    sent_enrs = sorted(
        rlp.encode(enr)
        for outgoing_message in outgoing_messages
        for enr in outgoing_message.message.enrs
    )
    expected_sent_enrs = sorted(rlp.encode(enr) for enr in enrs_at_255)
    assert sent_enrs == expected_sent_enrs


@pytest.mark.trio
async def test_send_ping(ping_sender_service,
                         routing_table,
                         incoming_message_channels,
                         outgoing_message_channels,
                         local_enr,
                         remote_enr,
                         remote_endpoint):
    with trio.fail_after(ROUTING_TABLE_PING_INTERVAL):
        outgoing_message = await outgoing_message_channels[1].receive()

    assert isinstance(outgoing_message.message, PingMessage)
    assert outgoing_message.receiver_endpoint == remote_endpoint
    assert outgoing_message.receiver_node_id == remote_enr.node_id


@pytest.mark.trio
async def test_send_endpoint_vote(ping_sender_service,
                                  routing_table,
                                  incoming_message_channels,
                                  outgoing_message_channels,
                                  endpoint_vote_channels,
                                  local_enr,
                                  remote_enr,
                                  remote_endpoint):
    # wait for ping
    with trio.fail_after(ROUTING_TABLE_PING_INTERVAL):
        outgoing_message = await outgoing_message_channels[1].receive()
    ping = outgoing_message.message

    # respond with pong
    fake_local_endpoint = EndpointFactory()
    pong = PongMessage(
        request_id=ping.request_id,
        enr_seq=0,
        packet_ip=fake_local_endpoint.ip_address,
        packet_port=fake_local_endpoint.port,
    )
    incoming_message = IncomingMessage(
        message=pong,
        sender_endpoint=outgoing_message.receiver_endpoint,
        sender_node_id=outgoing_message.receiver_node_id,
    )
    await incoming_message_channels[0].send(incoming_message)
    await wait_all_tasks_blocked()

    # receive endpoint vote
    endpoint_vote = endpoint_vote_channels[1].receive_nowait()
    assert endpoint_vote.endpoint == fake_local_endpoint
    assert endpoint_vote.node_id == incoming_message.sender_node_id
