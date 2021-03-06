from eth import constants

from eth.vm.computation import BaseComputation


def blockhash(computation: BaseComputation) -> None:
    block_number = computation.stack_pop(type_hint=constants.UINT256)

    block_hash = computation.state.get_ancestor_hash(block_number)

    computation.stack_push(block_hash)


def coinbase(computation: BaseComputation) -> None:
    computation.stack_push(computation.state.coinbase)


def timestamp(computation: BaseComputation) -> None:
    computation.stack_push(computation.state.timestamp)


def number(computation: BaseComputation) -> None:
    computation.stack_push(computation.state.block_number)


def difficulty(computation: BaseComputation) -> None:
    computation.stack_push(computation.state.difficulty)


def gaslimit(computation: BaseComputation) -> None:
    computation.stack_push(computation.state.gas_limit)
