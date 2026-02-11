"""Fistic classes for applying code mutation to binary files"""

from .core import NoFault
from .payload import PayloadInjection, RandomPayloadInjection
from .replacer import InstructionPayloads
from .replacer import InstructionReplacer, InstructionSkipper
from .bitflip import BitflipFaulter
