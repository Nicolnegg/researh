"""Fistic: fault injection simulator via code mutation"""

from .core import FisticOptions, Articulator
from .mapper import Mapper, MapperFromMap

from .core import Placers as __Placers
from .core import Faulters as __Faulters
from .core import Evaluators as __Evaluators
PlacerKeys = __Placers.keys()
FaulterKeys = __Faulters.keys()
EvaluatorKeys = __Evaluators.keys()
