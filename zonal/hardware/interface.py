# zonal/hardware/interface.py
from abc import ABC, abstractmethod
from typing import Dict, Any

class Sensor(ABC):
    @abstractmethod
    def read(self) -> Dict[str, Any]:
        pass