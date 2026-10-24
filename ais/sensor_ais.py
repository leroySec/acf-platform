#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ais.ais_engine import AISEngine
from ais.risk_functions import risk_from_sensor

if __name__ == "__main__":
    engine = AISEngine(
        capability="sensor",
        monitor_section="layer_1_sensor_ext",
        ais_section="layer_2_ais_sensor",
        risk_func=risk_from_sensor
    )
    engine.run()