
from tests.greybox import PowerSchedule

class Paths:
    n = 0

    def add_path(self):
        pass

class PowerScheduleExponentialCutoff(PowerSchedule):
    M = 150000
    s0 = 0
    f0 = 1
    
    def assignEnergy(self), s_i, f_i:
        energy = min(alpha / * (s_i, f_i), M)
