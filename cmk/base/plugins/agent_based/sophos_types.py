# Helpers and utils
from datetime import datetime
from .agent_based_api.v1 import startswith
from typing import NamedTuple, Optional
from enum import Enum

DETECT_SophosX18 = startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.2604.5")
DETECT_SophosX17 = startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.21067")


class SophosHAState(Enum):
    notapplicable = 0
    auxiliary = 1
    standAlone = 2
    primary = 3,
    faulty = 4
    ready = 5


class SophosHAStatus(NamedTuple):
    HA_Status: int
    MasterSerialNumber: str
    PeerSerialNumber: str
    MasterHaState: SophosHAState
    PeerHaState: SophosHAState
    HA_Mode: str


class SophosInfo(NamedTuple):
    serialnumber: str
    model: str
    firmwareversion: str


class SophosSubscriptionStatusType(Enum):
    none = 0
    evaluating = 1
    notsubscribed = 2
    subscribed = 3
    expired = 4
    deactivated = 5


class SophosLicense(NamedTuple):
    LicenseLabel: str
    LicenseStatus: SophosSubscriptionStatusType
    LicenseExiprationDate: datetime

