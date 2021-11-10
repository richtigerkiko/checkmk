#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2021 Alexander Kiko - redhhouse GmbH - License: GNU General Public License v2
# Relevant OIDs
# .1.3.6.1.4.1.2604.5.1.4.1.0 1 --> SFOS-FIREWALL-MIB::sfosHAStatus.0
# .1.3.6.1.4.1.2604.5.1.4.2.0 X2100469P9848F4 --> SFOS-FIREWALL-MIB::sfosDeviceCurrentAppKey.0
# .1.3.6.1.4.1.2604.5.1.4.3.0 X2100467J93JTF3 --> SFOS-FIREWALL-MIB::sfosDevicePeerAppKey.0
# .1.3.6.1.4.1.2604.5.1.4.4.0 2 --> SFOS-FIREWALL-MIB::sfosDeviceCurrentHAState.0
# .1.3.6.1.4.1.2604.5.1.4.5.0 4 --> SFOS-FIREWALL-MIB::sfosDevicePeerHAState.0
# .1.3.6.1.4.1.2604.5.1.4.6.0 Active-Passive --> SFOS-FIREWALL-MIB::sfosDeviceHAConfigMode.0
# .1.3.6.1.4.1.2604.5.1.4.7.0 0 --> SFOS-FIREWALL-MIB::sfosDeviceLoadBalancing.0
# .1.3.6.1.4.1.2604.5.1.4.8.0 Port8 --> SFOS-FIREWALL-MIB::sfosDeviceHAPort.0
# .1.3.6.1.4.1.2604.5.1.4.9.0 169.254.192.1 --> SFOS-FIREWALL-MIB::sfosDeviceHACurrentIP.0
# .1.3.6.1.4.1.2604.5.1.4.10.0 169.254.192.2 --> SFOS-FIREWALL-MIB::sfosDeviceHAPeerIP.0
# .1.3.6.1.4.1.2604.5.1.4.11.1.0 Port1 --> SFOS-FIREWALL-MIB::sfosDeviceAuxAdminPort.0
# .1.3.6.1.4.1.2604.5.1.4.11.2.0 10.0.200.2 --> SFOS-FIREWALL-MIB::sfosDeviceHAAuxAdminIP.0

from typing import Optional
from .sophos_types import DETECT_SophosX18, SophosHAState, SophosHAStatus

from .agent_based_api.v1 import register, SNMPTree, equals, all_of, startswith, not_equals, Service, Result, State, HostLabel, Metric, check_levels
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, InventoryResult, StringTable, HostLabelGenerator


DETECT = all_of(
    DETECT_SophosX18,
    equals(".1.3.6.1.4.1.2604.5.1.4.1.0", "1")
)


def _parse_string(val):
    return val.strip().replace("\r\n", " ").replace("\n", " ")


def parse_sophos_hainfo(string_table: StringTable) -> Optional[SophosHAStatus]:
    if not string_table:
        return None
    sophos_hastatus = [_parse_string(s) for s in string_table[0]]
    sophos_hastatus[3] = SophosHAState(int(sophos_hastatus[3]))
    sophos_hastatus[4] = SophosHAState(int(sophos_hastatus[4]))
    return SophosHAStatus(*sophos_hastatus)


def host_label_function_sophos(section: SophosHAStatus) -> HostLabelGenerator:
    yield HostLabel("sophos", "HA_Cluster")

register.snmp_section(
    name = "sophos_xg18_hastatus",
    detect = DETECT,
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.2604.5.1.4',
        oids = [
            "1.0", # SFOS-FIREWALL-MIB::sfosHAStatus.0
            "2.0", # SFOS-FIREWALL-MIB::sfosDeviceCurrentAppKey.0
            "3.0", # SFOS-FIREWALL-MIB::sfosDevicePeerAppKey.0
            "4.0", # SFOS-FIREWALL-MIB::sfosDeviceCurrentHAState.0
            "5.0", # SFOS-FIREWALL-MIB::sfosDevicePeerHAState.0
            "6.0"  # SFOS-FIREWALL-MIB::sfosDeviceHAConfigMode.0
        ],
    ),
    host_label_function=host_label_function_sophos,
    parse_function = parse_sophos_hainfo
)


def discover_sophos_hastatus(section: SophosHAStatus) -> DiscoveryResult:
    yield Service()


def check_sophos_hastatus(section: SophosHAStatus) -> CheckResult:
    yield from check_levels(
        value=section.MasterHaState.value,
        metric_name="ha_status",
        boundaries=(0, 5)
    )
    if(section.MasterHaState != SophosHAState.primary):
        yield Result(
            state=State.CRIT,
            summary=f"HA Status: {section.MasterHaState.name}. Aux Device is {section.PeerHaState.name}",
            details=f"Active Firewall is: {section.MasterSerialNumber}"
        )
    else:
        yield Result(
        state=State.OK,
        summary=f"HA-Info: Active Firewall {section.MasterSerialNumber}, Current Primare-State {section.MasterHaState.name}"
        )

register.check_plugin(
    name="sophos_xg18_hastatus",
    service_name="SOPHOS HA Status",
    discovery_function=discover_sophos_hastatus,
    check_function=check_sophos_hastatus
)
