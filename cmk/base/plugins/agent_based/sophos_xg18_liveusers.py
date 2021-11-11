#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2021 Alexander Kiko - a.kiko@redhouse.de - redhhouse GmbH - License: GNU General Public License v2
# this one is super simple
# Relevant OIDs
#.1.3.6.1.4.1.2604.5.1.2.6.0 0 --> SFOS-FIREWALL-MIB::sfosLiveUsersCount.0

from typing import Optional
from .sophos_types import DETECT_SophosX18

from .agent_based_api.v1 import register, SNMPTree, Service, Result, State, check_levels
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, StringTable

def parse_sophos_liveuser(string_table: StringTable) -> Optional[int]:
    return int(string_table[0][0])

register.snmp_section(
    name = "sophos_xg18_liveusers",
    detect = DETECT_SophosX18,
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.2604.5.1.2.6',
        oids = [
            "0" # --> SFOS-FIREWALL-MIB::sfosLiveUsersCount.0
        ],
    ),
    parse_function = parse_sophos_liveuser
)


def discover_sophos_liveusers(section: int) -> DiscoveryResult:
    yield Service()


def check_sophos_liveusers(section: int) -> CheckResult:
    yield Result(
    state=State.OK,
    summary=f"Current Live Users: {section}"
    )

    yield from check_levels(
        value=section,
        metric_name="sophos_live_users",
        notice_only=True
    )



register.check_plugin(
    name="sophos_xg18_liveusers",
    service_name="SOPHOS Live Users",
    discovery_function=discover_sophos_liveusers,
    check_function=check_sophos_liveusers
)
