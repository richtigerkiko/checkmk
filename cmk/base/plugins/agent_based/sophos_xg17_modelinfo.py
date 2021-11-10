#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2021 Alexander Kiko - redhhouse GmbH - License: GNU General Public License v2


from .sophos_types import DETECT_SophosX17, SophosInfo
from .agent_based_api.v1 import register, SNMPTree, Service, Result, State, HostLabel
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, InventoryResult, StringTable, HostLabelGenerator
from typing import Optional

def _parse_string(val):
    return val.strip().replace("\r\n", " ").replace("\n", " ")


def parse_sophos_modelinfo(string_table: StringTable) -> Optional[SophosInfo]:
    if not string_table:
        return None
    sophos_info = [_parse_string(s) for s in string_table[0]]
    return SophosInfo(*sophos_info)


def host_label_function_sophos(section: SophosInfo) -> HostLabelGenerator:
    yield HostLabel("cmk/device_type", "firewall")
    yield HostLabel("manufacturer", "sophos")
    yield HostLabel("sophos/model", section.model)
    yield HostLabel("sophos/version", "xg_17.x")

register.snmp_section(
    name = "sophos_modelinfo_xg17",
    detect = DETECT_SophosX17,
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.21067.2.1.1',
        oids = [
            "1.0",
            "2.0",
            "3.0"
        ],
    ),
    host_label_function=host_label_function_sophos,
    parse_function = parse_sophos_modelinfo
)


def discover_sophos_info(section: SophosInfo) -> DiscoveryResult:
    yield Service()


def check_sophos_info(section: SophosInfo) -> CheckResult:
    yield Result(
        state=State.OK,
        summary=f"{section.model}, {section.serialnumber}, {section.firmwareversion}"
    )

register.check_plugin(
    name="sophos_modelinfo_xg17",
    service_name="SOPHOS Modelinfo",
    discovery_function=discover_sophos_info,
    check_function=check_sophos_info
)
