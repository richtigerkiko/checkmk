#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import json

from typing import Mapping, Tuple, TypedDict, Sequence

from cmk.base.api.agent_based.checking_classes import Metric

from .agent_based_api.v1 import register, type_defs, Service, Result, State


class Section(TypedDict):
    unread_count: int
    total_count: int
    unread_headers: Sequence[str]


def parse_mxmail(string_table: type_defs.StringTable) -> dict:
    """Extracts number of unread messages, total messages and headers
    for unread"""
    mxmail = json.loads(" ".join(string_table[0]))
    unread_count = 0
    unread_headers = []
    for mail in mxmail["m"]:
        if mail.get("f") == "u":
            unread_count += 1
            unread_headers.append(mail["su"])
    return {
        "unread_count": unread_count,
        "total_count": len(mxmail["m"]),
        "unread_headers": unread_headers,
    }


def discovery_mxmail(section: Section) -> type_defs.DiscoveryResult:
    """..."""
    yield Service()


register.agent_section(
    name="mxzimbra",
    parse_function=parse_mxmail,
)


def check_mxmail(
    params: Mapping[str, Tuple[int, int]], section: Section
) -> type_defs.CheckResult:
    """..."""
    level_warn, level_crit = params["levels"]
    total_count = section["total_count"]
    yield Result(state=State.OK, summary=f"Total: {total_count}")
    yield Metric(name="mails_total_count", value=total_count)
    state = State.OK
    unread_count = section["unread_count"]
    if unread_count > level_crit:
        state = State.CRIT
    elif unread_count > level_warn:
        state = State.WARN
    yield Result(
        state=state,
        summary=f"Unread emails: {unread_count}",
        details="Headers: " + "\n".join(section["unread_headers"]),
    )


register.check_plugin(
    name="mxzimbra",
    service_name="Mails",
    discovery_function=discovery_mxmail,
    check_function=check_mxmail,
    check_ruleset_name="mxzimbra",
    check_default_parameters={"levels": (4, 9)},
)
