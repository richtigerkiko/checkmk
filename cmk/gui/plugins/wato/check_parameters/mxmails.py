#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from typing import List

from cmk.gui.i18n import _
from cmk.gui.valuespec import Dictionary, DictionaryEntry, Integer, Tuple

from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithItem,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
)


def _parameter_valuespec_mxmail():
    elements: List[DictionaryEntry] = [
        (
            "levels",
            Tuple(
                title=_("Specify levels in absolute usage values"),
                elements=[
                    Integer(title=_("Warning at"), unit=_("mails")),
                    Integer(title=_("Critical at"), unit=_("mails")),
                ],
            ),
        ),
    ]
    return Dictionary(elements=elements)


rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="mxzimbra",
        group=RulespecGroupCheckParametersApplications,
        parameter_valuespec=_parameter_valuespec_mxmail,
        title=lambda: _("MX Mails"),
    )
)
