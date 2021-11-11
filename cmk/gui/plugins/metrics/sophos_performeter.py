#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2021 Alexander Kiko - a.kiko@redhouse.de - redhhouse GmbH - License: GNU General Public License v2

# copy to ./cmk/local/share/check_mk/web/plugins/perfometer/

from . import perfometer_info

perfometer_info.append({
    "type": "linear",
    "segments": ["sophos_live_users"],
    "total": 60
})
