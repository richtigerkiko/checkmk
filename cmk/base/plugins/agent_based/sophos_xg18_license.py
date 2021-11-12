#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2021 Alexander Kiko - a.kiko@redhouse.de - redhhouse GmbH - License: GNU General Public License v2
# .1.3.6.1.4.1.2604.5.1.5.1.1.0 3 --> SFOS-FIREWALL-MIB::sfosBaseFWLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.1.2.0 Dec 31 2999 --> SFOS-FIREWALL-MIB::sfosBaseFWLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.2.1.0 1 --> SFOS-FIREWALL-MIB::sfosNetProtectionLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.2.2.0 Nov 10 2021 --> SFOS-FIREWALL-MIB::sfosNetProtectionLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.3.1.0 1 --> SFOS-FIREWALL-MIB::sfosWebProtectionLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.3.2.0 Nov 10 2021 --> SFOS-FIREWALL-MIB::sfosWebProtectionLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.4.1.0 1 --> SFOS-FIREWALL-MIB::sfosMailProtectionLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.4.2.0 Nov 10 2021 --> SFOS-FIREWALL-MIB::sfosMailProtectionLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.5.1.0 1 --> SFOS-FIREWALL-MIB::sfosWebServerProtectionLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.5.2.0 Nov 10 2021 --> SFOS-FIREWALL-MIB::sfosWebServerProtectionLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.6.1.0 1 --> SFOS-FIREWALL-MIB::sfosSandstromLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.6.2.0 Nov 10 2021 --> SFOS-FIREWALL-MIB::sfosSandstromLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.7.1.0 2 --> SFOS-FIREWALL-MIB::sfosEnhancedSupportLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.7.2.0 fail --> SFOS-FIREWALL-MIB::sfosEnhancedSupportLicExpiryDate.0
# .1.3.6.1.4.1.2604.5.1.5.8.1.0 2 --> SFOS-FIREWALL-MIB::sfosEnhancedPlusLicRegStatus.0
# .1.3.6.1.4.1.2604.5.1.5.8.2.0 fail --> SFOS-FIREWALL-MIB::sfosEnhancedPlusLicExpiryDate.0

from datetime import datetime
from typing import Dict, List

from cmk.base.api.agent_based.checking_classes import Metric

from .agent_based_api.v1 import register, SNMPTree, Result, State, Service, check_levels, render
from .agent_based_api.v1.type_defs import StringTable, DiscoveryResult, CheckResult
from .sophos_types import DETECT_SophosX18, SophosLicense, SophosSubscriptionStatusType



Section = Dict[str, SophosLicense]


def get_license_name(i: int, row: str):  # function to get the license name from snmp parser
    if(i == 0):
        return "BaseLicense"
    elif(i == 2):
        return "Network Protection"
    elif(i == 4):
        return "Web Protection"
    elif(i == 6):
        return "Mail Protection"
    elif(i == 8):
        return "Webserver Protection"
    elif(i == 10):
        return "Sandstorm"
    elif(i == 12):
        return "Enhanced Support"
    elif(i == 14):
        return "Enhanced Support Plus"
    else:
        return f"Unknown license: {row}"




def parse_snmp(string_table: StringTable) -> Section:
    snmpresult = string_table[0]  # fetched snmp data is array length 1 so wie just neet the first one
    parse_result:Section = {}  # init dictionary
    for i, row in enumerate(snmpresult):  # with this for loop i fill the parse_result dcitionary
        if(i % 2 == 0):  # we only need every second row starting with string_table[0]
            if(snmpresult[i + 1] == "fail"):  # Giving "fail" Datetime datetime of baselicense to avoid formatting errors
                snmpresult[i + 1] = "Dec 31 2999"
            parse_result[get_license_name(i, row).replace(" ","_").lower()] = SophosLicense(
                LicenseStatus=SophosSubscriptionStatusType(int(row)),
                LicenseExiprationDate = datetime.strptime(snmpresult[i +1], "%b %d %Y"),
                LicenseLabel=get_license_name(i, row)
            )
    return parse_result

def discover_sophos_license(section: Section) -> DiscoveryResult:
    for licName, licObj in section.items(): 
        if((licObj.LicenseStatus == SophosSubscriptionStatusType.subscribed or 
        licObj.LicenseStatus == SophosSubscriptionStatusType.expired or 
        licObj.LicenseStatus == SophosSubscriptionStatusType.evaluating) and
        licName != "baselicense"): # Only yield Service if License is active and pop baselicense because its forever
            yield Service(item=licName)

def check_sophos_license(item: str, section: Section) -> CheckResult:
    sopLic:SophosLicense = section[item]
    daysLeft:int = (sopLic.LicenseExiprationDate - datetime.now()).days # calc daysleft
    
    licDur:str=""
    if(daysLeft > 730 ): # get metricname for 3y lic, to make the perf-o-meter nicer
        licDur:str="3y"
    elif(daysLeft > 365): # get metricname for 2y lic, to make the perf-o-meter nicer
        licDur:str="2y"
    else: # get metricname for 1y lic, to make the perf-o-meter nicer
        licDur:str="1y"

        if(daysLeft < 0):
            daysLeft=0

    yield from check_levels(
        value=daysLeft, # for timespan in seconds
        metric_name=f"sophos_license_{licDur}", # generate sophos license name with license duration
        levels_lower=(31,14), # 14 or 31 days error
        label="Days Left",
        notice_only=True
    )

    yield Result(
        state=State.OK,
        summary=f"Sophos license {sopLic.LicenseLabel} expires on {sopLic.LicenseExiprationDate.ctime()}"
    )


register.snmp_section(
    name = "sophos_xg18_lics",
    detect = DETECT_SophosX18,
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.2604.5.1.5',
        oids = [
            "1.1.0",  # --> SFOS-FIREWALL-MIB::sfosBaseFWLicRegStatus.0
            "1.2.0",  # --> SFOS-FIREWALL-MIB::sfosBaseFWLicExpiryDate.0
            "2.1.0",  # --> SFOS-FIREWALL-MIB::sfosNetProtectionLicRegStatus.0
            "2.2.0",  # --> SFOS-FIREWALL-MIB::sfosNetProtectionLicExpiryDate.0
            "3.1.0",  # --> SFOS-FIREWALL-MIB::sfosWebProtectionLicRegStatus.0
            "3.2.0",  # --> SFOS-FIREWALL-MIB::sfosWebProtectionLicExpiryDate.0
            "4.1.0",  # --> SFOS-FIREWALL-MIB::sfosMailProtectionLicRegStatus.0
            "4.2.0",  # --> SFOS-FIREWALL-MIB::sfosMailProtectionLicExpiryDate.0
            "5.1.0",  # --> SFOS-FIREWALL-MIB::sfosWebServerProtectionLicRegStatus.0
            "5.2.0",  # --> SFOS-FIREWALL-MIB::sfosWebServerProtectionLicExpiryDate.0
            "6.1.0",  # --> SFOS-FIREWALL-MIB::sfosSandstromLicRegStatus.0
            "6.2.0",  # --> SFOS-FIREWALL-MIB::sfosSandstromLicExpiryDate.0
            "7.1.0",  # --> SFOS-FIREWALL-MIB::sfosEnhancedSupportLicRegStatus.0
            "7.2.0",  # --> SFOS-FIREWALL-MIB::sfosEnhancedSupportLicExpiryDate.0
            "8.1.0",  # --> SFOS-FIREWALL-MIB::sfosEnhancedPlusLicRegStatus.0
            "8.2.0"  # --> SFOS-FIREWALL-MIB::sfosEnhancedPlusLicExpiryDate.0
        ],
    ),
    parse_function = parse_snmp
)


register.check_plugin(
    name="sophos_xg18_lics",
    service_name="SOPHOS License: %s",
    discovery_function=discover_sophos_license,
    check_function=check_sophos_license
)
