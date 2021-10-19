from textwrap import wrap

from cmk.base.plugins.agent_based.smart import _summary

from .mxmails import parse_mxmail, discovery_mxmail, check_mxmail
from .agent_based_api.v1 import State

import json
import pytest


def load_params_from_json(json_path):
    with open(json_path) as f:
        return [json.load(f)]


@pytest.fixture(params=load_params_from_json("mxmails.json"), ids=["mxmail"])
def mxmails_dict(request):
    return request.param


def test_parse_mxmail_takes_a_list_of_strings(mxmails_dict):
    parse_mxmail([wrap(json.dumps(mxmails_dict), 60)])


@pytest.fixture(ids=["mxmail"])
def mxmails_raw(mxmails_dict):
    return wrap(json.dumps(mxmails_dict), 60)


@pytest.fixture
def unread():
    return 3


def test_parse_mxmail_expects_a_dict_with_unread_count(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert "unread_count" in parsed


def test_parse_mxmail_expects_a_dict_with_3_unread_count(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert parsed["unread_count"] == 3


def test_parse_mxmail_expects_a_dict_with_total_count(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert "total_count" in parsed


def test_parse_mxmail_expects_a_dict_with_3_total(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert parsed["total_count"] == 165


def test_parse_mxmail_expects_a_dict_with_unread_headers(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert "unread_headers" in parsed


def test_parse_mxmail_expects_a_dict_with_3_unread_headers(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert len(parsed["unread_headers"]) == 3


@pytest.fixture(ids=["mxmail"])
def mxmails_raw_mangled(unread, mxmails_dict):
    new_mails = []
    marked_unread = sum(mail.get("f") == "u" for mail in mxmails_dict["m"])
    for mail in mxmails_dict["m"]:
        new_mail = mail.copy()
        if marked_unread < unread and mail.get("f") != "u":
            new_mail["f"] = "u"
            marked_unread += 1
        new_mails.append(new_mail)
    return wrap(json.dumps({"m": new_mails}), 60)


@pytest.mark.parametrize("unread", [3, 4, 5, 30, 20])
def test_parse_mxmail_expects_a_dict_with_n_unread_headers(unread, mxmails_raw_mangled):
    parsed = parse_mxmail([mxmails_raw_mangled])
    assert len(parsed["unread_headers"]) == unread


@pytest.mark.parametrize("header", ["Mail #1", "Mail #2", "Mail #3"])
def test_parse_mxmail_expects_a_dict_with_a_header(header, mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    assert header in parsed["unread_headers"]


def test_discovery_mxmail_returns_an_iterable(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    list(discovery_mxmail(parsed))


def test_check_mxmail_expects_parsed(mxmails_raw):
    parsed = parse_mxmail([mxmails_raw])
    list(check_mxmail(parsed))


def test_check_mxmail_checks_total(mxmails_raw_mangled, mxmails_dict):
    parsed = parse_mxmail([mxmails_raw_mangled])
    results = list(check_mxmail(parsed))
    assert results[-2].state == State.OK
    assert results[-2].summary == f"Total: {len(mxmails_dict['m'])}"


@pytest.mark.parametrize("unread", [3, 4])
def test_check_mxmail_checks_are_ok(mxmails_raw_mangled):
    parsed = parse_mxmail([mxmails_raw_mangled])
    results = list(check_mxmail(parsed))
    assert results[-1].state == State.OK


@pytest.mark.parametrize("unread", [5, 6, 7, 8, 9])
def test_check_mxmail_checks_are_warn(mxmails_raw_mangled):
    parsed = parse_mxmail([mxmails_raw_mangled])
    results = list(check_mxmail(parsed))
    assert results[-1].state == State.WARN


@pytest.mark.parametrize("unread", [10, 15, 20, 25, 30])
def test_check_mxmail_checks_are_crit(mxmails_raw_mangled):
    parsed = parse_mxmail([mxmails_raw_mangled])
    results = list(check_mxmail(parsed))
    assert results[-1].state == State.CRIT


@pytest.mark.parametrize("unread", [3, 4, 5])
def test_check_mxmail_checks_include_headers(unread, mxmails_raw_mangled):
    parsed = parse_mxmail([mxmails_raw_mangled])
    result = list(check_mxmail(parsed))[-1]
    assert all(f"Mail #{i + 1}" in result.details for i in range(unread))
