#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import pytest

from oslo_policy_opa import generator
from oslo_policy import _checks


def test_normalize_name():
    assert generator.normalize_name("a:b-C_d") == "a_b_C_d"


def test_deep_merge_dicts():
    assert generator.deep_merge_dicts(
        {"a": {"b": {"c": "d"}}}, {"a": {"b": {"e": "f"}}, "g": "h"}
    ) == {"a": {"b": {"c": "d", "e": "f"}}, "g": "h"}
    assert generator.deep_merge_dicts(
        {"a": {"b": {"c": ["d"]}}}, {"a": {"b": {"c": ["e"]}}}
    ) == {"a": {"b": {"c": ["d", "e"]}}}


def test_product():
    assert list(
        generator.product([{"a": "b"}, {"c": "d"}], [{"e": "f"}, {"g": "h"}])
    ) == [
        {"a": "b", "e": "f"},
        {"a": "b", "g": "h"},
        {"c": "d", "e": "f"},
        {"c": "d", "g": "h"},
    ]


def test_opa_generic_check():
    global_results = {}
    check = generator.GenericCheck(
        _checks.GenericCheck("tenant", "%(tenant_id)s")
    )
    assert check.get_opa_policy(global_results) == [
        "input.credentials.tenant == input.tenant_id"
    ]
    check = generator.GenericCheck(
        _checks.GenericCheck("'member'", "%(role.name)s")
    )
    assert check.get_opa_policy(global_results) == [
        '"member" == input.role.name'
    ]


def test_opa_test_data_generic_check():
    global_results = {}
    check = generator.GenericCheck(
        _checks.GenericCheck("tenant", "%(tenant_id)s")
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {"input": {"credentials": {"tenant": "foo"}, "tenant_id": "foo"}}
    ]
