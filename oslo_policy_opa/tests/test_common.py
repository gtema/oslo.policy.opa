# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from oslo_policy_opa.generator import common


def test_normalize_name():
    assert common.normalize_name("a:b-C_d") == "a_b_C_d"


def test_deep_merge_dicts():
    assert common.deep_merge_dicts(
        {"a": {"b": {"c": "d"}}}, {"a": {"b": {"e": "f"}}, "g": "h"}
    ) == {"a": {"b": {"c": "d", "e": "f"}}, "g": "h"}
    assert common.deep_merge_dicts(
        {"a": {"b": {"c": ["d"]}}}, {"a": {"b": {"c": ["e"]}}}
    ) == {"a": {"b": {"c": ["d", "e"]}}}


def test_product():
    assert list(
        common.product([{"a": "b"}, {"c": "d"}], [{"e": "f"}, {"g": "h"}])
    ) == [
        {"a": "b", "e": "f"},
        {"a": "b", "g": "h"},
        {"c": "d", "e": "f"},
        {"c": "d", "g": "h"},
    ]
