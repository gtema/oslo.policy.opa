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


from oslo_policy_opa.generator import types
from oslo_policy import _checks


def test_opa_generic_check():
    global_results = {}
    check = types.GenericCheck(_checks.GenericCheck("tenant", "%(tenant_id)s"))
    assert check.get_opa_policy(global_results) == [
        "input.credentials.tenant == input.target.tenant_id"
    ]
    check = types.GenericCheck(
        _checks.GenericCheck("'member'", "%(role.name)s")
    )
    assert check.get_opa_policy(global_results) == [
        '"member" == input.target.role.name'
    ]


def test_opa_role_check():
    global_results = {}
    check = types.RoleCheck(_checks.RoleCheck("'role'", "member"))
    assert check.get_opa_policy(global_results) == [
        '"member" in input.credentials.roles'
    ]


def test_opa_test_data_generic_check():
    global_results = {}
    check = types.GenericCheck(_checks.GenericCheck("tenant", "%(tenant_id)s"))
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo"},
            }
        }
    ]
