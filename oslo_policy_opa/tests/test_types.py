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


def test_opa_generic_complex_name():
    global_results = {}
    check = types.GenericCheck(
        _checks.GenericCheck("tenant", "%(target:foo)s")
    )
    assert check.get_opa_policy(global_results) == [
        'input.credentials.tenant == input.target["target:foo"]'
    ]
    # oslo_policy GenericCheck will first try to access attribute as is and
    # then go into dict lookup. In OPA we need to wrap this to different access
    # types explicitly.
    check = types.GenericCheck(
        _checks.GenericCheck("'member'", "%(role.name)s")
    )
    assert check.get_opa_policy(global_results) == [
        '"member" == input.target.role.name',
        '"member" == input.target["role.name"]',
    ]


def test_opa_generic_check_test_data():
    assert types.GenericCheck(
        _checks.GenericCheck("tenant", "%(tenant_id)s")
    ).get_opa_policy_test_data(None, "foo", False) == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo"},
            }
        }
    ]

    assert types.GenericCheck(
        _checks.GenericCheck("'foo'", "%(a.b.c)s")
    ).get_opa_policy_test_data(None, "foo", False) == [
        {"input": {"target": {"a": {"b": {"c": "foo"}}}}},
        {"input": {"target": {"a.b.c": "foo"}}},
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


def test_opa_test_data_and():
    global_results = {}
    check = types.AndCheck(
        _checks.AndCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.GenericCheck("False", "%(foo)s"),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo", "foo": False},
            }
        }
    ]


def test_opa_test_data_and_complex_generic():
    global_results = {}
    check = types.AndCheck(
        _checks.AndCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.GenericCheck("False", "%(foo.bar)s"),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo", "foo": {"bar": False}},
            }
        },
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"foo.bar": False, "tenant_id": "foo"},
            }
        },
    ]


def test_opa_test_data_and_or():
    global_results = {}
    check = types.AndCheck(
        _checks.AndCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.OrCheck(
                    [
                        _checks.GenericCheck("False", "%(foo)s"),
                        _checks.GenericCheck("1", "%(b)s"),
                    ]
                ),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo", "foo": False},
            }
        },
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"b": 1, "tenant_id": "foo"},
            }
        },
    ]


def test_opa_test_data_and_and():
    global_results = {}
    check = types.AndCheck(
        _checks.AndCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.AndCheck(
                    [
                        _checks.GenericCheck("False", "%(foo)s"),
                        _checks.GenericCheck("1", "%(b)s"),
                    ]
                ),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo", "foo": False, "b": 1},
            }
        }
    ]


def test_opa_test_data_or():
    global_results = {}
    check = types.OrCheck(
        _checks.OrCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.GenericCheck("False", "%(foo)s"),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo"},
            }
        },
        {"input": {"target": {"foo": False}}},
    ]


def test_opa_test_data_or_and():
    global_results = {}
    check = types.OrCheck(
        _checks.OrCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.AndCheck(
                    [
                        _checks.GenericCheck("False", "%(foo)s"),
                        _checks.GenericCheck("1", "%(b)s"),
                    ]
                ),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo"},
            }
        },
        {"input": {"target": {"foo": False, "b": 1}}},
    ]


def test_opa_test_data_or_or():
    global_results = {}
    check = types.OrCheck(
        _checks.OrCheck(
            [
                _checks.GenericCheck("tenant", "%(tenant_id)s"),
                _checks.OrCheck(
                    [
                        _checks.GenericCheck("False", "%(foo)s"),
                        _checks.GenericCheck("1", "%(b)s"),
                    ]
                ),
            ]
        )
    )
    assert check.get_opa_policy_test_data(global_results, "dummy") == [
        {
            "input": {
                "credentials": {"tenant": "foo"},
                "target": {"tenant_id": "foo"},
            }
        },
        {"input": {"target": {"foo": False}}},
        {"input": {"target": {"b": 1}}},
    ]
