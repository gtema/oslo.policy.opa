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

from collections import abc
import datetime
import os
import pytest
from pathlib import Path
import tempfile
import typing as ty
import warnings

from oslo_config import cfg
from oslo_policy import policy
from oslo_policy import _checks
from oslo_policy import opts as oslo_opts

from oslo_policy_opa import opa
from oslo_policy_opa import opts


@pytest.fixture
def config(request):
    oslo_opts._register(cfg.CONF)
    opts._register(cfg.CONF)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir, "policy.yaml")
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        # with open(path, "w", encoding="utf-8") as f:
        #    f.write("test_rule: 'opa:test_rule'")
        #    f.write("test_filter_rule: 'opa_filter:test_rule'")

        cfg.CONF.set_override(
            "opa_url", "http://localhost:8181", group="oslo_policy"
        )
        cfg.CONF.set_override("policy_file", path, group="oslo_policy")
        yield cfg.CONF


def test_execute_json(requests_mock, config):
    check = opa.OPACheck("opa", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule/allow",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"foo": "bar"},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": True},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    assert check({"foo": "bar"}, {"project_id": "pid"}, enforcer, None)


def test_execute_json_neutron_dict_keys(requests_mock, config):
    """Test with target containing dict_keys (as used by Neutron)"""
    check = opa.OPACheck("opa", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule/allow",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {
                    "foo": "bar",
                    "attributes_to_update": ["foo", "baz"],
                },
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": True},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    attrs = {"foo": "bar", "baz": "foo"}
    assert check(
        {"foo": "bar", "attributes_to_update": attrs.keys()},
        {"project_id": "pid"},
        enforcer,
        None,
    )


def test_execute_json_neutron_dict_values(requests_mock, config):
    """Test with target containing dict_keys"""
    check = opa.OPACheck("opa", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule/allow",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {
                    "foo": "bar",
                    "attributes_to_update": ["bar", "foo"],
                },
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": True},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    attrs = {"foo": "bar", "baz": "foo"}
    assert check(
        {"foo": "bar", "attributes_to_update": attrs.values()},
        {"project_id": "pid"},
        enforcer,
        None,
    )


def test_execute_filter_json_neutron_dict_values(requests_mock, config):
    """Test with target containing dict_keys"""
    check = opa.OPAFilter("opa_filter", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {
                    "foo": "bar",
                    "attributes_to_update": ["bar", "foo"],
                },
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": True, "filtered": {"foo": "bar"}}},
    )
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"baz": "bar", "ignore": "me"},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": True, "filtered": {"baz": "bar"}}},
    )
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"bad": "actor"},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": False, "filtered": {"baz": "bar"}}},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    attrs = {"foo": "bar", "baz": "foo"}
    results = list(
        check(
            [
                {"foo": "bar", "attributes_to_update": attrs.values()},
                {"baz": "bar", "ignore": "me"},
                {"bad": "actor"},
            ],
            {"project_id": "pid"},
            enforcer,
            None,
        )
    )
    assert [{"foo": "bar"}, {"baz": "bar"}] == results


def test_execute_filter_json_neutron_dict_values_no_threads(
    requests_mock, config
):
    """Test with target containing dict_keys"""
    check = opa.OPAFilter("opa_filter", "testrule")
    config.set_override("opa_filter_max_threads_count", 0, group="oslo_policy")

    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {
                    "foo": "bar",
                    "attributes_to_update": ["bar", "foo"],
                },
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": True, "filtered": {"foo": "bar"}}},
    )
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"baz": "bar", "ignore": "me"},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": True, "filtered": {"baz": "bar"}}},
    )
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"bad": "actor"},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": {"allow": False, "filtered": {"baz": "bar"}}},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    attrs = {"foo": "bar", "baz": "foo"}
    results = list(
        check(
            [
                {"foo": "bar", "attributes_to_update": attrs.values()},
                {"baz": "bar", "ignore": "me"},
                {"bad": "actor"},
            ],
            {"project_id": "pid"},
            enforcer,
            None,
        )
    )
    assert [{"foo": "bar"}, {"baz": "bar"}] == results


def test_execute_glance(requests_mock, config):
    """Test proper dealing with Glance ImageTarget"""
    check = opa.OPACheck("opa", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule/allow",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"foo": "bar", "bar": None},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": True},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    class ImageTarget(abc.Mapping):
        SENTINEL = object()

        def __init__(self, target):
            """Initialize the object

            :param target: Object being targeted
            """
            self.target = target
            self._target_keys = ["foo", "bar"]

        def __getitem__(self, key):
            """Return the value of 'key' from the target.

            If the target has the attribute 'key', return it.

            :param key: value to retrieve
            """
            key = self.key_transforms(key)

            value = getattr(self.target, key, self.SENTINEL)
            if value is self.SENTINEL:
                extra_properties = getattr(
                    self.target, "extra_properties", None
                )
                if extra_properties is not None:
                    value = extra_properties[key]
                else:
                    value = None
            return value

        def get(self, key, default=None):
            try:
                return self.__getitem__(key)
            except KeyError:
                return default

        def __len__(self):
            length = len(self._target_keys)
            length += len(getattr(self.target, "extra_properties", {}))
            return length

        def __iter__(self):
            yield from self._target_keys

        def key_transforms(self, key):
            transforms = {
                "id": "image_id",
                "project_id": "owner",
                "member_id": "member",
            }

            return transforms.get(key, key)

    class Image:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    assert check(
        ImageTarget(target=Image(foo="bar")),
        {"project_id": "pid"},
        enforcer,
        None,
    )

    assert check._construct_payload(
        {}, None, enforcer, ImageTarget(target=Image(foo="bar"))
    ) == {"input": {"credentials": {}, "target": {"bar": None, "foo": "bar"}}}


def test_credentials_mutablemapping(requests_mock, config):
    """Test proper dealing with Glance ImageTarget"""
    check = opa.OPACheck("opa", "testrule")
    requests_mock.post(
        "http://localhost:8181/v1/data/testrule/allow",
        additional_matcher=lambda r: r.json()
        == {
            "input": {
                "target": {"foo": "bar", "bar": None},
                "credentials": {"project_id": "pid"},
            }
        },
        json={"result": True},
    )
    default_rule = _checks.TrueCheck()
    enforcer = policy.Enforcer(config, default_rule=default_rule)

    class Creds(abc.MutableMapping):
        def __init__(self, data: dict[str, ty.Any]):
            self._data = data
            self._deprecated: dict[str, ty.Any] = {}

        def __getitem__(self, k: str) -> ty.Any:
            try:
                return self._data[k]
            except KeyError:
                pass

            try:
                val = self._deprecated[k]
            except KeyError:
                pass
            else:
                warnings.warn(
                    "Policy enforcement is depending on the value of "
                    f"{k}. This key is deprecated. Please update your "
                    "policy file to use the standard policy values.",
                    DeprecationWarning,
                )
                return val

            raise KeyError(k)

        def __setitem__(self, k: str, v: ty.Any) -> None:
            self._deprecated[k] = v

        def __delitem__(self, k: str) -> None:
            del self._deprecated[k]

        def __iter__(self) -> ty.Iterator[ty.Any]:
            return iter(self._dict)

        def __len__(self) -> int:
            return len(self._dict)

        def __str__(self) -> str:
            return self._dict.__str__()

        def __repr__(self) -> str:
            return self._dict.__repr__()

        @property
        def _dict(self) -> dict[str, ty.Any]:
            d = self._deprecated.copy()
            d.update(self._data)
            return d

    c = Creds({"project_id": "pid"})

    assert check({"foo": "bar", "bar": None}, c, enforcer, None)


def test_construct_payload_datetime(config):
    check = opa.OPACheck("opa", "testrule")
    dt = datetime.datetime.now()
    assert check._construct_payload(
        creds={}, current_rule=None, enforcer=None, target={"date": dt}
    ) == {"input": {"target": {"date": dt.isoformat()}, "credentials": {}}}


def test_construct_payload_object():
    check = opa.OPACheck("opa", "testrule")

    class SOT(object):  # noqa
        def __init__(self, orig_set):
            if orig_set is None:
                orig_set = set([])  # noqa
            self.tags = orig_set

        def __iter__(self, *args, **kwargs):
            return self.tags.__iter__(*args, **kwargs)

        def __len__(self, *args, **kwargs):
            return self.tags.__len__(*args, **kwargs)

        def __getattr__(self, name):
            # Protect against deepcopy, which calls getattr. __getattr__
            # is only called when an attribute is not "normal", so when
            # self.tags is called, this is not.
            if name == "tags":
                try:
                    return self.__getattribute__("tags")
                except AttributeError:
                    return None
            return getattr(self.tags, name)

    res = check._construct_payload(
        creds={},
        current_rule=None,
        enforcer=None,
        target={"tags": SOT(["a", "b"])},
    )
    assert {
        "input": {"credentials": {}, "target": {"tags": ["a", "b"]}}
    } == res
