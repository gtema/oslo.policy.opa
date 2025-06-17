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

import os
from pathlib import Path
import pytest
import tempfile

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

        cfg.CONF.set_override(
            "opa_url", "http://localhost:8181", group="oslo_policy"
        )
        cfg.CONF.set_override("policy_file", path, group="oslo_policy")
        yield cfg.CONF


def test_invoke_opa(config):
    enforcer = policy.Enforcer(config, default_rule=_checks.FalseCheck())
    check = opa.OPACheck("opa", "test")

    assert check({"foo": "bar"}, {"project_id": "pid"}, enforcer, None)
    assert not check({"foo": "bar1"}, {"project_id": "pid"}, enforcer, None)


def test_invoke_opa_filter(config):
    enforcer = policy.Enforcer(config, default_rule=_checks.FalseCheck())
    check = opa.OPAFilter("opa", "test")

    assert [{"foo": "bar"}] == list(
        check(
            [{"foo": "bar"}, {"foo": "barx"}],
            {"project_id": "pid"},
            enforcer,
            None,
        )
    )
