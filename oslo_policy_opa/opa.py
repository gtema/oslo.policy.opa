# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import contextlib
import copy
import logging
import os
import requests
import time

import oslo_config
from oslo_policy import _checks
import oslo_log

from oslo_policy_opa import opts

LOG = logging.getLogger(__name__)


def normalize_name(name: str) -> str:
    return name.translate(str.maketrans({":": "/", "-": "_"}))


class OPACheck(_checks.Check):
    """Check ``opa:`` rules by calling to a remote OpenPolicyAgent server.

    Invoke OPA for the authorization policy evaluation. In case of errors
    fallback to the default rule definition.
    """

    opts_registered = False

    def __call__(self, target, creds, enforcer, current_rule=None):
        LOG.info(f"OPA check invoked for {target} at {self.match}")
        if not self.opts_registered:
            opts._register(enforcer.conf)
            self.opts_registered = True

        timeout = enforcer.conf.oslo_policy.remote_timeout

        url = "/".join(
            [
                enforcer.conf.oslo_policy.opa_url,
                "v1",
                "data",
                normalize_name(self.match),
                "allow",
            ]
        )
        json = self._construct_payload(creds, current_rule, enforcer, target)
        try:
            start = time.time()
            with contextlib.closing(
                requests.post(url, json=json, timeout=timeout)
            ) as r:
                end = time.time()
                if r.status_code == 200:
                    result = r.json().get("result")
                    LOG.debug(
                        f"Policy evaluation in OPA returned {result} at {(end - start) * 1000}ms"
                    )
                    if isinstance(result, bool):
                        return result
                else:
                    LOG.error(
                        "Exception during checking OPA. Status_code = %s",
                        r.status_code,
                    )
        except Exception as ex:
            LOG.error(
                f"Exception during checking OPA {ex}. Fallback to the DocumentedRuleDefault"
            )
        # When any exception has happened during the communication or OPA
        # result processing we want to fallback to the default rule
        default_rule = enforcer.registered_rules.get(current_rule)
        if default_rule:
            return _checks._check(
                rule=default_rule._check,
                target=target,
                creds=creds,
                enforcer=enforcer,
                current_rule=current_rule,
            )
        return False

    @staticmethod
    def _construct_payload(creds, current_rule, enforcer, target):
        # Convert instances of object() in target temporarily to
        # empty dict to avoid circular reference detection
        # errors in jsonutils.dumps().
        temp_target = copy.deepcopy(target)
        for key in target.keys():
            element = target.get(key)
            if type(element) is object:
                temp_target[key] = {}
        json = {"input": {"target": temp_target, "credentials": creds}}
        return json
