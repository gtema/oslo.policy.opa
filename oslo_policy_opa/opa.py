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

import collections
import concurrent.futures
import contextlib
import copy
import datetime
from functools import partial
import logging
import requests
import typing as ty

from oslo_policy import _checks

from oslo_policy_opa import opts

LOG = logging.getLogger(__name__)


def normalize_name(name: str) -> str:
    return name.translate(
        str.maketrans({":": "/", "-": "_"})  # type: ignore
    )


class OPACheck(_checks.Check):
    """Oslo.policy ``opa:`` check

    Invoke OPA for the authorization policy evaluation. In case of errors
    fallback to the default rule definition.
    """

    opts_registered = False

    def __call__(self, target, creds, enforcer, current_rule=None):
        if not self.opts_registered:
            opts._register(enforcer.conf)
            self.opts_registered = True

        timeout = getattr(enforcer.conf.oslo_policy, "remote_timeout", 1)

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
            with contextlib.closing(
                requests.post(url, json=json, timeout=timeout)
            ) as r:
                if r.status_code == 200:
                    result = r.json().get("result")
                    if isinstance(result, bool):
                        return result
                    else:
                        return False
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
        # Access whatever the target is a dictionary (iterate over attributes)
        # and copy those attributes which are known to be serializable.
        # Otherwise chance is very high an exception will be thrown that
        # certain attribute can not be pickled.
        #
        # Glance uses weird object
        # (https://opendev.org/openstack/glance/src/branch/master/glance/api/policy.py)
        # as the target which cannot be copied. If ever a target is not a
        # dictionary iterate over the target (which is similar to what
        # oslo.policy would do) and use the result as the key to use.
        #
        # Neutron passes `attributes_to_update: dict.keys()` which also fail
        # serialization
        temp_target: dict[str, ty.Any] = {}
        for attr in target:
            if (
                isinstance(
                    target[attr], (str, int, float, bool, list, tuple, dict)
                )
                or target[attr] is None
            ):
                temp_target[attr] = copy.deepcopy(target[attr])
            elif isinstance(target[attr], datetime.datetime):
                # Cast datetime to iso format
                temp_target[attr] = target[attr].isoformat()
            elif isinstance(
                target[attr],
                (collections.abc.KeysView, collections.abc.ValuesView),
            ):
                temp_target[attr] = list(target[attr])
            elif hasattr(target[attr], "__iter__"):
                # There is an iterator access. Try going this way analyzing
                # every item
                try:
                    subobj = []
                    for sa in target[attr]:
                        if (
                            isinstance(
                                sa, (str, int, float, bool, list, tuple, dict)
                            )
                            or target[attr] is None
                        ):
                            subobj.append(sa)
                    temp_target[attr] = subobj
                except Exception as e:  # noqa
                    LOG.exception(e)
                    pass

            else:
                LOG.warning(
                    f"Ignoring attribute {attr} with value {target[attr]} "
                    f"since it has unserializable type {type(target[attr])}"
                )
        # NOTE(gtema): Octavia uses `oslo.context:to_policy_values` which
        # returns `_DeprecatedPolicyValues`, which in turn is
        # `collections.abc.MutableMapping`. Treat it similarly to the target
        # object and explicitly access it as a dictionary
        if not isinstance(creds, dict):
            temp_creds = {k: copy.deepcopy(creds[k]) for k in creds}
        else:
            temp_creds = copy.deepcopy(creds)
        json = {"input": {"target": temp_target, "credentials": temp_creds}}
        return json


def query_filter(json: dict, url: str, timeout: int):
    try:
        with contextlib.closing(requests.post(url, json=json, timeout=1)) as r:
            if r.status_code == 200:
                return r.json().get("result")
            else:
                LOG.error(
                    "Exception during checking OPA. Status_code = %s",
                    r.status_code,
                )
    except Exception as ex:
        LOG.error(f"Exception during checking OPA {ex}.")


class OPAFilter(OPACheck):
    """Oslo.policy ``opa_filter:`` check

    Invoke OPA for the authorization policy evaluation. It is expected that the
    result is a dict with `allowed: BOOL` and `filtered: DICT_OF_FILTERED_ATTRIBUTES`.
    """

    opts_registered = False

    def __call__(
        self, targets: list[dict], creds, enforcer, current_rule=None
    ):
        if not self.opts_registered:
            opts._register(enforcer.conf)
            self.opts_registered = True

        timeout = getattr(enforcer.conf.oslo_policy, "remote_timeout", 1)

        # results: ty.Iterator[ty.Any] = []  # type: ignore
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            url = "/".join(
                [
                    enforcer.conf.oslo_policy.opa_url,
                    "v1",
                    "data",
                    normalize_name(self.match),
                ]
            )
            results = executor.map(
                partial(query_filter, url=url, timeout=timeout),
                [
                    self._construct_payload(
                        creds, current_rule, enforcer, target
                    )
                    for target in targets
                ],
            )
            executor.shutdown()

            for result in results:
                if result.get("allow", False):
                    filtered = result.get("filtered", {})
                    if filtered:
                        yield filtered

    @staticmethod
    def _construct_payload(creds, current_rule, enforcer, target):
        json = {"input": {"target": target, "credentials": creds}}
        return json
