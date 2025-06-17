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
import json
from functools import partial
import logging
import requests
import typing as ty
import urllib.request
import urllib.parse

from oslo_policy import _checks

from oslo_policy_opa import opts

LOG = logging.getLogger(__name__)


def normalize_name(name: str) -> str:
    return name.translate(str.maketrans({":": "/", "-": "_"}))  # type: ignore


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

        timeout = getattr(
            enforcer.conf.oslo_policy,
            "remote_timeout",
            enforcer.conf.oslo_policy.opa_timeout,
        )

        url = "/".join(
            [
                enforcer.conf.oslo_policy.opa_url,
                "v1",
                "data",
                normalize_name(self.match),
                "allow",
            ]
        )
        payload = self._construct_payload(
            creds, current_rule, enforcer, target
        )
        json_data = json.dumps(payload)
        json_data_as_bytes = json_data.encode("utf-8")

        req = urllib.request.Request(
            url, data=json_data_as_bytes, method="POST"
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(json_data_as_bytes)))

        try:
            # In real deployment sometimes requests exceed the timeout set
            # with requests library. Investigation shows that the response
            # was successfully processed by the kernel and ACKed while the
            # service still times out. Debugging this is nearly impossible,
            # so we try to eliminate as much dependencies as possible and
            # use urllib directly.
            if not url.startswith("http"):
                # Prevent https://cwe.mitre.org/data/definitions/22.html
                # (https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b310-urllib-urlopen)
                LOG.error(
                    f"OPA url must be HTTP or HTTPS. {req.type} is not supported."
                )
                raise RuntimeError()

            with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310
                if response.status == 200:
                    response_body = response.read().decode("utf-8")
                    try:
                        response_json = json.loads(response_body)
                        result = response_json.get("result")
                        if isinstance(result, bool):
                            return result
                        else:
                            return False

                    except json.JSONDecodeError:
                        LOG.error(
                            f"Got invalid response {response_body}. "
                            "Expecting json."
                        )
                        return False

                else:
                    LOG.error(
                        "Exception during checking OPA. Status_code ="
                        f" {response.status}"
                    )
        except Exception as ex:
            LOG.error(
                f"Exception during checking OPA {ex}. Fallback to the "
                "DocumentedRuleDefault"
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
        with contextlib.closing(
            requests.post(url, json=json, timeout=timeout)
        ) as r:
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
    result is a dict with `allowed: BOOL` and
    `filtered: DICT_OF_FILTERED_ATTRIBUTES`.

    :returns: Generator of entries that are allowed by OPA with "filtered"
        content as the entity
    """

    opts_registered = False

    def __call__(
        self, targets: list[dict], creds, enforcer, current_rule=None
    ):
        if not self.opts_registered:
            opts._register(enforcer.conf)
            self.opts_registered = True

        timeout = getattr(
            enforcer.conf.oslo_policy,
            "remote_timeout",
            enforcer.conf.oslo_policy.opa_timeout,
        )
        url = "/".join(
            [
                enforcer.conf.oslo_policy.opa_url,
                "v1",
                "data",
                normalize_name(self.match),
            ]
        )

        results: list = []
        if enforcer.conf.oslo_policy.opa_filter_max_threads_count > 0:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=enforcer.conf.oslo_policy.opa_filter_max_threads_count
            ) as executor:
                results = list(
                    executor.map(
                        partial(query_filter, url=url, timeout=timeout),
                        [
                            self._construct_payload(
                                creds, current_rule, enforcer, target
                            )
                            for target in targets
                        ],
                        timeout=timeout,
                    )
                )

        else:
            # It may be explicitly desired not to run threads
            for item in targets:
                results.append(
                    query_filter(
                        json=self._construct_payload(
                            creds, current_rule, enforcer, item
                        ),
                        url=url,
                        timeout=timeout,
                    )
                )

        for result in results:
            if result.get("allow", False):
                filtered = result.get("filtered", {})
                if filtered:
                    yield filtered
