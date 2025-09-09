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
import threading
from functools import partial
import logging
import requests
import typing as ty

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from oslo_policy import _checks

from oslo_policy_opa import opts

LOG = logging.getLogger(__name__)
_session = None
_lock = threading.Lock()


def get_session(max_retries: int = 3, reuse_session: bool = True):
    """
    Lazily creates and returns a thread-safe, singleton requests.Session object
    configured with a robust retry strategy.
    """

    def _new_session():
        _session = requests.Session()

        # Configure the retry strategy
        retry = Retry(
            total=max_retries,  # Total number of retries
            backoff_factor=0,
            allowed_methods=["POST"],
            status_forcelist=[500, 502, 503, 504],
        )

        # Mount the retry strategy to the session
        adapter = HTTPAdapter(max_retries=retry)
        _session.mount("http://", adapter)
        _session.mount("https://", adapter)

        return _session

    if reuse_session:
        # Use a lock to ensure that the session is only created once, even
        # in a multi-threaded environment.
        with _lock:
            global _session
            if _session is None:
                # A session is created only if one doesn't already exist.
                _session = _new_session()
        return _session
    else:
        return _new_session()


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

        conf = enforcer.conf.oslo_policy
        timeout = getattr(conf, "remote_timeout", conf.opa_timeout)

        url = "/".join(
            [conf.opa_url, "v1", "data", normalize_name(self.match), "allow"]
        )
        json = self._construct_payload(creds, current_rule, enforcer, target)

        try:
            session = get_session(conf.opa_max_retries, conf.opa_reuse_session)
            with session.post(url, json=json, timeout=timeout) as response:
                if response.status_code == 200:
                    result = response.json().get("result")
                    if isinstance(result, bool):
                        return result
                    else:
                        return False
                else:
                    LOG.error(
                        "Exception during checking OPA. Status_code = "
                        f"{response.status}"
                    )
        except Exception as ex:
            msg = f"Exception during checking OPA {ex}"
            LOG.error(msg)
            if not conf.opa_fallback_to_code_policy:
                raise
            LOG.warning("Fallback to the DocumentedRuleDefault")

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
            try:
                if isinstance(attr, tuple) and len(attr):
                    key = attr[0]
                    val = attr[1]
                else:
                    key = attr
                    val = target[attr]
            except Exception as ex:
                LOG.error(
                    f"Failure iterating over the target "
                    f"(attribute: {attr}): {ex}"
                )
                raise
            if (
                isinstance(val, (str, int, float, bool, list, tuple, dict))
                or val is None
            ):
                temp_target[key] = copy.deepcopy(val)
            elif isinstance(val, datetime.datetime):
                # Cast datetime to iso format
                temp_target[key] = val.isoformat()
            elif isinstance(
                val, (collections.abc.KeysView, collections.abc.ValuesView)
            ):
                temp_target[key] = list(val)
            elif hasattr(val, "__iter__"):
                # There is an iterator access. Try going this way analyzing
                # every item
                try:
                    subobj = []
                    for sa in val:
                        if (
                            isinstance(
                                sa, (str, int, float, bool, list, tuple, dict)
                            )
                            or val is None
                        ):
                            subobj.append(sa)
                    temp_target[key] = subobj
                except Exception as e:  # noqa
                    LOG.exception(e)
                    pass

            else:
                LOG.warning(
                    f"Ignoring attribute {key} with value {val} "
                    f"since it has unserializable type {type(val)}"
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
        session = get_session(3, True)
        with contextlib.closing(
            session.post(url, json=json, timeout=timeout)
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

        conf = enforcer.conf.oslo_policy
        timeout = getattr(conf, "remote_timeout", conf.opa_timeout)
        url = "/".join(
            [conf.opa_url, "v1", "data", normalize_name(self.match)]
        )

        results: list = []
        if conf.opa_filter_max_threads_count > 0:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=conf.opa_filter_max_threads_count
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
