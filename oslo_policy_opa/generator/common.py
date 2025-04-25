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

import logging
import typing

import stevedore


LOG = logging.getLogger(__name__)


def on_load_failure_callback(*args, **kwargs):
    raise


def get_enforcer(namespace):
    """Find a policy.Enforcer via an entry point with the given namespace.

    :param namespace: a namespace under oslo.policy.enforcer where the desired
        enforcer object can be found.
    :returns: a policy.Enforcer object
    """
    if namespace.startswith("neutron-"):
        namespace = "neutron"
    mgr = stevedore.named.NamedExtensionManager(
        "oslo.policy.enforcer",
        names=[namespace],
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True,
    )
    if namespace not in mgr:
        raise KeyError(f"Namespace {namespace} not found.")
    enforcer = mgr[namespace].obj

    return enforcer


def get_policies_dict(namespaces):
    """Find the options available via the given namespaces.

    :param namespaces: a list of namespaces registered under
        'oslo.policy.policies'
    :returns: a dict of {namespace1: [rule_default_1, rule_default_2],
        namespace2: [rule_default_3]...}
    """
    mgr = stevedore.named.NamedExtensionManager(
        "oslo.policy.policies",
        names=namespaces,
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True,
    )
    opts = {ep.name: ep.obj for ep in mgr}

    return opts


def normalize_name(name: str) -> str:
    name = name.replace("default", "dflt")
    return name.translate(str.maketrans({":": "_", "-": "_", "*": "any"}))  # type: ignore


def deep_dict_set(path_parts: list[str], val) -> dict[str, typing.Any]:
    """Set dictionary value by path"""
    result: dict[str, typing.Any] = {}
    if len(path_parts) > 1:
        result[path_parts[0]] = deep_dict_set(path_parts[1:], val)
    elif len(path_parts) == 1:
        result[path_parts[0]] = val
    else:
        raise NotImplementedError(
            f"deep set invoked with unclear path {path_parts}"
        )
    return result


def deep_merge_dicts(dict1, dict2):
    """
    Recursively merge two dictionaries.
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge_dicts(result[key], value)
        elif (
            key in result
            and isinstance(result[key], list)
            and isinstance(value, list)
        ):
            result[key] = result[key] + value
        else:
            result[key] = value
    return result


def product(*iterables):
    """Build cartesian product

    based on from https://docs.python.org/3/library/itertools.html#itertools.product
    """
    # product([{"a": "b"}, {"c": "d"}], [{"e": "f"}, {"g": "h"}]) →
    #   [{'a': 'b', 'e': 'f'}, {'a': 'b', 'g': 'h'}, {'c': 'd', 'e': 'f'}, {'c': 'd', 'g': 'h'}]

    pools = [tuple(pool) for pool in iterables if len(pool) > 0]

    result = [{}]
    for pool in pools:
        result = [deep_merge_dicts(x, y) for x in result for y in pool]

    yield from result
