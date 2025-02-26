#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import ast
import logging
import sys
import textwrap
import typing
import pathlib
import warnings
import yaml

from oslo_config import cfg
import oslo_policy
import stevedore

from oslo_policy import policy
from oslo_serialization import jsonutils

LOG = logging.getLogger(__name__)

GENERATOR_OPTS = [
    cfg.StrOpt(
        "output-file", help="Path of the file to write to. Defaults to stdout."
    ),
    cfg.StrOpt(
        "output-dir", help="Path of the file to write to. Defaults to stdout."
    ),
]

RULE_OPTS = [
    cfg.MultiStrOpt(
        "namespace",
        help='Option namespace(s) under "oslo.policy.policies" in '
        "which to query for options.",
    )
]

ENFORCER_OPTS = [
    cfg.StrOpt(
        "namespace",
        help='Option namespace under "oslo.policy.enforcer" in '
        "which to look for a policy.Enforcer.",
    )
]


def normalize_name(name: str) -> str:
    return name.translate(
        str.maketrans({":": "_", "-": "_", "*": "any"})
    ).lower()


def deep_dict_set(path_parts: list[str], val) -> dict[str, typing.Any]:
    """Set dictionary value by path"""
    result: dict[str, typing.Any] = {}
    if len(path_parts) > 1:
        result[path_parts[0]] = deep_dict_set(path_parts[1:], val)
    elif len(path_parts) == 1:
        result[path_parts[0]] = val
    else:
        raise NotImplementedError(f"deep set invoked with unclear path {path}")
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


def _get_enforcer(namespace):
    """Find a policy.Enforcer via an entry point with the given namespace.

    :param namespace: a namespace under oslo.policy.enforcer where the desired
        enforcer object can be found.
    :returns: a policy.Enforcer object
    """
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


class BaseOpaCheck:
    def __init__(self, oslo_policy_check: oslo_policy._checks.BaseCheck):
        self.check = oslo_policy_check

    def __str__(self):
        return self.check.__str__()

    def get_header(self):
        return "if {\n"

    def get_footer(self):
        return "}"

    @abc.abstractmethod
    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_opa_incremental_rule_name(self) -> str:
        raise NotImplementedError()


class TrueCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.TrueCheck):
        super().__init__(oslo_policy_check)

    def get_header(self):
        return ""

    def get_footer(self):
        return ""

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return []

    def get_opa_incremental_rule_name(self) -> str:
        return "true"

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], rule_name: str
    ) -> dict:
        return {}


class FalseCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.FalseCheck):
        super().__init__(oslo_policy_check)

    def get_header(self):
        return ""

    def get_footer(self):
        return ""

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return []

    def get_opa_incremental_rule_name(self) -> str:
        return "false"

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], rule_name: str
    ) -> dict:
        return "false"


class AndCheck(BaseOpaCheck):
    rules: list[BaseOpaCheck]

    def __init__(self, oslo_policy_check: oslo_policy._checks.AndCheck):
        super().__init__(oslo_policy_check)
        self.rules = []
        for rule in self.check.rules:
            self.rules.append(_convert_oslo_policy_check_to_opa_check(rule))

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        results: list = []
        for rule in self.rules:
            opa_rule_repr = rule.get_opa_policy(global_results)
            # AndCheck returns single string
            if len(opa_rule_repr) == 1 and not isinstance(rule, AndCheck):
                results.append(opa_rule_repr[0])
            elif isinstance(rule, OrCheck):
                # For OrCheck results we need to produce multiple entries for every OR part
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(incremental_rule_name)
                if incremental_rule_name not in global_results:
                    global_results.setdefault(
                        incremental_rule_name, []
                    ).extend(
                        [
                            f"#{rule}\n{incremental_rule_name} if {{\n  {part}\n}}"
                            for part in opa_rule_repr
                        ]
                    )

            else:
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(incremental_rule_name)
                if incremental_rule_name not in global_results:
                    global_results.setdefault(
                        incremental_rule_name, []
                    ).append(
                        f"#{rule}\n{incremental_rule_name} if {{\n  {'\n  '.join(opa_rule_repr)}\n}}"
                    )

        return ["\n  ".join(results)]

    def get_opa_incremental_rule_name(self) -> str:
        rule_names = "_and_".join(
            [rule.get_opa_incremental_rule_name() for rule in self.rules]
        )
        return rule_names

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        tests: list[str] = []
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            # rule_tests: list[str] = rule.get_opa_policy_tests(
            #    policy_tests, rule_name
            # )
            if not isinstance(rule, AndCheck) and not isinstance(
                rule, OrCheck
            ):
                test_data = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                tests.append(
                    f"test_{rule_name} if {jsonutils.dumps(test_data)}"
                )
            elif isinstance(rule, AndCheck):
                test_datas: list[dict] = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                cnt = 0
                for test_data in test_datas:
                    tests.append(
                        f"test_{rule_name}_{cnt} if {{ {rule_name}.allow with input as {jsonutils.dumps(test_data)}}}"
                    )
                    cnt += 1
            elif isinstance(rule, OrCheck):
                test_datas: list[dict] = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                cnt = 0
                for test_data in test_datas:
                    tests.append(
                        f"test_{rule_name}_{cnt} if {{ {rule_name}.allow with input as {jsonutils.dumps(test_data)}}}"
                    )
                    cnt += 1
            else:
                tests.append(
                    f"test_{rule_name} if {{ {rule_name}.allow with input as false}}"
                )
        return tests

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], rule_name: str
    ) -> list[typing.Any]:
        tests: list[typing.Any] = []
        test_data: dict = {}
        and_or_mode: bool = False
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            test_parts = rule.get_opa_policy_test_data(policy_tests, rule_name)
            if isinstance(rule, AndCheck):
                # A and (B and C) => [A+B+C]
                for test in test_parts:
                    test_data = deep_merge_dicts(test_data, test)

            elif isinstance(rule, OrCheck):
                # A and (B or C) => [A+B, A+C] - need to calculate cartesian product once rest is processed
                tests.append(test_parts)

            else:
                # A and B => [A+B]
                if test_parts:
                    test_data = deep_merge_dicts(test_data, test_parts)

        if len(tests) > 0:
            final_test_data: list[dict] = []
            for part in tests:
                final_test_data = list(product(final_test_data, part))
            return final_test_data

        else:
            tests.append(test_data)
        return tests


class OrCheck(BaseOpaCheck):
    rules: list[BaseOpaCheck]

    def __init__(self, oslo_policy_check: oslo_policy._checks.OrCheck):
        super().__init__(oslo_policy_check)
        self.rules = []
        for rule in self.check.rules:
            self.rules.append(_convert_oslo_policy_check_to_opa_check(rule))

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        results: list = []
        for rule in self.rules:
            opa_rule_repr = rule.get_opa_policy(global_results)
            # AndCheck returns single string
            if len(opa_rule_repr) == 1 and not isinstance(rule, AndCheck):
                results.append(f"#{rule}\n{opa_rule_repr[0]}")

            elif isinstance(rule, OrCheck):
                # For OrCheck results we need to produce multiple entries for every OR part
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(incremental_rule_name)
                if incremental_rule_name not in global_results:
                    global_results.setdefault(
                        incremental_rule_name, []
                    ).extend(
                        [
                            f"#{rule}\n{incremental_rule_name} if {{\n  {part}\n}}"
                            for part in opa_rule_repr
                        ]
                    )

            else:
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(incremental_rule_name)

                if incremental_rule_name not in global_results:
                    global_res = global_results.setdefault(
                        incremental_rule_name, []
                    )
                    for subrule in opa_rule_repr:
                        global_res.append(
                            f"#{rule}\n{incremental_rule_name} if {{\n  {subrule}\n}}"
                        )
        return results

    def get_opa_incremental_rule_name(self) -> str:
        rule_names = "_or_".join(
            [rule.get_opa_incremental_rule_name() for rule in self.rules]
        )
        return rule_names

    def get_opa_policy_tests(
        self, policy_tests: dict[str, list[str]], oslo_rule_name: str
    ) -> list[str]:
        tests: list[str] = []
        policy_rule_name = oslo_rule_name.split(":")[-1]
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            if not isinstance(rule, AndCheck) and not isinstance(
                rule, OrCheck
            ):
                test_data = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                if test_data:
                    tests.append(
                        f"test_{rule_name} if {{ {policy_rule_name}.allow with input as {jsonutils.dumps(test_data)}}}"
                    )
            elif isinstance(rule, AndCheck):
                test_datas: list[dict] = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                resulting_data = {}
                cnt = 0
                for test_data in test_datas:
                    resulting_data = deep_merge_dicts(
                        resulting_data, test_data
                    )
                    tests.append(
                        f"test_{rule_name}_{cnt} if {{ {policy_rule_name}.allow with input as {jsonutils.dumps(test_data)}}}"
                    )
                    cnt += 1
            elif isinstance(rule, OrCheck):
                # one rule of or is itself an or - just dump them individually
                test_datas: list[dict] = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                cnt = 0
                for test_data in test_datas:
                    tests.append(
                        f"test_{rule_name}_{cnt} if {{ {policy_rule_name}.allow with input as {jsonutils.dumps(test_data)}}}"
                    )
                    cnt += 1
            else:
                tests.append(
                    f"test_{rule_name} if {{ {policy_rule_name}.allow with input as false}}"
                )
        return tests

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], rule_name: str
    ) -> list[typing.Any]:
        tests: list[typing.Any] = []
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            test_data: dict = {}
            if isinstance(rule, AndCheck):
                # A or (B and C) => [A, B+C]
                test_parts = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                for test in test_parts:
                    test_data = deep_merge_dicts(test_data, test)
                tests.append(test_data)
            elif isinstance(rule, OrCheck):
                # A or (B or C) => [A, B, C]
                test_parts = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                for test in test_parts:
                    tests.append(test_data)

            elif not isinstance(rule, OrCheck):
                # A or B => [A, B]
                test_part = rule.get_opa_policy_test_data(
                    policy_tests, rule_name
                )
                test_data = deep_merge_dicts(test_data, test_part)
                tests.append(test_data)

        return tests


class RoleCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.RoleCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return [f'"{self.check.match}" in input.credentials.roles']

    def get_opa_incremental_rule_name(self) -> str:
        return self.check.match

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> dict:
        return {"credentials": {"roles": [self.check.match]}}


class RuleCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.RuleCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return [f"lib.{normalize_name(self.check.match)}"]

    def get_opa_incremental_rule_name(self) -> str:
        return self.check.match

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> dict:
        return {}


class GenericCheck(BaseOpaCheck):
    """Generic check

    Matches look like:

        - tenant:%(tenant_id)s
        - role:compute:admin
        - True:%(user.enabled)s
        - 'Member':%(role.name)s
        - domain_id:None
        - is_admin:1

    """

    def __init__(self, oslo_policy_check: oslo_policy._checks.GenericCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        result: str
        right = self.check.match
        check: str = ""
        if right.startswith("%(") and right.endswith(")s"):
            right = f"input.{right[2:-2]}"
        else:
            # This is a string so we need to figure out what is it: a string,
            # an int, bool, None, ...
            try:
                right = ast.literal_eval(right)
                if isinstance(right, str):
                    right = f'"{right}"'
            except ValueError:
                right = f'"{right}"'
        try:
            left = ast.literal_eval(self.check.kind)
            if isinstance(left, bool):
                if left:
                    left = ""
                else:
                    left = "not "
                check = f"{left}{right}"
            elif isinstance(left, int):
                check = f"{left} == {right}"
            elif isinstance(left, str):
                check = f'"{left}" == {right}'
            elif left is None:
                check = f"is_null({right})"
            else:
                raise NotImplementedError(
                    f"translation of {self.check.kind} is not supported yet"
                )
        except ValueError:
            if right is None:
                check = f"is_null(input.credentials.{self.check.kind})"
            elif isinstance(right, bool):
                if right:
                    check = f"input.credentials.{self.check.kind}"
                else:
                    check = f"not input.credentials.{self.check.kind}"
            else:
                check = f"input.credentials.{self.check.kind} == {right}"
        return [check]

    def get_opa_incremental_rule_name(self) -> str:
        rule_name: str
        right = self.check.match
        if right.startswith("%(") and right.endswith(")s"):
            right = "input_" + "_".join(right[2:-2].split(".")[0:])
        try:
            left = ast.literal_eval(self.check.kind)
            if isinstance(left, bool):
                if left:
                    left = ""
                else:
                    left = "not"
                rule_name = f"{left}_{right}"
            elif isinstance(left, int):
                rule_name = f"{left}_is_{right}"
            elif isinstance(left, str):
                rule_name = f"{left}_is_{right}"
            elif left is None:
                rule_name = f"{right}_empty"
            else:
                raise NotImplementedError(
                    f"translation of {self.check.kind} is not supported yet"
                )
        except ValueError:
            rule_name = f"creds_{self.check.kind}_eq_{right}"
        return normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], oslo_rule_name: str
    ) -> dict[str, typing.Any]:
        result: dict
        right = self.check.match
        right_is_path = False
        if right.startswith("%(") and right.endswith(")s"):
            # right side is a path
            right = f"{right[2:-2]}"
            right_is_path = True
        else:
            # This is a literal
            try:
                right = ast.literal_eval(right)
                if isinstance(right, str):
                    right = f'"{right}"'
            except ValueError:
                right = f"{right}"
        try:
            left = ast.literal_eval(self.check.kind)
            # left side is a literal
            path = right
            value = left
            # result = {"credentials": deep_dict_set(path.split("."), value)}
            result = deep_dict_set(path.split("."), value)
        except ValueError:
            # left is a path
            path = self.check.kind
            if not right_is_path:
                # right side is a literal
                value = right
                result = {"credentials": deep_dict_set(path.split("."), value)}
            else:
                value = "foo"
                result_left = {
                    "credentials": deep_dict_set(path.split("."), value)
                }
                result_right = deep_dict_set(right.split("."), value)
                result = deep_merge_dicts(result_left, result_right)
        return result


class NeutronOwnerCheck(BaseOpaCheck):
    """Neutron Owner check

    Matches look like:

        - tenant:%(tenant_id)s

    """

    def __init__(self, oslo_policy_check: oslo_policy._checks.GenericCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return ["# not yet implemented owner check"]

    def get_opa_incremental_rule_name(self) -> str:
        rule_name: str
        right = self.check.match
        if right.startswith("%(") and right.endswith(")s"):
            right = "_".join(right[2:-2].split(".")[1:])
        try:
            left = ast.literal_eval(self.check.kind)
            if isinstance(left, bool):
                if left:
                    left = ""
                else:
                    left = "not"
                rule_name = f"{left}_{right}"
            elif isinstance(left, int):
                rule_name = f"{left}_is_{right}"
            elif isinstance(left, str):
                rule_name = f"{left}_is_{right}"
            elif left is None:
                rule_name = f"{right}_empty"
            else:
                raise NotImplementedError(
                    f"translation of {self.check.kind} is not supported yet"
                )
        except ValueError:
            rule_name = f"{self.check.kind}_{right}"
        return normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], oslo_rule_name: str
    ) -> dict:
        return {}


class NeutronFieldCheck(BaseOpaCheck):
    """Neutron Field check

    Matches look like:

        - field:networs:shared:True
        - field:port:device_owner=~^network:

    """

    def __init__(self, oslo_policy_check: oslo_policy._checks.GenericCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        check: str = ""
        resource, field_value = self.check._orig_match.split(":", 1)
        field, value = field_value.split("=", 1)
        if ":" in field:
            left = f'input["{field}"]'
        else:
            left = f"input.{field}"
        if value.startswith("~"):
            check = f'regex.match("{value}", {left})'
        else:
            # This is a string so we need to figure out what is it: a string,
            # an int, bool, None, ...
            try:
                right = ast.literal_eval(value)
                if isinstance(right, bool):
                    if right:
                        right = ""
                    else:
                        right = "not"
                    check = f"{left}{right}"
                elif isinstance(right, str):
                    right = f'"{right}"'
                    check = f"{left} == {right}"
            except (ValueError, SyntaxError):
                check = f'{left} == "{value}"'
        if resource == "networks" and field == "shared":
            check = check + "\n\t# or fetch and check"
        return [check]

    def get_opa_incremental_rule_name(self) -> str:
        rule_name: str
        right = self.check.match
        if right.startswith("%(") and right.endswith(")s"):
            right = "_".join(right[2:-2].split(".")[1:])
        try:
            left = ast.literal_eval(self.check.kind)
            if isinstance(left, bool):
                if left:
                    left = ""
                else:
                    left = "not"
                rule_name = f"{left}_{right}"
            elif isinstance(left, int):
                rule_name = f"{left}_is_{right}"
            elif isinstance(left, str):
                rule_name = f"{left}_is_{right}"
            elif left is None:
                rule_name = f"{right}_empty"
            else:
                raise NotImplementedError(
                    f"translation of {self.check.kind} is not supported yet"
                )
        except ValueError:
            rule_name = f"{self.check.kind}_{right}"
        return normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(self):
        return {}


class NotCheck(BaseOpaCheck):
    rule: BaseOpaCheck

    def __init__(self, oslo_policy_check: oslo_policy._checks.NotCheck):
        super().__init__(oslo_policy_check)
        self.rule = _convert_oslo_policy_check_to_opa_check(self.check.rule)

    def __str__(self):
        return self.check.__str__()

    def get_header(self):
        return ""

    def get_footer(self):
        return ""

    def get_opa_policy(self, global_results: dict[str, list[str]]):
        if not isinstance(self.rule, AndCheck) and not isinstance(
            self.rule, OrCheck
        ):
            opa_rule_repr = self.rule.get_opa_policy(global_results)
            if len(opa_rule_repr) == 1:
                result = f"not {opa_rule_repr[0]}"
            else:
                raise NotImplementedError(
                    "Negation base returned multiple rules"
                )
        else:
            raise NotImplementedError(
                f"not and/or is not supported yet", self.rule
            )
        return [result]

    def get_opa_incremental_rule_name(self) -> str:
        return "not_" + self.rule.get_opa_incremental_rule_name()

    def get_opa_policy_tests(
        self,
        policy_tests: dict[str, list[str]],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self, policy_tests: dict[str, list[str]], rule_name: str
    ) -> dict:
        return {}


def _convert_oslo_policy_check_to_opa_check(
    opc: type[oslo_policy._checks.BaseCheck],
) -> BaseOpaCheck:
    """Convert oslo_policy._checks.BaseCheck into the internal interpretation
    of the OpenPolicyAgent conversion

    :param opc: oslo_policy check
    :param namespace: check namespace
    :returns: BaseOpaCheck subtype representing the check
    """
    if isinstance(opc, oslo_policy._checks.AndCheck):
        return AndCheck(opc)
    elif isinstance(opc, oslo_policy._checks.OrCheck):
        return OrCheck(opc)
    elif isinstance(opc, oslo_policy._checks.RoleCheck):
        return RoleCheck(opc)
    elif isinstance(opc, oslo_policy._checks.RuleCheck):
        return RuleCheck(opc)
    elif isinstance(opc, oslo_policy._checks.GenericCheck):
        return GenericCheck(opc)
    elif isinstance(opc, oslo_policy._checks.NotCheck):
        return NotCheck(opc)
    elif isinstance(opc, oslo_policy._checks.TrueCheck):
        return TrueCheck(opc)
    elif isinstance(opc, oslo_policy._checks.FalseCheck):
        return FalseCheck(opc)
    elif opc.__class__.__module__ == "neutron.policy":
        if opc.__class__.__name__ == "OwnerCheck":
            return NeutronOwnerCheck(opc)
        elif opc.__class__.__name__ == "FieldCheck":
            return NeutronFieldCheck(opc)
    raise NotImplementedError(f"Check {type(opc)} is not supported")


def _translate_default_rule(
    default: oslo_policy.policy._BaseRule,
    results: dict[str, list[str]],
    policy_tests: dict[str, list[str]],
    namespace: typing.Optional[str] = None,
):
    """Create a yaml node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param results: A dictionary with relevant policy rules that is shared globally
    :param namespace: Namespace name that is prepended to the Rule checks for
        structuring a policy rule into dedicated policy files.
    :returns: A string containing a yaml representation of the RuleDefault
    """  # noqa: E501

    # LOG.info(f"Converting {default.check}")
    opa_rule = _convert_oslo_policy_check_to_opa_check(default.check)
    lib_part_rules = {}
    opa_part_rules = opa_rule.get_opa_policy(lib_part_rules)
    opa_rule_tests = opa_rule.get_opa_policy_tests(policy_tests, default.name)
    rule_description = _get_rule_help(default)
    # LOG.info(f"Converted {default} {getattr(default, 'operations', None)} into {opa_part_rules}")
    if hasattr(default, "operations") and default.operations:
        # This is the final role
        results.setdefault(default.name, [rule_description])
        results[default.name].extend(
            [
                f"allow {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
                for rule in opa_part_rules
            ]
        )
        results[default.name].extend(
            [
                f"{subrule}\n"
                for rule in lib_part_rules.values()
                for subrule in rule
            ]
        )
        policy_tests[default.name] = opa_rule_tests
    else:
        # a library "rule"
        LOG.info(
            f"A library rule {default} with {opa_part_rules} and {lib_part_rules}"
        )
        if default.name == "default":
            # Skip the library "default" rule
            return
        results.setdefault("lib", [])
        results["lib"].extend(
            [
                f"{normalize_name(default.name)} {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
                for rule in opa_part_rules
            ]
        )
        if lib_part_rules:
            results["lib"].extend(
                [
                    f"{subrule}\n"
                    for rule in lib_part_rules.values()
                    for subrule in rule
                ]
            )

    return


def _format_help_text(description):
    """Format a comment for a policy based on the description provided.

    :param description: A string with helpful text.
    :returns: A line wrapped comment, or blank comment if description is None
    """
    if not description:
        return "#"

    formatted_lines = []
    paragraph = []

    def _wrap_paragraph(lines):
        return textwrap.wrap(
            " ".join(lines), 70, initial_indent="# ", subsequent_indent="# "
        )

    for line in description.strip().splitlines():
        if not line.strip():
            # empty line -> line break, so dump anything we have
            formatted_lines.extend(_wrap_paragraph(paragraph))
            formatted_lines.append("#")
            paragraph = []
        elif len(line) == len(line.lstrip()):
            # no leading whitespace = paragraph, which should be wrapped
            paragraph.append(line.rstrip())
        else:
            # leading whitespace - literal block, which should not be wrapping
            if paragraph:
                # ...however, literal blocks need a new line before them to
                # delineate things
                # TODO(stephenfin): Raise an exception here and stop doing
                # anything else in oslo.policy 2.0
                warnings.warn(
                    "Invalid policy description: literal blocks must be "
                    "preceded by a new line. This will raise an exception in "
                    f"a future version of oslo.policy:\n{description}",
                    FutureWarning,
                )
                formatted_lines.extend(_wrap_paragraph(paragraph))
                formatted_lines.append("#")
                paragraph = []

            formatted_lines.append(f"# {line.rstrip()}")

    if paragraph:
        # dump anything we might still have in the buffer
        formatted_lines.extend(_wrap_paragraph(paragraph))

    return "\n".join(formatted_lines)


def _get_rule_help(default: oslo_policy.policy._BaseRule) -> str:
    text: str = f'"{default.name}": "{default.check_str}"\n'
    op = ""
    if hasattr(default, "operations"):
        for operation in default.operations:
            if operation["method"] and operation["path"]:
                op += "# {method}  {path}\n".format(
                    method=operation["method"], path=operation["path"]
                )
    intended_scope = ""
    if getattr(default, "scope_types", None) is not None:
        intended_scope = (
            "# Intended scope(s): " + ", ".join(default.scope_types) + "\n"
        )
    comment = "#"  # if comment_rule else ''
    text = f"{op}{intended_scope}{comment}{text}\n"
    if default.description:
        text = _format_help_text(default.description) + "\n" + text

    return text


def _generate_opa_policy(namespace, output_dir=None):
    """Generate a OPA policies.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param output_file: The path of a file to output to. stdout used if None.
    """
    generate_policy_test: bool = True
    enforcer = _get_enforcer(namespace)
    # Ensure that files have been parsed
    enforcer.load_rules()

    file_rules = [
        policy.RuleDefault(name, default.check_str)
        for name, default in enforcer.file_rules.items()
    ]
    registered_rules = [
        policy.RuleDefault(name, default.check_str)
        for name, default in enforcer.registered_rules.items()
        if name not in enforcer.file_rules
    ]

    policies = get_policies_dict([namespace])

    opa_policies: dict[str, list[str]] = {}
    opa_test_policies: dict[str, list[str]] = {}
    for section in sorted(policies.keys()):
        rule_defaults = policies[section]
        for rule_default in rule_defaults:
            if rule_default.deprecated_since:
                continue
            _translate_default_rule(
                rule_default,
                opa_policies,
                opa_test_policies,
                namespace=namespace,
            )

    lib_output = None
    if output_dir:
        lib_fname = pathlib.Path(output_dir, namespace).with_suffix(".rego")
        lib_fname.parent.mkdir(parents=True, exist_ok=True)
        lib_output = open(lib_fname, "w") if output_dir else sys.stdout
        lib_output.write(f"package lib\n\n")
    for rule, opa_policy in opa_policies.items():
        LOG.info(f"Writing rule {rule}")
        if rule != "lib":
            # final policy rule
            if output_dir:
                LOG.info(f"Prepare to write {rule}")
                fname_parts = rule.split(":")
                fname_parts[-1] = f"{fname_parts[-1]}.rego"
                fname = pathlib.Path(output_dir, *fname_parts)
                fname.parent.mkdir(parents=True, exist_ok=True)
                output = open(fname, "w")
            else:
                output = sys.stdout

            output.write(
                f"package {rule.replace(':', '.').replace('-', '_')}\n\n"
            )
            output.write(f"import data.lib\n\n")
            for opa_policy_rule in opa_policy:
                output.write(opa_policy_rule)
                output.write("\n")
            if output != sys.stdout:
                output.close()

            tests = opa_test_policies.get(rule)
            if generate_policy_test and tests:
                fname_parts = rule.split(":")
                fname_parts[-1] = f"{fname_parts[-1]}_test.rego"
                packagename_parts = rule.split(":")
                fname = pathlib.Path(output_dir, *fname_parts)
                fname.parent.mkdir(parents=True, exist_ok=True)
                output = open(fname, "w")

                output.write(f"package {normalize_name(rule)}_test\n\n")
                output.write(f"import data.{'.'.join(packagename_parts)}\n\n")
                num: int = 1
                for opa_policy_rule_test in tests:
                    output.write(opa_policy_rule_test)
                    output.write("\n")
                    num += 1
                if output != sys.stdout:
                    output.close()
        else:
            # for opa_policy_rule in opa_policy:
            if lib_output:
                for opa_policy_rule in opa_policy:
                    lib_output.write(opa_policy_rule.replace(f"lib.", ""))
                    lib_output.write("\n\n")
    if lib_output:
        lib_output.close()


def _format_rule_default_yaml(
    default, include_help=True, comment_rule=False, add_deprecated_rules=True
):
    """Create a yaml node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param comment_rule: By default rules will be commented out in generated
        yaml format text. If you want to keep few or all rules uncommented then
        pass this arg as False.
    :param add_deprecated_rules: Whether to add the deprecated rules in format
        text.
    :returns: A string containing a yaml representation of the RuleDefault
    """  # noqa: E501
    text = '"{name}": "{check_str}"\n'.format(
        name=default.name,
        check_str=f"opa:{normalize_name(default.name.replace(':', '/'))}",
    )

    if include_help:
        op = ""
        if hasattr(default, "operations"):
            for operation in default.operations:
                if operation["method"] and operation["path"]:
                    op += "# {method}  {path}\n".format(
                        method=operation["method"],
                        path=operation["path"],
                    )
        intended_scope = ""
        if getattr(default, "scope_types", None) is not None:
            intended_scope = (
                "# Intended scope(s): " + ", ".join(default.scope_types) + "\n"
            )
        comment = "#" if comment_rule else ""
        text = f"{op}{intended_scope}{comment}{text}\n"
        if default.description:
            text = _format_help_text(default.description) + "\n" + text

    if add_deprecated_rules and default.deprecated_for_removal:
        text = (
            f'# DEPRECATED\n# "{default.name}" has been deprecated since '
            f"{default.deprecated_since}.\n{_format_help_text(default.deprecated_reason)}\n{text}"
        )
    elif add_deprecated_rules and default.deprecated_rule:
        deprecated_reason = (
            default.deprecated_rule.deprecated_reason
            or default.deprecated_reason
        )
        deprecated_since = (
            default.deprecated_rule.deprecated_since
            or default.deprecated_since
        )

        # This issues a deprecation warning but aliases the old policy name
        # with the new policy name for compatibility.
        deprecated_text = (
            f'"{default.deprecated_rule.name}":"{default.deprecated_rule.check_str}" has been deprecated '
            f'since {deprecated_since} in favor of "{default.name}":"{default.check_str}".'
        )
        text = f"{text}# DEPRECATED\n{_format_help_text(deprecated_text)}\n{_format_help_text(deprecated_reason)}\n"

        text += "\n"

    return text


def _sort_and_format_by_section(
    policies, include_help=True, exclude_deprecated=False
):
    """Generate a list of policy section texts

    The text for a section will be created and returned one at a time. The
    sections are sorted first to provide for consistent output.

    Text is created in yaml format. This is done manually because PyYaml
    does not facilitate returning comments.

    :param policies: A dict of {section1: [rule_default_1, rule_default_2],
        section2: [rule_default_3]}
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
        defaults to False.
    """
    for section in sorted(policies.keys()):
        rule_defaults = policies[section]
        for rule_default in rule_defaults:
            if hasattr(rule_default, "operations"):
                yield _format_rule_default_yaml(
                    rule_default,
                    include_help=include_help,
                    add_deprecated_rules=not exclude_deprecated,
                )


def on_load_failure_callback(*args, **kwargs):
    raise


def _generate_sample(
    namespaces, output_file=None, include_help=True, exclude_deprecated=False
):
    """Generate a sample policy file.

    List all of the policies available via the namespace specified in the
    given configuration and write them to the specified output file.

    :param namespaces: a list of namespaces registered under 
        'oslo.policy.policies'. Stevedore will look here for policy options.
    :param output_file: The path of a file to output to. stdout used if None.
    :param include_help: True, generates a sample-policy file with help text
        along with rules in which everything is commented out. False, generates
        a sample-policy file with only rules.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
        defaults to False.
    """
    policies = get_policies_dict(namespaces)

    output_file = open(output_file, "w") if output_file else sys.stdout

    sections_text = []
    for section in _sort_and_format_by_section(
        policies,
        include_help=include_help,
        exclude_deprecated=exclude_deprecated,
    ):
        sections_text.append(section)

    output_file.writelines(sections_text)
    if output_file != sys.stdout:
        output_file.close()


def generate_sample(args=None, conf=None):
    logging.basicConfig(level=logging.WARN)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS)
    conf(args)
    _generate_sample(
        conf.namespace, output_file=conf.output_file, exclude_deprecated=False
    )


def generate_opa_policy(args=None):
    logging.basicConfig(level=logging.INFO)
    conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf.register_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf(args)
    _generate_opa_policy(conf.namespace, conf.output_dir)
