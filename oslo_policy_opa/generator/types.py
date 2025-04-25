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

import abc
import ast
import logging
import re
import typing

import oslo_policy

from oslo_serialization import jsonutils

from oslo_policy_opa.generator import common

LOG = logging.getLogger(__name__)

GET_FUNCTIONS: dict[str, str] = {
    "floatingip": (
        "get_floatingip(id) := net if {"
        "net := http.send({"
        '  "url": concat("/", ["http://localhost:9098/floatingip", id]),'
        '  "method": "get",'
        '  "timeout": "1s",'
        '  "cache": true'
        "}).body"
        "}"
    ),
    "network": (
        "get_network(id) := net if {"
        "net := http.send({"
        '  "url": concat("/", ["http://localhost:9098/network", id]),'
        '  "method": "get",'
        '  "timeout": "1s",'
        '  "cache": true'
        "}).body"
        "}"
    ),
    "policy": (
        "get_policy(id) := net if {"
        "net := http.send({"
        '  "url": concat("/", ["http://localhost:9098/policy", id]),'
        '  "method": "get",'
        '  "timeout": "1s",'
        '  "cache": true'
        "}).body"
        "}"
    ),
    "security_group": (
        "get_security_group(id) := net if {"
        "net := http.send({"
        '  "url": concat("/", ["http://localhost:9098/security_group", id]),'
        '  "method": "get",'
        '  "timeout": "1s",'
        '  "cache": true'
        "}).body"
        "}"
    ),
}


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
        rules: dict[str, "BaseOpaCheck"],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        raise NotImplementedError()

    def get_opa_policy_test_data(
        self,
        rules: dict[str, "BaseOpaCheck"],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_opa_incremental_rule_name(self) -> str:
        raise NotImplementedError()


class TrueCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.TrueCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return [""]

    def get_opa_incremental_rule_name(self) -> str:
        return "true"

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        return []


class FalseCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.FalseCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return ["false"]

    def get_opa_incremental_rule_name(self) -> str:
        return "false"

    def get_opa_policy_tests(
        self,
        rules: dict[str, "BaseOpaCheck"],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        return [{"input": "false"}]


class AndCheck(BaseOpaCheck):
    rules: list[BaseOpaCheck]

    def __init__(self, oslo_policy_check: oslo_policy._checks.AndCheck):
        super().__init__(oslo_policy_check)
        self.rules = []
        for rule in self.check.rules:
            self.rules.append(convert_oslo_policy_check_to_opa_check(rule))

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
                    subrules = "\n ".join(opa_rule_repr)
                    global_results.setdefault(
                        incremental_rule_name, []
                    ).append(
                        f"#{rule}\n{incremental_rule_name} if {{\n  {subrules}\n}}"
                    )

        return ["\n  ".join(results)]

    def get_opa_incremental_rule_name(self) -> str:
        rule_names = "_and_".join(
            [rule.get_opa_incremental_rule_name() for rule in self.rules]
        )
        return rule_names

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        oslo_rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        tests: list[str] = []
        if oslo_rule_name:
            policy_rule_name = oslo_rule_name.split(":")[-1]
            rule_name = self.get_opa_incremental_rule_name()
            test_datas = self.get_opa_policy_test_data(rules, oslo_rule_name)
            for i, test_data in enumerate(test_datas):
                with_parts = []
                for data_key, data_val in test_data.items():
                    with_parts.append(
                        f"with {data_key} as {jsonutils.dumps(data_val)}"
                    )
                tests.append(
                    f"test_{rule_name}_{i} if {common.normalize_name(policy_rule_name)}.allow {' '.join(with_parts)}"
                )
        return tests

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[typing.Any]:
        tests: list[typing.Any] = []
        test_data: dict = {}
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            test_parts = rule.get_opa_policy_test_data(rules, rule_name)
            if isinstance(rule, AndCheck):
                # A and (B and C) => [A+B+C]
                for test in test_parts:
                    test_data = common.deep_merge_dicts(test_data, test)

            elif isinstance(rule, OrCheck):
                # A and (B or C) => [A+B, A+C] - need to calculate cartesian product once rest is processed
                tests.append(test_parts)

            else:
                # A and B => [A+B]
                for test in test_parts:
                    test_data = common.deep_merge_dicts(test_data, test)

        if len(tests) > 0:
            final_test_data: list[dict] = [test_data]
            for part in tests:
                final_test_data = list(common.product(final_test_data, part))
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
            self.rules.append(convert_oslo_policy_check_to_opa_check(rule))

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
        self,
        rules: dict[str, "BaseOpaCheck"],
        oslo_rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        tests: list[str] = []
        if oslo_rule_name:
            policy_rule_name = common.normalize_name(
                oslo_rule_name.split(":")[-1]
            )
            rule_name = self.get_opa_incremental_rule_name()
            test_datas = self.get_opa_policy_test_data(rules, oslo_rule_name)
            for i, test_data in enumerate(test_datas):
                with_parts = []
                for data_key, data_val in test_data.items():
                    with_parts.append(
                        f"with {data_key} as {jsonutils.dumps(data_val)}"
                    )
                tests.append(
                    f"test_{rule_name}_{i} if {policy_rule_name}.allow {' '.join(with_parts)}"
                )
        return tests

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        tests: list[typing.Any] = []
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            test_parts = rule.get_opa_policy_test_data(rules, rule_name)
            test_data: dict = {}
            if isinstance(rule, AndCheck):
                # A or (B and C) => [A, B+C]
                for test in test_parts:
                    test_data = common.deep_merge_dicts(test_data, test)
                tests.append(test_data)
            elif isinstance(rule, OrCheck):
                # A or (B or C) => [A, B, C]
                for test in test_parts:
                    tests.append(test)

            elif not isinstance(rule, OrCheck):
                # A or B => [A, B]
                for test in test_parts:
                    # test_data = common.deep_merge_dicts(test_data, test_part)
                    tests.append(test)

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
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        return [{"input": {"credentials": {"roles": [self.check.match]}}}]


class RuleCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.RuleCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        rule_name = (
            common.normalize_name(self.check.match)
            if self.check.match != "default"
            else "_default"
        )
        return [f"lib.{rule_name}"]

    def get_opa_incremental_rule_name(self) -> str:
        return common.normalize_name(self.check.match)

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        tests = []
        if rule_name:
            policy_rule_name = common.normalize_name(rule_name.split(":")[-1])
            referred_rule = rules.get(self.check.match)
            if referred_rule:
                test_datas = referred_rule.get_opa_policy_test_data(
                    rules, rule_name
                )
                if test_datas:
                    for i, test_data in enumerate(test_datas):
                        with_parts = []
                        for data_key, data_val in test_data.items():
                            with_parts.append(
                                f"with {data_key} as {jsonutils.dumps(data_val)}"
                            )
                        tests.append(
                            f"test_{policy_rule_name}_{i} if {policy_rule_name}.allow {' '.join(with_parts)}"
                        )
        return tests

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict]:
        referred_rule = rules.get(self.check.match)
        if referred_rule:
            test_data = referred_rule.get_opa_policy_test_data(
                rules, rule_name
            )
            return test_data
        raise RuntimeError(
            f"Cannot generate test data for {self} since the rule is not known"
        )
        return []


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
        right = self.check.match
        check: str = ""
        if right.startswith("%(") and right.endswith(")s"):
            right = f"input.target.{right[2:-2]}"
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
                    rule_name = f"{right}"
                else:
                    rule_name = f"not_{right}"
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
            rule_name = f"creds_{self.check.kind.replace('.', '_')}_eq_{right}"
        return common.normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict[str, typing.Any]]:
        result: dict
        right = self.check.match
        right_is_path = False
        if right.startswith("%(") and right.endswith(")s"):
            # right side is a path
            right = f"target.{right[2:-2]}"
            right_is_path = True
        else:
            # This is a literal
            try:
                right = ast.literal_eval(right)
                if isinstance(right, str):
                    right = f'"{right}"'
                elif isinstance(right, bool):
                    right = right if not reverse else not right
                elif right is None:
                    right = None if not reverse else "foo"
            except ValueError:
                right = f"{right}" if not reverse else "foo"
        try:
            left = ast.literal_eval(self.check.kind)
            if reverse:
                if left is None:
                    left = "foo"
                elif isinstance(left, str):
                    left = f"not_{left}"
            # left side is a literal
            path = right
            value = left
            # result = {"credentials": deep_dict_set(path.split("."), value)}
            result = common.deep_dict_set(path.split("."), value)
        except ValueError:
            # left is a path
            path = self.check.kind
            if not right_is_path:
                # right side is a literal
                value = right
                result = {
                    "credentials": common.deep_dict_set(path.split("."), value)
                }
            else:
                value = "foo"
                result_left = {
                    "credentials": common.deep_dict_set(path.split("."), value)
                }
                result_right = common.deep_dict_set(right.split("."), value)
                result = common.deep_merge_dicts(result_left, result_right)
        return [{"input": result}]


class NeutronOwnerCheck(BaseOpaCheck):
    """Neutron Owner check

    Matches look like:

        - tenant:%(tenant_id)s

    """

    def __init__(self, oslo_policy_check: oslo_policy._checks.GenericCheck):
        super().__init__(oslo_policy_check)
        self.target_field = re.findall(r"^\%\((.*)\)s$", self.check.match)[0]

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        try:
            if ":" in self.target_field:
                res, field = self.target_field.split(":")
                res_field = f"{res}_id"
                if res.startswith("ext_parent_"):
                    res = res[11:]
                if res != "ext_parent" and res in GET_FUNCTIONS:
                    global_results.setdefault("lib", []).append(
                        GET_FUNCTIONS[res]
                    )
                    return [
                        f"lib.get_{res}(input.target.{res_field}).{field} == input.credentials.{self.check.kind}"
                    ]
                else:
                    return [
                        f"# not yet implemented owner check {self.check} {self.target_field}"
                    ]
            else:
                global_results.setdefault("lib", []).append(
                    GET_FUNCTIONS["security_group"]
                )
                return [
                    f"input.target.{self.target_field} == input.credentials.{self.target_field}"
                ]
        except Exception as ex:
            LOG.error(f"Error during neutron owner check conversion: {ex}")
        return [
            f"# not yet implemented owner check {self.check} {self.target_field}"
        ]

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
        return common.normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict[str, typing.Any]]:
        if hasattr(self, "target_field") and ":" in self.target_field:
            res, field = self.target_field.split(":")
            res_field = f"{res}_id"
            if res.startswith("ext_parent_"):
                res = res[11:]
            if res != "ext_parent":
                return [
                    {
                        "input": {
                            "credentials": {self.check.kind: "bar"},
                            "target": {res_field: "foo"},
                        },
                        f"data.lib.get_{res}": {field: "bar"},
                    }
                ]
        return [{"input": {}}]


class NeutronFieldCheck(BaseOpaCheck):
    """Neutron Field check

    Matches look like:

        - field:networs:shared:True
        - field:port:device_owner=~^network:

    """

    def __init__(self, oslo_policy_check: oslo_policy._checks.GenericCheck):
        super().__init__(oslo_policy_check)
        self.resource, field_value = self.check._orig_match.split(":", 1)
        self.field, self.value = field_value.split("=", 1)
        if ":" in self.field:
            self.left = f'input.target["{self.field}"]'
        else:
            self.left = f"input.target.{self.field}"
        if self.value.startswith("~"):
            self.check = f'regex.match("{self.value}", {self.left})'
        else:
            # This is a string so we need to figure out what is it: a string,
            # an int, bool, None, ...
            try:
                self.right = ast.literal_eval(self.value)
                if isinstance(self.right, bool):
                    if self.right:
                        self.right = ""
                    else:
                        self.right = "not"
                elif isinstance(self.right, str):
                    self.right = f'"{self.right}"'
            except (ValueError, SyntaxError):
                pass

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        check: str = ""
        # resource, field_value = self.check._orig_match.split(":", 1)
        # field, value = field_value.split("=", 1)
        # if ":" in field:
        #    left = f'input["{field}"]'
        # else:
        #    left = f"input.{field}"
        if self.value.startswith("~"):
            check = f'regex.match("{self.value}", {self.left})'
        else:
            # This is a string so we need to figure out what is it: a string,
            # an int, bool, None, ...
            try:
                right = ast.literal_eval(self.value)
                if isinstance(right, bool):
                    if right:
                        right = ""
                    else:
                        right = "not"
                    check = f"{self.left}{right}"
                elif isinstance(right, str):
                    right = f'"{right}"'
                    check = f"{self.left} == {right}"
            except (ValueError, SyntaxError):
                check = f'{self.left} == "{self.value}"'
        if self.resource == "networks" and self.field == "shared":
            if right == "":
                right = "true"
            elif right == "not":
                right = "false"
            check = f'net := lib.get_network(input.target.network_id)\nnet["{self.field}"] == {right}'
            global_results.setdefault("lib", []).append(
                GET_FUNCTIONS["network"]
            )
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
        return common.normalize_name(rule_name)

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict[str, typing.Any]]:
        if self.resource == "networks" and self.field == "shared":
            return [
                {
                    "input": {"target": {"network_id": "foo"}},
                    "data.lib.get_network": {"shared": True},
                }
            ]
        elif (
            self.check
            == 'regex.match("~^network:", input.target.device_owner)'
        ):
            return [{"input": {"target": {"device_owner": "network:foo"}}}]
        else:
            value: typing.Any
            try:
                right = ast.literal_eval(self.value)
                if isinstance(right, bool):
                    value = right
                elif isinstance(right, str):
                    value = f'"{right}"'
            except (ValueError, SyntaxError):
                value = self.value
            td = common.deep_dict_set(
                ["input", "target", self.field],
                value if not reverse else "foo",
            )
            return [td]


class NotCheck(BaseOpaCheck):
    rule: BaseOpaCheck

    def __init__(self, oslo_policy_check: oslo_policy._checks.NotCheck):
        super().__init__(oslo_policy_check)
        self.rule = convert_oslo_policy_check_to_opa_check(self.check.rule)

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
                "not and/or is not supported yet", self.rule
            )
        return [result]

    def get_opa_incremental_rule_name(self) -> str:
        return "not_" + self.rule.get_opa_incremental_rule_name()

    def get_opa_policy_tests(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: typing.Optional[str] = None,
    ) -> list[str]:
        return []

    def get_opa_policy_test_data(
        self,
        rules: dict[str, BaseOpaCheck],
        rule_name: str,
        reverse: bool = False,
    ) -> list[dict[str, typing.Any]]:
        test_data = self.rule.get_opa_policy_test_data(
            rules, rule_name, reverse=True
        )
        return test_data


def convert_oslo_policy_check_to_opa_check(
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
