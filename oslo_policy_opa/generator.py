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
        "output-dir", help="Path of the file to write to. Defaults to stdout."
    )
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
        raise KeyError('Namespace "%s" not found.' % namespace)
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
        self, policy_tests: dict[str, list[str]]
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
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        return []

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return []

    def get_opa_incremental_rule_name(self) -> str:
        return "true"


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
            else:
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(f"lib.{incremental_rule_name}")
                if incremental_rule_name not in global_results:
                    global_results.setdefault(
                        incremental_rule_name, []
                    ).append(
                        f"{incremental_rule_name} if {{\n  {'\n  '.join(opa_rule_repr)}\n}}"
                    )

        return ["\n  ".join(results)]

    def get_opa_incremental_rule_name(self) -> str:
        rule_names = "_and_".join(
            [rule.get_opa_incremental_rule_name() for rule in self.rules]
        )
        return rule_names

    def get_opa_policy_tests(
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        tests: list[str] = []
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            rule_tests: list[str] = rule.get_opa_policy_tests(policy_tests)
            if not isinstance(rule, AndCheck) and not isinstance(
                rule, OrCheck
            ):
                if len(rule_tests) == 1:
                    tests.append(f"test_{rule_name} if {{rule_tests[0]}}")
                elif len(rule_tests) > 1:
                    raise NotImplementedError(
                        f"Testing of the rule {rule} is not possible yet"
                    )
                else:
                    tests.append(f"test_{rule_name} if {{false}}")
            else:
                tests.append(
                    f"test_{rule_name} if {{ data.{rule_name}.allow with input as false}}"
                )
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
                results.append(opa_rule_repr[0])
            else:
                incremental_rule_name = rule.get_opa_incremental_rule_name()
                results.append(f"lib.{incremental_rule_name}")

                if incremental_rule_name not in global_results:
                    global_res = global_results.setdefault(
                        incremental_rule_name, []
                    )
                    for subrule in opa_rule_repr:
                        global_res.append(
                            f"{incremental_rule_name} if {{\n  {subrule}\n}}"
                        )
        return results

    def get_opa_incremental_rule_name(self) -> str:
        rule_names = "_or_".join(
            [rule.get_opa_incremental_rule_name() for rule in self.rules]
        )
        return rule_names

    def get_opa_policy_tests(
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        tests: list[str] = []
        for rule in self.rules:
            rule_name = rule.get_opa_incremental_rule_name()
            rule_tests: list[str] = rule.get_opa_policy_tests(policy_tests)
            if not isinstance(rule, AndCheck) and not isinstance(
                rule, OrCheck
            ):
                if len(rule_tests) == 1:
                    tests.append(f"test_{rule_name} if {{rule_tests[0]}}")
                elif len(rule_tests) > 1:
                    raise NotImplementedError(
                        f"Testing of the rule {rule} is not possible yet"
                    )
                else:
                    tests.append(
                        f"test_{rule_name} if {{ data.{rule_name}.allow with input as false}}"
                    )
            else:
                tests.append(
                    f"test_{rule_name} if {{ data.{rule_name}.allow with input as false}}"
                )
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
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        return []


class RuleCheck(BaseOpaCheck):
    def __init__(self, oslo_policy_check: oslo_policy._checks.RuleCheck):
        super().__init__(oslo_policy_check)

    def get_opa_policy(
        self, global_results: dict[str, list[str]]
    ) -> list[str]:
        return [f"lib.{self.check.match}"]

    def get_opa_incremental_rule_name(self) -> str:
        return self.check.match

    def get_opa_policy_tests(
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
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
        return rule_name

    def get_opa_policy_tests(
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        return []


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
        self, policy_tests: dict[str, list[str]]
    ) -> list[str]:
        return []


def _convert_oslo_policy_check_to_opa_check(
    opc: typing.Type[oslo_policy._checks.BaseCheck],
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

    opa_rule = _convert_oslo_policy_check_to_opa_check(default.check)
    opa_part_rules = opa_rule.get_opa_policy(results)
    opa_rule_tests = opa_rule.get_opa_policy_tests(policy_tests)
    rule_description = _get_rule_help(default)
    results.setdefault(default.name, [rule_description])
    if ":" in default.name:
        # This is the final role
        results[default.name].extend(
            [
                f"allow {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
                for rule in opa_part_rules
            ]
        )
        policy_tests[default.name] = opa_rule_tests
        return results[default.name]
    else:
        results[default.name].extend(
            [
                f"{default.name} {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
                for rule in opa_part_rules
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
                    "a future version of oslo.policy:\n%s" % description,
                    FutureWarning,
                )
                formatted_lines.extend(_wrap_paragraph(paragraph))
                formatted_lines.append("#")
                paragraph = []

            formatted_lines.append("# %s" % line.rstrip())

    if paragraph:
        # dump anything we might still have in the buffer
        formatted_lines.extend(_wrap_paragraph(paragraph))

    return "\n".join(formatted_lines)


def _get_rule_help(default: oslo_policy.policy._BaseRule) -> str:
    text: str = '"%(name)s": "%(check_str)s"\n' % {
        "name": default.name,
        "check_str": default.check_str,
    }
    op = ""
    if hasattr(default, "operations"):
        for operation in default.operations:
            if operation["method"] and operation["path"]:
                op += "# %(method)s  %(path)s\n" % {
                    "method": operation["method"],
                    "path": operation["path"],
                }
    intended_scope = ""
    if getattr(default, "scope_types", None) is not None:
        intended_scope = (
            "# Intended scope(s): " + ", ".join(default.scope_types) + "\n"
        )
    comment = "#"  # if comment_rule else ''
    text = "%(op)s%(scope)s%(comment)s%(text)s\n" % {
        "op": op,
        "scope": intended_scope,
        "comment": comment,
        "text": text,
    }
    if default.description:
        text = _format_help_text(default.description) + "\n" + text

    return text


def _generate_policy(namespace, output_dir=None):
    """Generate a policy file showing what will be used.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param output_file: The path of a file to output to. stdout used if None.
    """
    generate_policy_test: bool = True
    enforcer = _get_enforcer(namespace)
    # Ensure that files have been parsed
    enforcer.load_rules()

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
        if ":" in rule:
            # final policy rule
            if output_dir:
                fname_parts = rule.split(":")
                fname_parts[-1] = f"{fname_parts[-1]}.rego"
                fname = pathlib.Path(output_dir, *fname_parts)
                fname.parent.mkdir(parents=True, exist_ok=True)
                output = open(fname, "w")
            else:
                output = sys.stdout

            output.write(f"package {rule.replace(':', '.')}\n\n")
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
                fname = pathlib.Path(output_dir, *fname_parts)
                fname.parent.mkdir(parents=True, exist_ok=True)
                output = open(fname, "w")

                output.write(f"package {rule.replace(':', '.')}_test\n\n")
                output.write(
                    f"import data.{namespace}.{rule.replace(':', '.')}\n\n"
                )
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


def on_load_failure_callback(*args, **kwargs):
    raise


def generate_policy(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf.register_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf(args)
    _generate_policy(conf.namespace, conf.output_dir)
