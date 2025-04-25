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
import re
import pathlib
import sys
import textwrap
import typing
import warnings

import oslo_policy

from oslo_policy import policy

from oslo_policy_opa.generator import types
from oslo_policy_opa.generator import common

LOG = logging.getLogger(__name__)


IMPORT_REGEX = re.compile(r"lib\.(\w+)\b", flags=re.M)


def _get_opa_rule(
    rule: oslo_policy.policy._BaseRule,
    results: dict[str, list[str]],
    converted_rules: dict[str, types.BaseOpaCheck],
    namespace: typing.Optional[str] = None,
) -> types.BaseOpaCheck:
    """Get the OPA check from OsloPolicy check with hacks"""
    rule_check = rule.check
    opa_rule = None
    if namespace == "neutron":
        # For neutron we need some hacks to deal with custom checks
        if "floatingip_port_forwarding" in str(rule.name):
            # floatingip_port_forwarding ext_parent_owner means floatingip.
            # Replace it for easier conversion
            rule_check = oslo_policy._parser.parse_rule(
                str(rule.check).replace(
                    "rule:ext_parent_owner",
                    "tenant_id:%(ext_parent_floatingip:tenant_id)s",
                )
            )
        elif "policy" in rule.name and "rule" in rule.name:
            # xxx_policy_yyy_rule ext_parent_owner means policy.
            # Replace it for easier conversion
            rule_check = oslo_policy._parser.parse_rule(
                str(rule.check).replace(
                    "rule:ext_parent_owner",
                    "tenant_id:%(ext_parent_policy:tenant_id)s",
                )
            )
    if isinstance(rule.check, oslo_policy._checks.RuleCheck):
        if rule.check.match in converted_rules and rule.check.match in results:
            # The referred rule is already converted and it is not a regular lib
            # rule (i.e. in neutron
            # "delete_alias_minimum_packet_rate_rule: rule:delete_policy_minimum_packet_rate_rule)"
            # in this case we should replace referred rule with the already
            # converted value
            opa_rule = converted_rules[rule.check.match]
    if not opa_rule:
        opa_rule = types.convert_oslo_policy_check_to_opa_check(rule_check)
    return opa_rule


def _translate_default_rule(
    rule: oslo_policy.policy._BaseRule,
    results: dict[str, list[str]],
    converted_rules: dict[str, types.BaseOpaCheck],
    namespace: typing.Optional[str] = None,
    rule_operations: typing.Optional[list[dict]] = None,
):
    """Convert policy.RuleDefault or policy.DocumentedRuleDefault into internal OPA friendly structure

    :param oslo_policy.policy._BaseRule rule: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param dict results: A dictionary with relevant policy rules that is shared globally
    :param dict converted_rules: converted rules
    :param namespace: Namespace name that is prepended to the Rule checks for
        structuring a policy rule into dedicated policy files.
    :param rule_operations: Operations value for the Rule if it is not an
        instance of DocumentedRuleDefault
    """

    opa_rule = _get_opa_rule(rule, results, converted_rules, namespace)
    converted_rules[rule.name] = opa_rule
    lib_part_rules: dict[str, list[str]] = {}
    opa_part_rules = opa_rule.get_opa_policy(lib_part_rules)
    # opa_rule_tests = opa_rule.get_opa_policy_tests(converted_rules, rule.name)
    rule_description = _get_rule_help(rule, rule_operations)
    if hasattr(rule, "operations") and rule.operations or rule_operations:
        # This is the final role
        results.setdefault(rule.name, [rule_description])
        results[rule.name].extend(
            [
                f"allow {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
                for rule in opa_part_rules
            ]
        )
        results[rule.name].extend(
            [
                f"{subrule}\n"
                for k, rules in lib_part_rules.items()
                if k != "lib"
                for subrule in rules
            ]
        )
        if "lib" in lib_part_rules:
            # Append additional lib rules if those are not already there
            for orule in lib_part_rules["lib"]:
                if orule not in results["lib"]:
                    results["lib"].append(orule)
    else:
        # a library "rule"
        LOG.info(
            f"A library rule {rule} with {opa_part_rules} and {lib_part_rules} {rule.check}"
        )
        rule_name = (
            common.normalize_name(rule.name)
            if rule.name != "rule"
            else "_rule"
        )
        results.setdefault("lib", [])
        results["lib"].extend(
            [
                f"{rule_name} {opa_rule.get_header()}  {rule}\n{opa_rule.get_footer()}\n"
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


def _generate_rule_tests(
    rule: oslo_policy.policy._BaseRule,
    results: dict[str, list[str]],
    converted_rules: dict[str, types.BaseOpaCheck],
    policy_tests: dict[str, list[str]],
    namespace: typing.Optional[str] = None,
    rule_operations: typing.Optional[list[dict]] = None,
):
    """Generate OPA tests for the rule.

    :param oslo_policy.policy._BaseRule rule: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param dict results: A dictionary with relevant policy rules that is shared globally
    :param dict converted_rules: converted rules
    :param namespace: Namespace name that is prepended to the Rule checks for
        structuring a policy rule into dedicated policy files.
    """
    opa_rule = _get_opa_rule(rule, results, converted_rules, namespace)
    opa_rule_tests = opa_rule.get_opa_policy_tests(converted_rules, rule.name)
    policy_tests[rule.name] = opa_rule_tests

    return


def _get_rule_help(
    rule: oslo_policy.policy._BaseRule,
    rule_operations: typing.Optional[list[dict]] = None,
) -> str:
    text: str = f'"{rule.name}": "{rule.check_str}"\n'
    op = ""
    for operation in getattr(rule, "operations", rule_operations or []):
        if operation["method"] and operation["path"]:
            op += "# {method}  {path}\n".format(
                method=operation["method"], path=operation["path"]
            )
    intended_scope = ""
    if getattr(rule, "scope_types", None) is not None:
        intended_scope = (
            "# Intended scope(s): " + ", ".join(rule.scope_types) + "\n"
        )
    comment = "#"  # if comment_rule else ''
    text = f"{op}{intended_scope}{comment}{text}\n"
    if rule.description:
        text = _format_help_text(rule.description) + "\n" + text

    return text


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


def generate_opa_policy(conf):
    """Generate a OPA policies.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param conf: Configuration options.
    """
    namespace = conf.namespace
    output_dir = conf.output_dir
    policy_file = conf.policy_file
    generate_policy_test: bool = True
    enforcer = common.get_enforcer(namespace)
    # Ensure that files have been parsed
    if policy_file:
        enforcer.policy_file = policy_file
    enforcer.load_rules(force_reload=True)

    file_rules = [
        policy.RuleDefault(name, default.check_str)
        for name, default in enforcer.file_rules.items()
    ]
    # registered_rules = [
    #     policy.RuleDefault(name, default.check_str)
    #     for name, default in enforcer.registered_rules.items()
    #     if name not in enforcer.file_rules
    # ]

    policies = common.get_policies_dict([namespace])

    opa_policies: dict[str, list[str]] = {}
    opa_test_policies: dict[str, list[str]] = {}
    converted_rules: dict[str, types.BaseOpaCheck] = {}
    for section in sorted(policies.keys()):
        rule_defaults = list(policies[section])
        for default_rule in rule_defaults:
            if default_rule.name in enforcer.file_rules:
                rule = enforcer.file_rules[default_rule.name]
            else:
                rule = default_rule

            _translate_default_rule(
                rule,
                opa_policies,
                converted_rules,
                namespace=namespace,
                rule_operations=getattr(default_rule, "operations", None),
            )

        # Custom policy file may contain additional "library" rules referred by
        # the regular rules. Find them and convert them
        override_additional_rules = {x.name for x in file_rules}.difference(
            {x.name for x in rule_defaults}
        )
        for custom_rule in override_additional_rules:
            rule = enforcer.file_rules[custom_rule]
            LOG.info(f"Generating overridden rule {custom_rule} {rule}")

            _translate_default_rule(
                rule,
                opa_policies,
                converted_rules,
                namespace=namespace,
                rule_operations=None,
            )

        # Another iteration over the rules to generate tests for rules while
        # being sure all rules have been converted.
        for default_rule in rule_defaults:
            if default_rule.name in enforcer.file_rules:
                rule = enforcer.file_rules[default_rule.name]
            else:
                rule = default_rule

            _generate_rule_tests(
                rule,
                opa_policies,
                converted_rules,
                opa_test_policies,
                namespace=namespace,
                rule_operations=getattr(default_rule, "operations", None),
            )

    lib_output = None
    if output_dir:
        lib_fname = pathlib.Path(output_dir, namespace).with_suffix(".rego")
        lib_fname.parent.mkdir(parents=True, exist_ok=True)
        lib_output = open(lib_fname, "w") if output_dir else sys.stdout
        lib_output.write("package lib\n\n")
    for rule, opa_policy in opa_policies.items():
        LOG.info(f"Writing rule {rule}")
        if rule != "lib":
            # final policy rule
            if output_dir:
                fname_parts = rule.split(":")
                fname_parts[-1] = f"{fname_parts[-1]}.rego"
                fname = pathlib.Path(output_dir, *fname_parts)
                fname.parent.mkdir(parents=True, exist_ok=True)
                output = open(fname, "w")
            else:
                output = sys.stdout

            output.write(
                f"package {common.normalize_name(rule.replace(':', '.').replace('-', '_'))}\n\n"
            )
            if "lib." in "".join(opa_policy):
                output.write("import data.lib\n\n")
            for opa_policy_rule in opa_policy:
                if namespace == "glance":
                    opa_policy_rule = opa_policy_rule.replace(
                        "member_id", "member"
                    )
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

                output.write(f"package {common.normalize_name(rule)}_test\n\n")
                output.write(
                    f"import data.{'.'.join(common.normalize_name(x) for x in packagename_parts)}\n\n"
                )
                num: int = 1
                for opa_policy_rule_test in tests:
                    if namespace == "glance":
                        opa_policy_rule_test = opa_policy_rule_test.replace(
                            "member_id", "member"
                        )
                    output.write(opa_policy_rule_test)
                    output.write("\n")
                    num += 1
                if output != sys.stdout:
                    output.close()
        else:
            # for opa_policy_rule in opa_policy:
            if lib_output:
                for opa_policy_rule in opa_policy:
                    lib_output.write(opa_policy_rule.replace("lib.", ""))
                    lib_output.write("\n\n")
    if lib_output:
        lib_output.close()
