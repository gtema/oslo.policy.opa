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
import sys
import textwrap
import warnings

from oslo_config import cfg

from oslo_policy_opa.generator import opa
from oslo_policy_opa.generator import common

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
    ),
    cfg.StrOpt(
        "policy-file",
        help="Optional policy.yaml file to use as a source of policy"
        "customization (full path)",
    ),
]


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
        check_str=f"opa:{common.normalize_name(default.name.replace(':', '/'))}",
    )

    if include_help:
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
    policies = common.get_policies_dict(namespaces)

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
    opa.generate_opa_policy(conf)
