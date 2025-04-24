# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
#
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

from oslo_context import context
from oslo_log import log as logging
from oslo_policy import policy as oslo_policy

from oslo_policy_opa import opa

from neutron._i18n import _
from neutron import manager  # type: ignore
from neutron.pecan_wsgi import constants as pecan_constants
from neutron.pecan_wsgi.hooks import utils
from neutron.pecan_wsgi.hooks import (
    policy_enforcement as neutron_policy_enforcement,
)

from neutron import policy  # type: ignore

LOG = logging.getLogger(__name__)


def _map_context_attributes_into_creds(context):
    """oslo.policy method extracting creds from the context"""
    creds = {}
    # port public context attributes into the creds dictionary so long as
    # the attribute isn't callable
    context_values = context.to_policy_values()
    for k, v in context_values.items():
        creds[k] = v

    return creds


class PolicyHook(neutron_policy_enforcement.PolicyHook):
    priority = 140

    def after(self, state):
        neutron_context = state.request.context.get("neutron_context")
        resource = state.request.context.get("resource")
        collection = state.request.context.get("collection")
        controller = utils.get_controller(state)
        if not resource:
            # can't filter a resource we don't recognize
            return
        # NOTE(kevinbenton): extension listing isn't controlled by policy
        if resource == "extension":
            return
        try:
            data = state.response.json
        except ValueError:
            return
        if state.request.method not in pecan_constants.ACTION_MAP:
            return
        if not data or (resource not in data and collection not in data):
            return
        is_single = resource in data
        action_type = pecan_constants.ACTION_MAP[state.request.method]
        if action_type == "get":
            action = controller.plugin_handlers[controller.SHOW]
        else:
            action = controller.plugin_handlers[action_type]
        key = resource if is_single else collection
        to_process = [data[resource]] if is_single else data[collection]
        # in the single case, we enforce which raises on violation
        # in the plural case, we just check so violating items are hidden
        policy_method = policy.enforce if is_single else policy.check
        plugin = manager.NeutronManager.get_plugin_for_resource(collection)
        try:
            rule = policy.get_enforcer().rules.get(action)
            if rule and isinstance(rule, opa.OPAFilter):
                # The rule explicitly wants to filter/sanitize results. For
                # this we should rather invoke the OPA directly since oslo.policy
                # expects checks to return only True/False. And while returnung a dict
                # works in practice it is not future safe.
                resp = []
                if isinstance(neutron_context, context.RequestContext):
                    creds = _map_context_attributes_into_creds(neutron_context)
                else:
                    creds = neutron_context
                resp = list(rule(to_process, creds, policy.get_enforcer()))
                if is_single and len(resp) == 0:
                    raise oslo_policy.PolicyNotAuthorized(rule, action, creds)
            else:
                resp = [
                    self._get_filtered_item(
                        state.request, controller, resource, collection, item
                    )
                    for item in to_process
                    if (
                        state.request.method != "GET"
                        or policy_method(
                            neutron_context,
                            action,
                            item,
                            plugin=plugin,
                            pluralized=collection,
                        )
                    )
                ]
        except (oslo_policy.PolicyNotAuthorized, oslo_policy.InvalidScope):
            # This exception must be explicitly caught as the exception
            # translation hook won't be called if an error occurs in the
            # 'after' handler.  Instead of raising an HTTPNotFound exception,
            # we have to set the status_code here to prevent the catch_errors
            # middleware from turning this into a 500.
            state.response.status_code = 404
            return

        if is_single:
            resp = resp[0]
        state.response.json = {key: resp}
