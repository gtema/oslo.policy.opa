import pecan

from neutron.pecan_wsgi.controllers import root
from neutron.pecan_wsgi import hooks
from neutron.pecan_wsgi import startup

from oslo_policy_opa import neutron_policy_hook


def v2_factory(global_config, **local_config):
    # Processing Order:
    #   As request enters lower priority called before higher.
    #   Response from controller is passed from higher priority to lower.
    app_hooks = [
        hooks.UserFilterHook(),  # priority 90
        hooks.ContextHook(),  # priority 95
        hooks.ExceptionTranslationHook(),  # priority 100
        hooks.BodyValidationHook(),  # priority 120
        hooks.OwnershipValidationHook(),  # priority 125
        hooks.QuotaEnforcementHook(),  # priority 130
        hooks.NotifierHook(),  # priority 135
        hooks.QueryParametersHook(),  # priority 139
        neutron_policy_hook.PolicyHook(),  # priority 140
    ]
    app = pecan.make_app(
        root.V2Controller(),
        debug=False,
        force_canonical=False,
        hooks=app_hooks,
        guess_content_type_from_ext=True,
    )
    startup.initialize_all()
    return app


def APIRouter(**local_config):
    return v2_factory(None, **local_config)


def _factory(global_config, **local_config):
    return v2_factory(global_config, **local_config)


setattr(APIRouter, "factory", _factory)
