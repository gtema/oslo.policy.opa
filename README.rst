Oslo Policy OpenPolicyAgent integration
=======================================

What is Oslo.Policy?
--------------------

`oslo.policy <https://docs.openstack.org/oslo.policy/latest/>`_ is an OpenStack
library that allows configuration of the authorization policies for OpenStack
service APIs. Those are described directly in the code and can be further
modified by the service deployer.

It looks approximately like that:

.. code-block:: yaml

   "identity:get_application_credential": "(rule:admin_required) or (role:reader and system_scope:all) or rule:owner"

In a human language it would translate to: get_application_credential operation
of the identity service is allowed if one of the following conditions is true:

- `rule:admin_required` evaluates to True (user has admin role)

- `role:reader and system_scope:all)` - user has reader role and authorized
  with the system scope and `all` target

- `rule:owned` - user is owner of the resource

What is OpenPolicyAgent?
------------------------

The `Open Policy Agent (OPA) <https://www.openpolicyagent.org/docs/latest/>`_
is an open source, general-purpose policy engine that unifies policy
enforcement across the stack. OPA provides a high-level declarative language
that lets you specify policy as code and simple APIs to offload policy
decision-making from your software. It is possible to use OPA to enforce
policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.
Variety of big software systems already integrate with OPA natively
(Kubernetes, Ceph, Envoy, Terraform, Kafka, APISIX, etc)

What is better and why this project?
------------------------------------

Both oslo.policy and OpenPolicyAgent serve the same purpose but differently.
Scope of this project is to integrate both and not to say which one is better.

OPA has few unique features that are not present in the oslo.policy. It is
possible not only to express RBAC or ABAC policy directly, it is also possible
to combine them simultaneously and even to add ReBAC on top of that. It is
possible to not only have static policy, but also to embed additional data into
the policy. That allows higher flexibility for the CSPs to address fine
granular access control.

Purpose of this project is to integrate both oslo.policy and opa by providing
custom oslo.policy rule invoking opa rest API. Since that involves network
roundtrips (usually opa deployed as a side-car pattern so that the network
roundtrip does not technically leeaves the host) and dependency on the external
service we can implement a fallback which in case of opa unavailability (or any
other communication issues) uses default policy configured by the OpenStack
service.


Convertor and policy testing
----------------------------

An OPA policy generator is available to generate policies in the OPA Rego
language as defined by oslo_policy. At the moment maybe not everything is
ported yet. Keystone and Barbican policies can be generated without known
issues.

OPA allows writing policy tests in a unit-test manner. At the moment failing
test stubs are generated as well. It is possible to also generate test
implementations, but this is not done yet.

.. code-block:: console

   oslopolicy-opa-policy-generator --namespace keystone --output-dir opa_policies

The above command (assuming project is installed in the virtual environment
with Keystone) will generate series of policy files in the defined folder based
on the policies defined in the keystone code. It functions very similarly to
the oslopolicy-policy-generator or oslopolicy-sample-generator.

OPA language does not implement nested `if` conditions requiring to instead
define the incremental rules what also enables their parallel evaluation.
Depending on the policy complexity this may result in a big amount of such
incremental rules which are placed together with general `rules` in the
lib.rego file.

For every oslo_policy rule there is a dedicated `.rego` file so that it is
possible to query preciese policy using the REST API from the oslo_policy.


Policy language
---------------

.. code-block:: rego
  :caption: identity/create_project.rego

  package identity.create_project

  import data.lib
  
  # Create project.
  # POST  /v3/projects
  # Intended scope(s): system, domain, project
  #"identity:create_project": "(rule:admin_required) or (role:manager and domain_id:%(target.project.domain_id)s)"
  
  
  allow if {
    lib.admin_required
  }
  
  allow if {
    lib.manager_and_domain_id_project_domain_id
  }

Authorization decision for this policy can be queried by sending:

.. code-block:: console

   curl "http://localhost:8181/v1/data/identity/create_project/allow" -v -H "content-type: application/json" --data '{"input": {"credentials": {"roles": ["admin"]}}}'

The OR part of the policy can be also checked adding required information into
the query context:

.. code-block:: console

   curl "http://localhost:8181/v1/data/identity/create_project/allow" -v -H "content-type: application/json" --data '{"input": {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id":"foo"}}}}'

Extending policies above RBAC/ABAC
----------------------------------

One of the very interesting and useful features of OpenPolicyAgent is
possibility to provide engine additional data to be included in the policy
evaluation. It is typically a soft-structured JSON and possibility to execute
lookup queries including certain algorithms from graph theory. This allows
implementing ReBAC in addition to the default policy rules.

Imagine the following policy for listing Keystone roles:

.. code-block:: rego
   :caption: identity/list_roles.rego

   package identity.list_roles

   import data.lib

   # List roles.
   # GET  /v3/roles
   # HEAD  /v3/roles
   # Intended scope(s): system, domain, project
   #"identity:list_roles": "(rule:admin_required or (role:reader and system_scope:all)) or (role:manager and not domain_id:None)"


   allow if {
     lib.admin_required_or_reader_and_system_scope_all
   }

   allow if {
     lib.manager_and_not_domain_id_None
   }

If we would want to grant a certain user (or maybe group of users) listing all
domain roles without being an admin or manager we could first rewrite the
policy:

 .. code-block:: rego
   :caption: identity/list_roles.rego

   package identity.list_roles

   ...

   allow if {
       data.assignments["list_roles"][input.credentials.user_id]
   }

This new policy checks that there is an entry present in
`assignments.list_roles[USER_ID]`. Unless the data is present in the OPA
nothing will change and a regular user used for tests is not allowed to list
roles. Now let's push the assignments data:

.. code-block:: console

   curl "http://localhost:8181/v1/data/assignments" -X PUT -H "content-type: application/json" --data '{"list_roles": {"ac1728767bb34d4393d514b8f5835c8f": {}}}'

   # alternatively we can directly push only `list_roles` relevant data with
   # curl "http://localhost:8181/v1/data/assignments/list_roles" -X PUT -H "content-type: application/json" --data '{"ac1728767bb34d4393d514b8f5835c8f": {}}'

Without restart of Keystone or OPA user with the ID used above is allowed to
execute `list_roles` API call. And this happens dynamically without service
restart. This example is very simplified but it still demonstrates possibility
to extend policies above what is possible by `oslo_policy` while at the same
time providing capability to have preciese tests for policies and also the
decision logs (those can be pushed to the external service).

.. code-block:: json
   :caption: OPA decision_log

   {
     "decision_id":"adeedec1-d260-476d-a98d-91b94bc61c00",
     "input":{"credentials":{"user_id":"ac1728767bb34d4393d514b8f5835c8f"}},
     "labels":{"id":"9d3990bd-cac2-464e-ab1a-fb6e129cd6fa","version":"1.0.0"},
     "level":"info",
     "metrics":{
       "counter_server_query_cache_hit":0,
       "timer_rego_external_resolve_ns":583,
       "timer_rego_input_parse_ns":30833,
       "timer_rego_query_compile_ns":106541,
       "timer_rego_query_eval_ns":147416,
       "timer_rego_query_parse_ns":75666,
       "timer_server_handler_ns":1428583
     },
     "msg":"Decision Log",
     "path":"identity/list_roles",
     "req_id":4,
     "requested_by":"127.0.0.1:58893",
     "result":{"allow":true},
     "time":"2025-01-22T14:58:23+01:00",
     "timestamp":"2025-01-22T13:58:23.955441Z",
     "type":"openpolicyagent.org/decision_logs"
   }

`OPA documentation
<https://www.openpolicyagent.org/docs/latest/policy-reference/#graph>`_
describes few graph related functions (reachable, reachable_paths, walk) giving
possibility to model data as a relation graph with nodes being OpenStack
resources (i.e. role and user as in the example above) and graph edges being
relations (or grants). This is how ReBAC systems work. It is possible to
provide OPA instance only the relevant data (i.e. OPA instance for Keystone
only containing identity relevant relations while the OPA instance for Nova
only dealing with compute relevant relations) so that the data is structured in
smaller self-containing chunks without exploding central storage.
