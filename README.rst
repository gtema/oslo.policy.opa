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

oslo.policy is older. They both serve the same purpose and while OPA got
adapted widely, oslo.policy stays as an OpenStack specific policy engine.

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
