# Most simple and naive RBAC implementation
# Got the inspiration from Auth0 -
# - https://github.com/auth0-developer-hub/api_fastapi_python_hello-world
# - https://developer.auth0.com/resources/code-samples/api/fastapi/basic-role-based-access-control#set-up-role-based-access-control-rbac

# The scope convention {verb}:{resource} is inspired by Auth0's RBAC

# Note that since we don't use Auth0's RBAC, I just took the concepts but left the implementation more simple

# TODO: move resources (alert, rule, etc.) to class constants
# TODO: move verbs (read, write, delete, update) to class constants
# TODO: custom roles
# TODO: implement a solid RBAC mechanism (probably OPA over Keycloak)


import enum

from fastapi import HTTPException


class Roles(enum.Enum):
    ADMIN = "admin"
    NOC = "noc"
    WEBHOOK = "webhook"
    WORKFLOW_RUNNER = "workflowrunner"


class Role:
    @classmethod
    def get_name(cls):
        return cls.__name__.lower()

    @classmethod
    def has_scopes(cls, scopes: list[str]) -> bool:
        required_scopes = set(scopes)
        available_scopes = set(cls.SCOPES)

        for scope in required_scopes:
            # First, check if the scope is available
            if scope in available_scopes:
                # Exact match, on to the next scope
                continue

            # If not, check if there's a wildcard permission for this action
            scope_parts = scope.split(":")
            if len(scope_parts) != 2:
                return False  # Invalid scope format
            action, resource = scope_parts
            if f"{action}:*" not in available_scopes:
                return False  # No wildcard permission for this action
        # All scopes are available
        return True


# Noc has read/write on alerts and incidents, read-only visibility into how the
# alert pipeline is configured, and read/write on maintenance windows.
# Explicitly excludes dashboards, topology, providers, settings (SMTP/API keys/SSO/
# users/roles) and secrets (raw workflow credentials) — those stay admin-only.
class Noc(Role):
    SCOPES = [
        # core alert/incident work
        "read:alert",
        "write:alert",
        "read:incident",
        "read:incidents",
        "write:incident",
        # saved views (both scope names are needed to browse presets in the UI)
        "read:preset",
        "read:presets",
        # live updates in the UI
        "read:pusher",
        # maintenance/silence windows
        "read:maintenance",
        "write:maintenance",
        # read-only visibility into pipeline configuration (no write, no secrets)
        "read:rules",
        "read:extraction",
        "read:actions",
        "read:deduplications",
        "read:workflows",
        "execute:workflows",
    ]
    DESCRIPTION = (
        "read/write on alerts, incidents and maintenance windows; read-only "
        "visibility into rules/extraction/actions/deduplications/metrics/workflows; "
        "can execute workflows and assign itself to alerts"
    )


# Admin has all permissions
class Admin(Role):
    SCOPES = ["read:*", "write:*", "delete:*", "update:*", "execute:*"]
    DESCRIPTION = "do everything"


# Webhook has write:alert permission to write alerts
# this is internal role used by API keys
class Webhook(Role):
    SCOPES = ["write:alert", "write:incident"]
    DESCRIPTION = "write alerts using API keys"


class WorkflowRunner(Role):
    SCOPES = ["write:workflows", "execute:workflows"]
    DESCRIPTION = "Run workflows using API keys"


def get_role_by_role_name(role_name: str) -> list[str]:
    if role_name == Roles.ADMIN.value:
        return Admin
    elif role_name == Roles.NOC.value:
        return Noc
    elif role_name == Roles.WEBHOOK.value:
        return Webhook
    elif role_name == Roles.WORKFLOW_RUNNER.value:
        return WorkflowRunner
    else:
        raise HTTPException(
            status_code=403,
            detail=f"Role {role_name} not found",
        )
