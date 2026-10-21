"""actionwall: a policy firewall for what AI agents do."""

__version__ = "0.1.0"

from .actions import Action, ActionBlocked, Decision, Kind, Verdict  # noqa: E402
from .audit import AuditLog, verify  # noqa: E402
from .executor import GuardedExecutor  # noqa: E402
from .guard import Guard  # noqa: E402
from .integrations import guarded  # noqa: E402
from .policy import Policy  # noqa: E402

__all__ = ["Action", "ActionBlocked", "AuditLog", "Decision", "Guard", "GuardedExecutor", "Kind", "Policy",
           "Verdict", "guarded", "verify", "__version__"]
