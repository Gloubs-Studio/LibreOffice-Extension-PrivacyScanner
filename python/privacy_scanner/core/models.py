# A standardized model representing a detected privacy issue.

from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

@dataclass
class Issue:
    rule_id: str
    title: str
    description: str
    severity: Severity
    location: str = ""       # e.g., "Page 2" or "meta.xml"
    can_autofix: bool = False