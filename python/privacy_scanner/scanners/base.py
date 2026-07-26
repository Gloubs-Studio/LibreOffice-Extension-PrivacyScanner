# Define a clear contract so every new scanner rule adheres to the same interface.

from abc import ABC, abstractmethod
from typing import List
from privacy_scanner.core.models import Issue

class BaseScanner(ABC):
    """Abstract base class for all privacy inspection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for the rule."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category name (e.g., 'Metadata', 'PII', 'Tracked Changes')."""
        pass

    @abstractmethod
    def scan(self, document) -> List[Issue]:
        """Runs the inspection logic against the LibreOffice document model."""
        pass