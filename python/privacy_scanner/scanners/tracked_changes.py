# This scanner checks LibreOffice Writer documents for unresolved comments, tracked deletions/insertions, and hidden editing history.

from typing import List
from privacy_scanner.scanners.base import BaseScanner
from privacy_scanner.core.models import Issue, Severity

class TrackedChangesScanner(BaseScanner):
    rule_id = "tracked_changes_comments"
    category = "Document History"

    def scan(self, document) -> List[Issue]:
        issues = []

        # 1. Check for Unresolved Comments / Annotations
        try:
            fields = document.getTextFields()
            field_enum = fields.createEnumeration()
            comment_count = 0

            while field_enum.hasMoreElements():
                field = field_enum.nextElement()
                # Check for Annotation / Comment text fields
                if field.supportsService("com.sun.star.text.TextField.Annotation"):
                    comment_count += 1
                    author = getattr(field, "Author", "Unknown Author")
                    content = getattr(field, "Content", "")
                    
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            title="Unresolved Comment Found",
                            description=f"Comment by '{author}': \"{content[:40]}...\"",
                            severity=Severity.MEDIUM,
                            location=f"Comment #{comment_count}",
                            can_autofix=True
                        )
                    )
        except Exception as e:
            print(f"Error scanning comments: {e}")

        # 2. Check for Active Tracked Changes (Redlines)
        try:
            if hasattr(document, "Redlines"):
                redlines = document.Redlines
                if redlines and redlines.getCount() > 0:
                    count = redlines.getCount()
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            title="Unaccepted Tracked Changes",
                            description=f"Document contains {count} unaccepted tracked change(s) / revision(s).",
                            severity=Severity.HIGH,
                            location="Document Body",
                            can_autofix=False
                        )
                    )
        except Exception as e:
            print(f"Error scanning tracked changes: {e}")

        return issues