# The engine dynamically registers scanners and coordinates the execution.

from typing import List
from privacy_scanner.core.models import Issue
from privacy_scanner.scanners.metadata import MetadataScanner
from privacy_scanner.scanners.pii import PIIScanner
from privacy_scanner.scanners.tracked_changes import TrackedChangesScanner


class ScannerEngine:
    def __init__(self):
        self._scanners = [
            MetadataScanner(),
            PIIScanner(),
            TrackedChangesScanner(),
        ]

    def run_all(self, document) -> List[Issue]:
        all_issues = []
        for scanner in self._scanners:
            try:
                results = scanner.scan(document)
                if results:
                    all_issues.extend(results)
            except Exception as e:
                print(f"Error running scanner {scanner.rule_id}: {e}")

        # --- Smart Comment Deduplication Pass ---
        # 1. Track comments that already matched PII rules
        pii_comment_locations = set()
        for issue in all_issues:
            if issue.rule_id == "pii_regex_detector":
                loc = getattr(issue, "location", "")
                if "Comment #" in loc:
                    # Extract 'Comment #1' or 'Comment #2' base prefix
                    parts = loc.split(" ")
                    if len(parts) >= 2:
                        base_comment_id = parts[0] + " " + parts[1]
                        pii_comment_locations.add(base_comment_id)

        # 2. Filter out generic 'tracked_changes_comments' if PII was already found in that comment
        deduped_issues = []
        for issue in all_issues:
            if issue.rule_id == "tracked_changes_comments":
                loc = getattr(issue, "location", "")
                if any(comment_id in loc for comment_id in pii_comment_locations):
                    continue  # Skip generic finding since PII was already flagged
            deduped_issues.append(issue)

        return deduped_issues