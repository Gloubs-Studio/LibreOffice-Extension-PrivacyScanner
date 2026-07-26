# This module inspects the document’s built-in metadata properties
# (such as Author, Last Saved By, Creation/Modification dates,
# and Title/Subject keywords) that often leak personal or company details unnoticed.

from typing import List
from privacy_scanner.scanners.base import BaseScanner
from privacy_scanner.core.models import Issue, Severity

class MetadataScanner(BaseScanner):
    rule_id = "document_metadata"
    category = "Metadata"

    def scan(self, document) -> List[Issue]:
        issues = []

        try:
            # Access LibreOffice Document Information Properties (com.sun.star.document.DocumentProperties)
            doc_props = document.getDocumentProperties()

            # 1. Check Author / Last Modified By
            author = getattr(doc_props, "Author", "").strip()
            modified_by = getattr(doc_props, "ModifiedBy", "").strip()

            if author:
                issues.append(
                    Issue(
                        rule_id=f"{self.rule_id}_author",
                        title="Document Author Exposed",
                        description=f"Author field is populated with: '{author}'",
                        severity=Severity.LOW,
                        location="Document Metadata (meta.xml)",
                        can_autofix=True
                    )
                )

            if modified_by:
                issues.append(
                    Issue(
                        rule_id=f"{self.rule_id}_modified_by",
                        title="Last Saved By Exposed",
                        description=f"Last Modified By field is populated with: '{modified_by}'",
                        severity=Severity.LOW,
                        location="Document Metadata (meta.xml)",
                        can_autofix=True
                    )
                )

            # 2. Check Software Generator Tag (reveals LO version & OS)
            generator = getattr(doc_props, "Generator", "").strip()
            if generator:
                issues.append(
                    Issue(
                        rule_id=f"{self.rule_id}_generator",
                        title="Software Generator Version Exposed",
                        description=f"Document contains application info: '{generator}'",
                        severity=Severity.LOW,
                        location="Document Metadata (meta.xml)",
                        can_autofix=False
                    )
                )

            # 3. Check for Custom Properties / User Variables
            user_defined = getattr(doc_props, "UserDefinedProperties", None)
            if user_defined and hasattr(user_defined, "getPropertyValues"):
                props = user_defined.getPropertyValues()
                if len(props) > 0:
                    issues.append(
                        Issue(
                            rule_id=f"{self.rule_id}_custom_props",
                            title="Custom User Properties Found",
                            description=f"Found {len(props)} custom user-defined metadata field(s).",
                            severity=Severity.MEDIUM,
                            location="Custom Properties",
                            can_autofix=True
                        )
                    )

        except Exception as e:
            print(f"Error scanning metadata: {e}")

        return issues