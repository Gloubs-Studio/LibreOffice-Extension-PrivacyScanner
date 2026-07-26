import re
from typing import List
from privacy_scanner.scanners.base import BaseScanner
from privacy_scanner.core.models import Issue, Severity


class PIIScanner(BaseScanner):
    rule_id = "pii_regex_detector"
    category = "Sensitive Data"

    # Map pattern titles to compiled regexes & assigned severity levels
    PATTERNS = {
        "Date of Birth": {
            "regex": re.compile(r'(0[1-9]|1[0-2])/(?:0[1-9]|1\d|2\d|3[01])/(\d{4})'),
            "severity": Severity.LOW,
        },
        "Marital Status": {
            "regex": re.compile(r'(Single|Married|Divorced|Widowed)'),
            "severity": Severity.LOW,
        },
        "Government-issued ID Number": {
            "regex": re.compile(r'[A-Z]{2}[a-z]*\s\d{5,9}'),
            "severity": Severity.MEDIUM,
        },
        "Credit Card Number": {
            "regex": re.compile(r'(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:017|35)[0-9]{12}|35[0-9]{14}|3[47][0-9]{13}|8[0-`^(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:017|35)[0-9]{12}|35[0-9]{14}|3[47][0-9]{13}8[0-9]{14})'),
            "severity": Severity.HIGH,
        },
        "Tax Identification Number (TIN) or VAT Number": {
            "regex": re.compile(r'[A-Z]{2}[a-z]*[0-9]{3,9}'),
            "severity": Severity.LOW,
        },
        "Email Address": {
            "regex": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            "severity": Severity.MEDIUM,
        },
        "Phone Number": {
            "regex": re.compile(
                r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ),
            "severity": Severity.MEDIUM,
        },
        "Phone Number (FR)": {
            "regex": re.compile(
                r'\b\d{2}[-.\s]\d{2}[-.\s]\d{2}[-.\s]\d{2}[-.\s]\d{2}\b|\b\d{2}(?:[ ]?\d{2}){4}\b'
            ),
            "severity": Severity.MEDIUM,
        },
        "Social Security Number (FR)": {
            "regex": re.compile(
                r'\b\d{1}[-.\s]\d{2}[-.\s]\d{2}[-.\s]\d{2}[-.\s]\d{3}[-.\s]\d{3}[-.\s]\d{2}\b'
            ),
            "severity": Severity.HIGH,
        },
        "IPv4 Address": {
            "regex": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "severity": Severity.MEDIUM,
        },
        "Internal Confidential Tag": {
            "regex": re.compile(
                r'\bCONFIDENTIAL\b|\bRESTRICTED\b|\bTOP SECRET\b|\bSECRET\b'
            ),
            "severity": Severity.HIGH,
        },
        "National Insurance Number (UK)": {
            "regex": re.compile(
                r'\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b'
            ),
            "severity": Severity.HIGH,
        },
        "API Key / Token": {
            "regex": re.compile(r'\b[A-Za-z0-9_]{32}\b'),
            "severity": Severity.HIGH,
        },
    }

    def _scan_text_content(self, text: str, location_label: str) -> List[Issue]:
        issues = []
        if not text or not text.strip():
            return issues

        for rule_name, config in self.PATTERNS.items():
            pattern = config["regex"]
            severity = config["severity"]

            matches = pattern.findall(text)
            for match in matches:
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        title=f"Exposed {rule_name}",
                        description=f"Found potential sensitive data: '{match}'",
                        severity=severity,
                        location=location_label,
                        can_autofix=False,
                    )
                )
        return issues

    def scan(self, document) -> List[Issue]:
        issues = []
        text_enum = document.getText().createEnumeration()

        paragraph_count = 0
        while text_enum.hasMoreElements():
            paragraph = text_enum.nextElement()
            content = paragraph.getString()
            paragraph_count += 1

            # Skip blank paragraphs early to save CPU time
            if not content.strip():
                continue

            issues.extend(
                self._scan_text_content(content, f"Paragraph {paragraph_count}")
            )

        # Scan Headers and Footers
        try:
            style_families = document.getStyleFamilies()
            page_styles = style_families.getByName("PageStyles")

            for name in page_styles.getElementNames():
                style = page_styles.getByName(name)

                # Check Header
                if hasattr(style, "HeaderIsOn") and style.HeaderIsOn:
                    header_text = style.HeaderText.getString()
                    issues.extend(
                        self._scan_text_content(header_text, f"Header ({name})")
                    )

                # Check Footer
                if hasattr(style, "FooterIsOn") and style.FooterIsOn:
                    footer_text = style.FooterText.getString()
                    issues.extend(
                        self._scan_text_content(footer_text, f"Footer ({name})")
                    )
        except Exception:
            pass  # Defensive: fail quietly if style families are unreadable

        # Scan Comments / Annotations
        try:
            if hasattr(document, "getTextFields"):
                text_fields = document.getTextFields().createEnumeration()
                comment_count = 0
                while text_fields.hasMoreElements():
                    field = text_fields.nextElement()
                    if field.supportsService(
                        "com.sun.star.text.TextField.Annotation"
                    ):
                        comment_count += 1
                        comment_text = field.Content
                        author = getattr(field, "Author", "Unknown Author")
                        issues.extend(
                            self._scan_text_content(
                                comment_text,
                                f"Comment #{comment_count} (by {author})",
                            )
                        )
        except Exception:
            pass  # Defensive: fail quietly if text fields enumeration fails

        return issues