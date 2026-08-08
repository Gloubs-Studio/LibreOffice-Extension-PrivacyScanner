import re
from typing import List
from privacy_scanner.scanners.base import BaseScanner
from privacy_scanner.core.models import Issue, Severity


class PIIScanner(BaseScanner):
    rule_id = "pii_regex_detector" # pyright: ignore[reportAssignmentType]
    category = "Sensitive Data" # pyright: ignore[reportAssignmentType]

    # Map pattern titles to compiled regexes & assigned severity levels
    PATTERNS = {

        "IBAN / Bank Account": {
            "regex": re.compile(
                r"\b[A-Z]{2}\s*\d{2}"
                r"(?:[\s-]*[A-Z0-9]){11,30}\b",
                re.IGNORECASE,
            ),
            "severity": Severity.HIGH,
        },

        "Passport Number": {
            "regex": re.compile(
                r"\b(?:passport(?:\s+number|\s+no\.?)?\s*[:\-]?\s*)?"
                r"[A-Z]{1,2}\d{6,9}\b",
                re.IGNORECASE,
            ),
            "severity": Severity.HIGH,
        },

        "MAC Address": {
            "regex": re.compile(
                r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
            ),
            "severity": Severity.MEDIUM,
        },

        "Vehicle Registration": {
            "regex": re.compile(
                r"\b(?:license\s+plate|licence\s+plate|"
                r"registration(?:\s+number)?|reg(?:istration)?\.?\s+no\.?)"
                r"\s*[:\-]?\s*[A-Z0-9][A-Z0-9\s-]{2,10}\b",
                re.IGNORECASE,
            ),
            "severity": Severity.MEDIUM,
        },

        "French Postal Address": {
            "regex": re.compile(
                r"\b\d{1,5}"
                r"(?:\s+(?:bis|ter|quater))?"
                r"\s*,?\s*"
                r"(?:rue|avenue|av\.|boulevard|bd|"
                r"chemin|route|impasse|allée|allee|"
                r"place|quai|cours|passage|"
                r"faubourg|square|lotissement)"
                r"\s+[A-Za-zÀ-ÖØ-öø-ÿ'’-]+"
                r"(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ'’-]+)*"
                r"\s*,?\s*"
                r"\b\d{5}\s+"
                r"[A-Za-zÀ-ÖØ-öø-ÿ'’-]+"
                r"(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ'’-]+)*"
                r"(?:\s*,?\s*France)?\b",
                re.IGNORECASE,
            ),
            "severity": Severity.MEDIUM,
        },

        "Person Name - Labelled": {
            "regex": re.compile(
                r"\b(?:"
                r"name|first\s+name|forename|last\s+name|surname|"
                r"prénom|nom\s+de\s+famille"
                r")\s*[:\-]\s*"
                r"[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]+"
                r"(?:\s+[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]+){0,3}",
                re.IGNORECASE,
            ),
        "severity": Severity.MEDIUM,
        },
        
        "Person Name - Title": {
            "regex": re.compile(
                r"\b(?:Mr|Mrs|Ms|Miss|Dr|M\.|Mme|Mlle)\.?\s+"
                r"[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]+"
                r"(?:\s+[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]+){0,3}\b"
            ),
            "severity": Severity.MEDIUM,
        },

        "Person Name - Capitalized Surname": {
            "regex": re.compile(
                r"\b"
                r"[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+"
                r"(?:[-'][A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+)?"
                r"(?:\s+"
                r"[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+"
                r"(?:[-'][A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+)?"
                r"){0,2}"
                r"\s+"
                r"[A-ZÀ-ÖØ-Ý]{2,}"
                r"(?:[-'][A-ZÀ-ÖØ-Ý]{2,})?"
                r"\b"
            ),
            "severity": Severity.MEDIUM,
        },

        "Date of Birth": {
            "regex": re.compile(
                r"\b(?:0[1-9]|[12]\d|3[01])"
                r"(?:[\/\-]|\s+)"
                r"(?:0[1-9]|1[0-2])"
                r"(?:[\/\-]|\s+)"
                r"(?:19|20)\d{2}\b"
            ),
            "severity": Severity.LOW,
        },

        "Marital Status": {
            "regex": re.compile(r'(Single|Married|Divorced|Widowed)'),
            "severity": Severity.LOW,
        },

        "Username": {
            "regex": re.compile(
                r"\b(?:username|user\s*name|login|user\s*id|"
                r"account\s*(?:name|id))"
                r"\s*[:=]\s*"
                r"[A-Za-z0-9][A-Za-z0-9_.-]{2,31}\b",
                re.IGNORECASE,
            ),
            "severity": Severity.LOW,
        },

        "Credit Card Number": {
            "regex": re.compile(
                r"\b(?:"
                r"(?:\d{4}[\s-]?){3}\d{4}"
                r"|"
                r"\d{15,16}"
                r")\b"
            ),
            "severity": Severity.HIGH,
        },


        "Email Address": {
            "regex": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            "severity": Severity.MEDIUM,
        },

        "Phone Number": {
            "regex": re.compile(
                r"(?<!\d)"
                r"(?:"
                r"\+33(?:[\s.-]?\d){9}"
                r"|"
                r"0[1-9](?:[\s.-]?\d){8}"
                r")"
                r"(?!\d)"
            ),
            "severity": Severity.MEDIUM,
        },

        "French Social Security Number": {
            "regex": re.compile(
                r"\b[12]\s?"
                r"\d{2}\s?"
                r"(?:0[1-9]|1[0-2])\s?"
                r"\d{2}\s?"
                r"\d{3}\s?"
                r"\d{3}\s?"
                r"\d{2}\b"
            ),
            "severity": Severity.HIGH,
        },

        "IPv4 Address": {
            "regex": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "severity": Severity.MEDIUM,
        },

        "Internal Confidential Tags": {
            "regex": re.compile(
                r'\bCONFIDENTIAL\b|\bRESTRICTED\b|\bTOP SECRET\b|\bSECRET\b'
            ),
            "severity": Severity.HIGH,
        },

        "UK National Insurance Number": {
            "regex": re.compile(
                r"\b"
                r"(?!BG|GB|NK|KN|TN|NT|ZZ)"
                r"[A-CEGHJ-PR-TW-Z]{2}"
                r"\s?"
                r"\d{2}\s?"
                r"\d{2}\s?"
                r"\d{2}"
                r"\s?"
                r"[A-D]\b",
                re.IGNORECASE,
            ),
            "severity": Severity.HIGH,
        },

        "API Key / Token": {
            "regex": re.compile(
                r"\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)"
                r"\s*[:=]\s*"
                r"[A-Za-z0-9_\-]{16,}\b",
                re.IGNORECASE,
            ),
            "severity": Severity.HIGH,
        },

        "Bearer Token": {
            "regex": re.compile(
                r"\bBearer\s+[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
                re.IGNORECASE,
            ),
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