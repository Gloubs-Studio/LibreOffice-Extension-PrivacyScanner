# This handles rendering the scan results inside a standard LibreOffice UNO graphical dialog window.

import time
import uno
import unohelper
from typing import List
from com.sun.star.awt import XActionListener
from privacy_scanner.core.models import Issue


class ExportActionListener(unohelper.Base, XActionListener):
    """Clean PyUNO ActionListener implementation for UI button events."""

    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()

    def disposing(self, event):
        pass


class ScannerDialog:
    def __init__(self, ctx, document, issues: List[Issue]):
        self.ctx = ctx
        self.document = document
        self.issues = issues
        self._last_export_time = 0.0
        self._export_listener = None  # Prevents Garbage Collection in PyUNO

    def _highlight_issues(self):
        """Highlights matching issues directly in the document with yellow background."""
        if not self.issues or not hasattr(self.document, "createSearchDescriptor"):
            return

        try:
            search_desc = self.document.createSearchDescriptor()
            for issue in self.issues:
                # Extract the matched text from description
                if "'" in issue.description:
                    match_str = issue.description.split("'")[1]
                    if match_str and len(match_str) > 2:
                        search_desc.SearchString = match_str
                        found_all = self.document.findAll(search_desc)

                        # Map severity to hex highlight colors for Writer
                        sev_upper = issue.severity.value.upper()
                        if sev_upper == "HIGH":
                            highlight_color = 0xFF0B6D  # Red ish
                        elif sev_upper == "MEDIUM":
                            highlight_color = 0xFF6D37  # Orange ish
                        else:
                            highlight_color = 0xFFF937  # Yellow ish

                        for i in range(found_all.getCount()):
                            found = found_all.getByIndex(i)
                            found.CharBackColor = highlight_color
        except Exception:
            pass  # Fail gracefully if document is read-only or search fails

    def _export_to_csv(self):
        """Opens a File Save dialog and exports detected issues to a CSV file."""
        import csv

        # Debounce: Ignore any call happening within 1.5 seconds of the last export
        now = time.time()
        if (now - self._last_export_time) < 1.5 or not self.issues:
            return

        self._last_export_time = now

        try:
            # Create LibreOffice FilePicker Service
            file_picker = self.ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.ui.dialogs.FilePicker", self.ctx
            )
            # 1 = SAVE_AS mode
            file_picker.initialize((1,))
            file_picker.appendFilter("CSV (Comma Delimited)", "*.csv")
            file_picker.setTitle("Save Privacy Scan Report")
            file_picker.setDefaultName("Privacy_Scan_Report.csv")

            if file_picker.execute() == 1:  # Executed successfully (OK clicked)
                files = file_picker.getFiles()
                if files:
                    file_url = files[0]
                    # Convert file URL (file:///path/to/file) to system path
                    system_path = uno.fileUrlToSystemPath(file_url)

                    with open(
                        system_path, mode="w", newline="", encoding="utf-8"
                    ) as csv_file:
                        writer = csv.writer(csv_file)
                        # Write CSV Header
                        writer.writerow(
                            ["Severity", "Rule ID", "Title", "Description", "Location"]
                        )

                        # Write Issues
                        for issue in self.issues:
                            writer.writerow(
                                [
                                    issue.severity.value,
                                    issue.rule_id,
                                    issue.title,
                                    issue.description,
                                    getattr(issue, "location", "N/A"),
                                ]
                            )
        except Exception as e:
            print(f"Error exporting CSV: {e}")

    def show(self):
        smgr = self.ctx.ServiceManager
        toolkit = smgr.createInstanceWithContext("com.sun.star.awt.Toolkit", self.ctx)

        # 1. Create Dialog Model
        dialog_model = smgr.createInstanceWithContext(
            "com.sun.star.awt.UnoControlDialogModel", self.ctx
        )
        dialog_model.PositionX = 150
        dialog_model.PositionY = 150
        dialog_model.Width = 320
        dialog_model.Height = 220
        dialog_model.Title = "Privacy Scanner Report"

        # 2. Add Label
        label_model = dialog_model.createInstance(
            "com.sun.star.awt.UnoControlFixedTextModel"
        )
        label_model.PositionX = 10
        label_model.PositionY = 10
        label_model.Width = 300
        label_model.Height = 15
        label_model.Label = f"Scan complete! Found {len(self.issues)} issue(s):"
        dialog_model.insertByName("SummaryLabel", label_model)

        # 3. Add Severity Summary Banner & Formatted List
        high_cnt = sum(1 for i in self.issues if i.severity.value.upper() == "HIGH")
        med_cnt = sum(1 for i in self.issues if i.severity.value.upper() == "MEDIUM")
        low_cnt = sum(1 for i in self.issues if i.severity.value.upper() == "LOW")

        # Create Color-Coded Summary Badges
        badge_y = 30
        for sev_label, count, color in [
            ("HIGH", high_cnt, 0xDC2626),
            ("MEDIUM", med_cnt, 0xEA580C),
            ("LOW", low_cnt, 0xD97706),
        ]:
            if count > 0:
                badge_model = dialog_model.createInstance(
                    "com.sun.star.awt.UnoControlFixedTextModel"
                )
                badge_model.PositionX = (
                    10 if sev_label == "HIGH" else (110 if sev_label == "MEDIUM" else 210)
                )
                badge_model.PositionY = badge_y
                badge_model.Width = 90
                badge_model.Height = 15
                badge_model.TextColor = color
                badge_model.Label = f"● {sev_label}: {count}"
                dialog_model.insertByName(f"Badge_{sev_label}", badge_model)

        # Standard List Box
        list_model = dialog_model.createInstance(
            "com.sun.star.awt.UnoControlListBoxModel"
        )
        list_model.PositionX = 10
        list_model.PositionY = 50
        list_model.Width = 300
        list_model.Height = 120

        if self.issues:
            display_items = tuple(
                f"[{issue.severity.value.upper()}] {issue.title}: {issue.description}"
                for issue in self.issues
            )
        else:
            display_items = ("No privacy issues found in document.",)

        list_model.StringItemList = display_items
        dialog_model.insertByName("IssuesList", list_model)

        # 4. Add Buttons (Export CSV & Close)
        export_btn_model = dialog_model.createInstance(
            "com.sun.star.awt.UnoControlButtonModel"
        )
        export_btn_model.PositionX = 60
        export_btn_model.PositionY = 180
        export_btn_model.Width = 90
        export_btn_model.Height = 25
        export_btn_model.Label = "Export CSV"
        dialog_model.insertByName("ExportButton", export_btn_model)

        close_btn_model = dialog_model.createInstance(
            "com.sun.star.awt.UnoControlButtonModel"
        )
        close_btn_model.PositionX = 170
        close_btn_model.PositionY = 180
        close_btn_model.Width = 90
        close_btn_model.Height = 25
        close_btn_model.Label = "Close"
        dialog_model.insertByName("CloseButton", close_btn_model)
        close_btn_model.PushButtonType = 1  # OK / Close action

        # Highlight detected issues in Writer
        self._highlight_issues()

        # 5. Render
        desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", self.ctx)
        parent_window = None
        if desktop and desktop.getCurrentFrame():
            parent_window = desktop.getCurrentFrame().getContainerWindow()

        dialog = smgr.createInstanceWithContext(
            "com.sun.star.awt.UnoControlDialog", self.ctx
        )
        dialog.setModel(dialog_model)
        dialog.createPeer(toolkit, parent_window)

        # Attach listener to Export CSV button ONCE and keep reference on self
        self._export_listener = ExportActionListener(self._export_to_csv)
        export_control = dialog.getControl("ExportButton")
        if export_control:
            export_control.addActionListener(self._export_listener)

        try:
            dialog.execute()
        finally:
            dialog.dispose()