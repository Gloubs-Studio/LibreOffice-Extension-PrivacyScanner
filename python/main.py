# Your UNO entry point now stays minimal, serving purely as the bridge between LibreOffice's service manager
# and your plugin architecture.

import sys
import os


# 1. Ensure local extension path is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import uno
import unohelper
from com.sun.star.task import XJobExecutor # ignore warnings about unused import; it's required for LibreOffice to recognize this as a Job service
from com.sun.star.lang import XServiceInfo # ignore warnings about unused import; it's required for LibreOffice to recognize this as a Job service

from privacy_scanner.core.engine import ScannerEngine
from privacy_scanner.ui.dialog import ScannerDialog


class PrivacyScannerComponent(unohelper.Base, XJobExecutor, XServiceInfo):
    IMPL_NAME = "org.privacy.PrivacyScanner"
    SERVICE_NAMES = ("com.sun.star.task.Job",)

    def __init__(self, ctx):
        self.ctx = ctx
        self.engine = ScannerEngine()

    def trigger(self, args):
        try:
            desktop = self.ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", self.ctx
            )
            doc = desktop.getCurrentComponent()

            if doc is None:
                return

            # Execute all rules
            issues = self.engine.run_all(doc)

            # Display results in UI
            dialog = ScannerDialog(self.ctx, doc, issues)
            dialog.show()

        except Exception as e:
            # Display any runtime python error inside a LibreOffice message box
            self._show_error_dialog(f"Privacy Scanner Error: {str(e)}")

    def _show_error_dialog(self, message):
        try:
            toolkit = self.ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.awt.Toolkit", self.ctx
            )
            parent = toolkit.getDesktopWindow()
            box = toolkit.createMessageBox(
                parent, 1, 1, "Error", str(message)
            )
            box.execute()
        except Exception:
            print(message)

    # --- XServiceInfo ---
    def getImplementationName(self):
        return self.IMPL_NAME

    def supportsService(self, service_name):
        return service_name in self.SERVICE_NAMES

    def getSupportedServiceNames(self):
        return self.SERVICE_NAMES


g_ImplementationHelper = unohelper.ImplementationHelper()
g_ImplementationHelper.addImplementation(
    PrivacyScannerComponent,
    PrivacyScannerComponent.IMPL_NAME,
    PrivacyScannerComponent.SERVICE_NAMES,
)