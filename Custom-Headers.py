# -*- coding: utf-8 -*-
#
# Custom Headers (Persistent) -- Jython Burp Suite extension
#
# - Adds a UI tab where you manage any number of custom request headers.
# - Settings are stored with saveExtensionSetting(), which writes to Burp's
#   USER-LEVEL preferences. That means they survive Burp restarts AND are
#   shared across every Burp project automatically (unlike project settings).
# - Each header can be toggled on/off individually, and the whole extension
#   has a master enable switch plus an optional host-scope filter.
#
# Load via: Extensions > Installed > Add > Extension type: Python
# (requires the Jython standalone .jar configured under Extensions > Options)

from burp import IBurpExtender
from burp import IHttpListener
from burp import IBurpExtenderCallbacks
from burp import ITab

from javax.swing import (JPanel, JTable, JButton, JScrollPane, JLabel,
                         JCheckBox, JTextField, BoxLayout, BorderFactory,
                         ListSelectionModel)
from javax.swing.table import AbstractTableModel
from javax.swing.event import TableModelListener
from java.awt import BorderLayout, FlowLayout, Font, Dimension
from java.lang import Boolean, String

import json


# --------------------------------------------------------------------------
# Table model: holds rows of [enabled(bool), name(str), value(str)]
# --------------------------------------------------------------------------
class HeadersTableModel(AbstractTableModel):
    COLUMNS = ["Enabled", "Header Name", "Header Value"]

    def __init__(self, rows=None):
        self._rows = rows if rows is not None else []

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getColumnClass(self, col):
        # Returning Boolean.class makes column 0 render as a checkbox.
        return Boolean if col == 0 else String

    def isCellEditable(self, row, col):
        return True

    def getValueAt(self, row, col):
        r = self._rows[row]
        if col == 0:
            return Boolean(bool(r[0]))
        elif col == 1:
            return r[1]
        else:
            return r[2]

    def setValueAt(self, value, row, col):
        r = self._rows[row]
        if col == 0:
            try:
                r[0] = value.booleanValue()      # java.lang.Boolean from checkbox
            except AttributeError:
                r[0] = bool(value)
        elif col == 1:
            r[1] = unicode(value) if value is not None else u""
        else:
            r[2] = unicode(value) if value is not None else u""
        self.fireTableCellUpdated(row, col)

    def addRow(self, enabled=True, name=u"", value=u""):
        self._rows.append([enabled, name, value])
        last = len(self._rows) - 1
        self.fireTableRowsInserted(last, last)

    def removeRow(self, row):
        if 0 <= row < len(self._rows):
            del self._rows[row]
            self.fireTableRowsDeleted(row, row)

    def getRows(self):
        return [list(r) for r in self._rows]


# --------------------------------------------------------------------------
# Small adapter so any data change auto-saves
# --------------------------------------------------------------------------
class _SaveOnChange(TableModelListener):
    def __init__(self, callback):
        self._callback = callback

    def tableChanged(self, event):
        self._callback()


# --------------------------------------------------------------------------
# Main extension
# --------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IHttpListener, ITab):

    # User-level setting keys (shared across projects + restarts)
    SETTINGS_KEY = "custom_headers_persistent_v1"
    ENABLED_KEY  = "custom_headers_enabled_v1"
    SCOPE_KEY    = "custom_headers_scope_v1"

    # Restrict to these tools. Set to None to apply to ALL tools.
    ENABLED_TOOLS = [
        IBurpExtenderCallbacks.TOOL_PROXY,
        IBurpExtenderCallbacks.TOOL_SCANNER,
        IBurpExtenderCallbacks.TOOL_REPEATER,
        IBurpExtenderCallbacks.TOOL_INTRUDER,
    ]

    # ---- lifecycle ----
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Headers (Persistent)")

        # runtime state
        self._headers = []          # list of [enabled, name, value]
        self._active_headers = []   # cached snapshot of enabled (name, value)
        self._master_enabled = True
        self._scope_hosts = []

        self._load_settings()
        self._build_ui()

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        print("[+] Custom Headers (Persistent) loaded")
        self._print_status()

    # ---- persistence ----
    def _load_settings(self):
        rows = []
        raw = self._callbacks.loadExtensionSetting(self.SETTINGS_KEY)
        if raw:
            try:
                for item in json.loads(raw):
                    rows.append([bool(item.get("enabled", True)),
                                 item.get("name", u""),
                                 item.get("value", u"")])
            except Exception as e:
                print("[!] Could not parse saved headers: %s" % e)
        if not rows:
            rows = [[True, u"HackerOne", u"falasi"]]   # seed default on first run
        self._headers = rows

        en = self._callbacks.loadExtensionSetting(self.ENABLED_KEY)
        self._master_enabled = (en != "false")   # default True

        scope = self._callbacks.loadExtensionSetting(self.SCOPE_KEY)
        if scope:
            self._scope_hosts = [h.strip() for h in scope.split(",") if h.strip()]
        else:
            self._scope_hosts = []

    def _save_settings(self):
        data = [{"enabled": bool(r[0]), "name": r[1], "value": r[2]}
                for r in self._headers]
        self._callbacks.saveExtensionSetting(self.SETTINGS_KEY, json.dumps(data))
        self._callbacks.saveExtensionSetting(
            self.ENABLED_KEY, "true" if self._master_enabled else "false")
        self._callbacks.saveExtensionSetting(
            self.SCOPE_KEY, ",".join(self._scope_hosts))

    def _apply_and_save(self):
        """Rebuild the active snapshot from the table, then persist everything."""
        rows = self._model.getRows()
        active = []
        for r in rows:
            if r[0] and r[1] and r[1].strip():
                active.append((r[1], r[2]))
        self._active_headers = active     # atomic reference swap for the listener
        self._headers = rows
        self._save_settings()

    # ---- UI ----
    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        title = JLabel("Custom Headers")
        title.setFont(Font("Dialog", Font.BOLD, 16))
        top.add(title)

        top.add(JLabel("Headers are injected into outgoing requests. "
                       "Settings persist across restarts and across all projects."))

        self._enabled_cb = JCheckBox("Extension enabled",
                                     self._master_enabled,
                                     actionPerformed=self._toggle_enabled)
        top.add(self._enabled_cb)

        scope_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        scope_panel.add(JLabel("Scope hosts (comma-separated, blank = all):"))
        self._scope_field = JTextField(", ".join(self._scope_hosts), 28)
        scope_panel.add(self._scope_field)
        scope_panel.add(JButton("Apply scope", actionPerformed=self._apply_scope))
        top.add(scope_panel)

        self._panel.add(top, BorderLayout.NORTH)

        # table
        self._model = HeadersTableModel([list(r) for r in self._headers])
        self._table = JTable(self._model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.getColumnModel().getColumn(0).setMaxWidth(70)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(70)
        self._table.setPreferredScrollableViewportSize(Dimension(600, 220))
        self._panel.add(JScrollPane(self._table), BorderLayout.CENTER)

        # buttons
        btns = JPanel(FlowLayout(FlowLayout.LEFT))
        btns.add(JButton("Add header", actionPerformed=self._on_add))
        btns.add(JButton("Remove selected", actionPerformed=self._on_remove))
        self._panel.add(btns, BorderLayout.SOUTH)

        # auto-save on any edit/add/remove
        self._model.addTableModelListener(_SaveOnChange(self._apply_and_save))

        # build the first snapshot from loaded data
        self._apply_and_save()

    # ---- UI handlers ----
    def _toggle_enabled(self, event=None):
        self._master_enabled = self._enabled_cb.isSelected()
        self._save_settings()
        self._print_status()

    def _apply_scope(self, event=None):
        txt = self._scope_field.getText()
        self._scope_hosts = [h.strip() for h in txt.split(",") if h.strip()]
        self._save_settings()
        self._print_status()

    def _on_add(self, event=None):
        self._model.addRow(True, u"New-Header", u"value")

    def _on_remove(self, event=None):
        row = self._table.getSelectedRow()
        if row >= 0:
            if self._table.isEditing():
                self._table.getCellEditor().stopCellEditing()
            self._model.removeRow(row)

    def _print_status(self):
        print("[+] Enabled: %s | Active headers: %d | Scope: %s"
              % (self._master_enabled,
                 len(self._active_headers),
                 ", ".join(self._scope_hosts) if self._scope_hosts else "ALL hosts"))

    # ---- ITab ----
    def getTabCaption(self):
        return "Custom Headers"

    def getUiComponent(self):
        return self._panel

    # ---- IHttpListener ----
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        if not self._master_enabled:
            return
        if self.ENABLED_TOOLS is not None and toolFlag not in self.ENABLED_TOOLS:
            return

        active = self._active_headers   # snapshot reference
        if not active:
            return

        if self._scope_hosts:
            host = messageInfo.getHttpService().getHost()
            if not any(s.lower() in host.lower() for s in self._scope_hosts):
                return

        request = messageInfo.getRequest()
        info = self._helpers.analyzeRequest(request)
        headers = list(info.getHeaders())
        body = request[info.getBodyOffset():]

        for name, value in active:
            lname = name.lower()
            # drop any existing copy to avoid duplicates, then append ours
            headers = [h for h in headers if not h.lower().startswith(lname + ":")]
            headers.append("%s: %s" % (name, value))

        messageInfo.setRequest(self._helpers.buildHttpMessage(headers, body))
