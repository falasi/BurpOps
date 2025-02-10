# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JButton, JFileChooser, JLabel, JTextField, JTextArea, Timer, JScrollPane, SwingUtilities, SwingWorker, JCheckBox
from java.awt import FlowLayout, Dimension
from javax.swing import BoxLayout
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout
import re
import os
import commands  # Using Jython's commands module

'''
This Burp Suite extension injects HTTP headers into requests by reading values from a file.
It is useful for dynamically updating authentication tokens or API keys from CLI tools, scripts, or external sources.

Example:
    aws sso get-bearer-token > token.txt

The extension reads token.txt and injects the token into Burp Proxy, Repeater, and Intruder.

Expected File Format:
The file should contain a single HTTP header in the format:

    Header-Name: Value

For example:

    Authorization: Bearer abc123xyz

How It Works:
    The extension reads the file and extracts the value after the first colon (:).
    The specified header is removed and re-added with the updated value.
    If the file contains multiple lines or additional colons, only the first occurrence of Header-Name: Value is processed.
'''

class BurpExtender(IBurpExtender, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Token Leech")

        self.auth_header = None
        self.autoRefreshTimer = None
        self.autoRefreshActive = False  # Controls whether auto refresh is active
        self.allowed_hosts = "*"
        self.target_header = "Authorization"  # Default header to modify

        # Create main panel
        self.panel = JPanel(BorderLayout())
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

        # Allowed Hosts UI Section 
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_panel.add(JLabel("Allowed Host (Prevents sensitive headers from being sent to 3rd party services): "))
        self.allowed_hosts_field = JTextField(20)
        self.allowed_hosts_field.setPreferredSize(Dimension(200, 25))
        self.set_hosts_button = JButton("Set Allowed Hosts", actionPerformed=self.setAllowedHosts)
        filter_panel.add(self.allowed_hosts_field)
        filter_panel.add(self.set_hosts_button)
        main_panel.add(filter_panel)

        # Header Selection UI Section
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_panel.add(JLabel("Header to Replace (e.g., Authorization, X-API-Key):"))
        self.target_header_field = JTextField(20)
        self.target_header_field.setPreferredSize(Dimension(200, 25))
        self.set_header_button = JButton("Set Header", actionPerformed=self.setTargetHeader)
        header_panel.add(self.target_header_field)
        header_panel.add(self.set_header_button)
        main_panel.add(header_panel)

        # File Selection UI Section 
        file_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        file_panel.add(JLabel("File Containing Header Value:"))
        self.file_path_field = JTextField(20)
        self.file_path_field.setPreferredSize(Dimension(200, 25))
        self.load_button = JButton("Select File", actionPerformed=self.loadFile)
        self.refresh_button = JButton("Read File", actionPerformed=self.refreshFile)
        file_panel.add(self.file_path_field)
        file_panel.add(self.load_button)
        file_panel.add(self.refresh_button)
        main_panel.add(file_panel)

        # Command Execution UI Section
        command_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        command_panel.add(JLabel("Command to Execute (Optional):"))
        self.command_field = JTextField(50)
        self.command_field.setPreferredSize(Dimension(400, 25))
        command_panel.add(self.command_field)
        main_panel.add(command_panel)

        # Auto-Refresh UI Section
        refresh_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        refresh_panel.add(JLabel("Auto Refresh Interval (seconds):"))
        self.interval_field = JTextField("10", 5)
        self.interval_field.setPreferredSize(Dimension(60, 25))
        self.start_timer_button = JButton("Start Auto Refresh", actionPerformed=self.startAutoRefresh)
        self.stop_timer_button = JButton("Stop Auto Refresh", actionPerformed=self.stopAutoRefresh)
        # Add a checkbox to control whether to execute the command during auto-refresh.
        self.exec_command_checkbox = JCheckBox("Execute command before reading file", True)
        refresh_panel.add(self.interval_field)
        refresh_panel.add(self.start_timer_button)
        refresh_panel.add(self.stop_timer_button)
        refresh_panel.add(self.exec_command_checkbox)
        main_panel.add(refresh_panel)

        # File Contents Display UI Section
        self.file_contents_area = JTextArea(5, 50)
        self.file_contents_area.setEditable(False)
        scroll_pane = JScrollPane(self.file_contents_area)
        scroll_pane.setPreferredSize(Dimension(400, 80))
        main_panel.add(scroll_pane)

        self.panel.add(main_panel, BorderLayout.NORTH)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def getTabCaption(self):
        return "Token Leech"

    def getUiComponent(self):
        return self.panel

    def loadFile(self, event):
        chooser = JFileChooser()
        file_filter = FileNameExtensionFilter("Text Files", ["txt"])
        chooser.setFileFilter(file_filter)
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath().strip()
            self.file_path_field.setText(file_path)
            self.readAuthHeader(file_path)

    def refreshFile(self, event):
        file_path = self.file_path_field.getText().strip()
        if file_path:
            self.runCommandAndRefreshWorker(file_path)

    def runCommandAndRefreshWorker(self, file_path):
        worker = self.CommandAndRefreshWorker(file_path, self.command_field.getText().strip(), self)
        worker.execute()

    class CommandAndRefreshWorker(SwingWorker):
        def __init__(self, file_path, command, ext):
            self.file_path = file_path.strip()
            self.command = command
            self.ext = ext

        def doInBackground(self):
            # Execute the command if provided and if the checkbox is selected.
            if self.command and self.ext.exec_command_checkbox.isSelected():
                try:
                    print("Executing command: " + self.command)
                    status, output = commands.getstatusoutput(self.command)
                    print("Command executed, status:", status)
                    print("Command output:\n" + output)
                except Exception as e:
                    print("Error executing command: " + str(e))
            else:
                print("Skipping command execution on auto-refresh.")

            try:
                if not os.path.isfile(self.file_path):
                    raise ValueError("File does not exist.")
                with open(self.file_path, "r") as f:
                    contents = f.read().strip()
                if not contents:
                    raise ValueError("File is empty.")
                if ":" in contents:
                    header_parts = contents.split(":", 1)
                    contents = header_parts[1].strip()
                return contents
            except Exception as e:
                return "Error loading file: " + str(e)

        def done(self):
            try:
                result = self.get()
            except Exception as e:
                result = "Error retrieving result: " + str(e)
            self.ext.auth_header = result if not result.startswith("Error loading file:") else None
            self.ext.file_contents_area.setText(result)
            print("Header value loaded:", result)

    def readAuthHeader(self, file_path):
        file_path = file_path.strip()
        try:
            if not os.path.isfile(file_path):
                raise ValueError("File does not exist.")
            with open(file_path, "r") as f:
                contents = f.read().strip()
            if not contents:
                raise ValueError("File is empty.")
            if ":" in contents:
                header_parts = contents.split(":", 1)
                contents = header_parts[1].strip()
            self.auth_header = contents
            print("Header value loaded:", self.auth_header)
            self.file_contents_area.setText(contents)
        except Exception as e:
            error_message = "Error loading file: " + str(e)
            print(error_message)
            self.auth_header = None
            self.file_contents_area.setText(error_message)

    def startAutoRefresh(self, event):
        try:
            interval_seconds = int(self.interval_field.getText())
        except ValueError:
            print("Invalid interval specified.")
            return
        if interval_seconds <= 0:
            print("Interval must be greater than zero.")
            return

        # Run an immediate refresh to pick up any changes in the command field.
        file_path = self.file_path_field.getText().strip()
        if file_path:
            self.runCommandAndRefreshWorker(file_path)
        
        self.autoRefreshActive = True
        delay = interval_seconds * 1000
        if self.autoRefreshTimer is not None:
            self.autoRefreshTimer.stop()
        self.autoRefreshTimer = Timer(delay, self.onAutoRefresh)
        self.autoRefreshTimer.start()
        print("Auto Refresh started with interval:", interval_seconds, "seconds")

    def onAutoRefresh(self, event):
        if not self.autoRefreshActive:
            return
        file_path = self.file_path_field.getText().strip()
        if file_path:
            self.runCommandAndRefreshWorker(file_path)

    def stopAutoRefresh(self, event):
        self.autoRefreshActive = False
        if self.autoRefreshTimer is not None:
            self.autoRefreshTimer.stop()
            self.autoRefreshTimer = None
        print("Auto Refresh stopped.")

    def setAllowedHosts(self, event):
        self.allowed_hosts = self.allowed_hosts_field.getText().strip()
        print("Allowed hosts updated to:", self.allowed_hosts)

    def setTargetHeader(self, event):
        self.target_header = self.target_header_field.getText().strip()
        print("Target header updated to:", self.target_header)

    def matchesAllowedHost(self, url):
        if self.allowed_hosts == "*":
            return True
        allowed_patterns = [pattern.strip() for pattern in self.allowed_hosts.split(",")]
        for pattern in allowed_patterns:
            regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
            if re.match("^{}$".format(regex_pattern), url):
                return True
        return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        request = messageInfo.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        headers = list(analyzedRequest.getHeaders())
        url = messageInfo.getHttpService().getHost()
        target_header_lower = self.target_header.lower()
        if self.auth_header and self.matchesAllowedHost(url):
            new_headers = [header for header in headers if not header.lower().startswith(target_header_lower + ":")]
            new_headers.append("{}: {}".format(self.target_header, self.auth_header))
            body = request[analyzedRequest.getBodyOffset():]
            new_request = self._helpers.buildHttpMessage(new_headers, body)
            messageInfo.setRequest(new_request)
