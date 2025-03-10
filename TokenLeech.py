# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener
from javax.swing import JPanel, JButton, JFileChooser, JLabel, JTextField, JTextArea, Timer, JScrollPane, SwingUtilities, SwingWorker, JCheckBox, JOptionPane
from java.awt import FlowLayout, Dimension
from javax.swing import BoxLayout
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout
import re
import os
import commands  # Using Jython's commands module
import datetime
import pickle

'''
This Burp Suite extension injects HTTP headers into requests by reading values from a file.
It is useful for dynamically updating authentication tokens or API keys from CLI tools, scripts, or external sources.
All settings are persisted between Burp restarts.

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

class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener):

    # Settings persistence implementation
    def saveSettings(self):
        """Save all user settings to Burp's extension settings."""
        try:
            settings = {
                'file_path': self.file_path_field.getText(),
                'command': self.command_field.getText(),
                'allowed_hosts': self.allowed_hosts_field.getText(),
                'target_header': self.target_header_field.getText(),
                'interval': self.interval_field.getText(),
                'exec_command': self.exec_command_checkbox.isSelected()
            }
            
            # Serialize settings to string
            serialized = pickle.dumps(settings)
            
            # Save to Burp's persistent storage
            self._callbacks.saveExtensionSetting("settings", serialized)
            self.log("Settings saved successfully")
        except Exception as e:
            self.log("Error saving settings: " + str(e))

    def loadSettings(self):
        """Load all user settings from Burp's extension settings."""
        try:
            serialized = self._callbacks.loadExtensionSetting("settings")
            if serialized:
                settings = pickle.loads(serialized)
                
                # Apply loaded settings to UI components
                if 'file_path' in settings and settings['file_path']:
                    self.file_path_field.setText(settings['file_path'])
                
                if 'command' in settings and settings['command']:
                    self.command_field.setText(settings['command'])
                
                if 'allowed_hosts' in settings and settings['allowed_hosts']:
                    self.allowed_hosts_field.setText(settings['allowed_hosts'])
                    self.allowed_hosts = settings['allowed_hosts']
                
                if 'target_header' in settings and settings['target_header']:
                    self.target_header_field.setText(settings['target_header'])
                    self.target_header = settings['target_header']
                
                if 'interval' in settings and settings['interval']:
                    self.interval_field.setText(settings['interval'])
                
                if 'exec_command' in settings:
                    self.exec_command_checkbox.setSelected(settings['exec_command'])
                
                self.log("Settings loaded successfully")
                
                # Read the auth header file if a path is set
                file_path = self.file_path_field.getText().strip()
                if file_path:
                    self.readAuthHeader(file_path)
            else:
                self.log("No saved settings found")
        except Exception as e:
            self.log("Error loading settings: " + str(e))

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
        allowed_hosts_label = JLabel("Allowed Host (Prevents sensitive headers from being sent to 3rd party services): ")
        filter_panel.add(allowed_hosts_label)
        self.allowed_hosts_field = JTextField(20)
        self.allowed_hosts_field.setPreferredSize(Dimension(200, 25))
        self.allowed_hosts_field.setToolTipText("Enter allowed host patterns (e.g., '*' for all or 'example.com' for a specific host). Use commas for multiple hosts.")
        self.set_hosts_button = JButton("Set Allowed Hosts", actionPerformed=self.setAllowedHosts)
        self.set_hosts_button.setToolTipText("Click to update the allowed hosts for header injection.")
        filter_panel.add(self.allowed_hosts_field)
        filter_panel.add(self.set_hosts_button)
        main_panel.add(filter_panel)

        # Header Selection UI Section
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_label = JLabel("Header to Replace (e.g., Authorization, X-API-Key):")
        header_panel.add(header_label)
        self.target_header_field = JTextField(20)
        self.target_header_field.setPreferredSize(Dimension(200, 25))
        self.target_header_field.setToolTipText("Specify the header name that you want to update.")
        self.set_header_button = JButton("Set Header", actionPerformed=self.setTargetHeader)
        self.set_header_button.setToolTipText("Click to update the target header name.")
        header_panel.add(self.target_header_field)
        header_panel.add(self.set_header_button)
        main_panel.add(header_panel)

        # File Selection UI Section 
        file_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        file_label = JLabel("File Containing Header Value:")
        file_panel.add(file_label)
        self.file_path_field = JTextField(20)
        self.file_path_field.setPreferredSize(Dimension(200, 25))
        self.file_path_field.setToolTipText("Path to the file that holds the header value.")
        self.load_button = JButton("Select File", actionPerformed=self.loadFile)
        self.load_button.setToolTipText("Click to choose a file containing the header value.")
        self.refresh_button = JButton("Read File", actionPerformed=self.refreshFile)
        self.refresh_button.setToolTipText("Click to manually read the file and update the header value.")
        file_panel.add(self.file_path_field)
        file_panel.add(self.load_button)
        file_panel.add(self.refresh_button)
        main_panel.add(file_panel)

        # Command Execution UI Section
        command_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        command_label = JLabel("Command to Execute (Optional):")
        command_panel.add(command_label)
        self.command_field = JTextField(50)
        self.command_field.setPreferredSize(Dimension(400, 25))
        self.command_field.setToolTipText("Enter a command to execute before reading the file (e.g., to update the file contents).")
        command_panel.add(self.command_field)
        # New Refresh button added next to the command input:
        self.command_refresh_button = JButton("Refresh", actionPerformed=self.refreshFile)
        self.command_refresh_button.setToolTipText("Click to execute the command (if provided) and refresh the header value from the file.")
        command_panel.add(self.command_refresh_button)
        main_panel.add(command_panel)

        # Auto-Refresh UI Section
        refresh_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        auto_label = JLabel("Auto Refresh Interval (seconds):")
        refresh_panel.add(auto_label)
        self.interval_field = JTextField("10", 5)
        self.interval_field.setPreferredSize(Dimension(60, 25))
        self.interval_field.setToolTipText("Set the interval (in seconds) at which the file will be automatically refreshed.")
        self.start_timer_button = JButton("Start Auto Refresh", actionPerformed=self.startAutoRefresh)
        self.start_timer_button.setToolTipText("Start automatically refreshing the file at the specified interval.")
        self.stop_timer_button = JButton("Stop Auto Refresh", actionPerformed=self.stopAutoRefresh)
        self.stop_timer_button.setToolTipText("Stop the automatic refresh process.")
        # Checkbox to control command execution on auto-refresh
        self.exec_command_checkbox = JCheckBox("Execute command before reading file", True)
        self.exec_command_checkbox.setToolTipText("Check to execute the command (if provided) before refreshing the file on auto-refresh.")
        refresh_panel.add(self.interval_field)
        refresh_panel.add(self.start_timer_button)
        refresh_panel.add(self.stop_timer_button)
        refresh_panel.add(self.exec_command_checkbox)
        main_panel.add(refresh_panel)

        # File Contents Display UI Section
        contents_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        contents_label = JLabel("File Contents:")
        contents_panel.add(contents_label)
        self.file_contents_area = JTextArea(5, 50)
        self.file_contents_area.setEditable(False)
        self.file_contents_area.setToolTipText("Displays the current value read from the file.")
        contents_scroll_pane = JScrollPane(self.file_contents_area)
        contents_scroll_pane.setPreferredSize(Dimension(400, 80))
        contents_panel.add(contents_scroll_pane)
        main_panel.add(contents_panel)

        # Help/Info Button Section
        info_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.info_button = JButton("Info", actionPerformed=self.showInfo)
        self.info_button.setToolTipText("Click for detailed information about what each control does.")
        # Add a Save Settings button
        self.save_settings_button = JButton("Save Settings", actionPerformed=self.onSaveSettings)
        self.save_settings_button.setToolTipText("Click to save all current settings for persistence.")
        info_panel.add(self.save_settings_button)
        info_panel.add(self.info_button)
        main_panel.add(info_panel)

        # Output Log Display UI Section
        log_panel = JPanel()
        log_panel.setLayout(BoxLayout(log_panel, BoxLayout.Y_AXIS))
        log_label = JLabel("Output Log:")
        log_panel.add(log_label)
        self.output_log_area = JTextArea(10, 50)
        self.output_log_area.setEditable(False)
        self.output_log_area.setToolTipText("Displays all log output with timestamps.")
        log_scroll_pane = JScrollPane(self.output_log_area)
        log_scroll_pane.setPreferredSize(Dimension(400, 150))
        log_panel.add(log_scroll_pane)
        main_panel.add(log_panel)

        self.panel.add(main_panel, BorderLayout.NORTH)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        # Load saved settings after UI initialization
        self.loadSettings()

    def onSaveSettings(self, event):
        """Handle the save settings button click."""
        self.saveSettings()

    def getTabCaption(self):
        return "Token Leech"

    def getUiComponent(self):
        return self.panel

    def log(self, message):
        """Append a message with a timestamp to the output log UI component."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = "[{}] {}\n".format(timestamp, message)
        # Ensure UI update happens on the Swing thread.
        SwingUtilities.invokeLater(lambda: self.output_log_area.append(log_message))
        # Optionally, also print to the console:
        print(log_message)

    def showInfo(self, event):
        info_message = (
            "Token Leech Extension Info:\n\n"
            "Allowed Hosts: Specify which hosts are allowed to receive the updated header. "
            "Use '*' to allow all hosts or specify specific hosts (comma separated).\n\n"
            "Header to Replace: The name of the header (e.g., 'Authorization') that will be replaced in the requests.\n\n"
            "File Containing Header Value: Select the file that contains the header value. "
            "The file should have a single header in the format 'Header-Name: Value'.\n\n"
            "Command to Execute: (Optional) A command to run before reading the file. This can be used to update the file contents dynamically.\n\n"
            "Refresh Buttons: Use either 'Read File' or the 'Refresh' button next to the command field to update the header value immediately.\n\n"
            "Auto Refresh Interval: Set the interval (in seconds) for automatically refreshing the file. Use the Start/Stop buttons to control this.\n\n"
            "File Contents Display: Shows the current value read from the file.\n\n"
            "Output Log: Displays all log output along with timestamps.\n\n"
            "Settings Persistence: All settings are automatically loaded when Burp starts and can be manually saved with the 'Save Settings' button."
        )
        JOptionPane.showMessageDialog(self.panel, info_message, "Token Leech - Information", JOptionPane.INFORMATION_MESSAGE)

    def loadFile(self, event):
        chooser = JFileChooser()
        file_filter = FileNameExtensionFilter("Text Files", ["txt"])
        chooser.setFileFilter(file_filter)
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath().strip()
            self.file_path_field.setText(file_path)
            self.readAuthHeader(file_path)
            # Save settings after file selection
            self.saveSettings()

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
                    self.ext.log("Executing command: " + self.command)
                    status, output = commands.getstatusoutput(self.command)
                    self.ext.log("Command executed, status: " + str(status))
                    self.ext.log("Command output:\n" + output)
                except Exception as e:
                    self.ext.log("Error executing command: " + str(e))
            else:
                self.ext.log("Skipping command execution on auto-refresh.")

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
            if not result.startswith("Error loading file:"):
                self.ext.auth_header = result
            else:
                self.ext.auth_header = None
            self.ext.file_contents_area.setText(result)
            self.ext.log("Header value loaded: " + result)

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
            self.log("Header value loaded: " + self.auth_header)
            self.file_contents_area.setText(contents)
        except Exception as e:
            error_message = "Error loading file: " + str(e)
            self.log(error_message)
            self.auth_header = None
            self.file_contents_area.setText(error_message)

    def startAutoRefresh(self, event):
        try:
            interval_seconds = int(self.interval_field.getText())
        except ValueError:
            self.log("Invalid interval specified.")
            return
        if interval_seconds <= 0:
            self.log("Interval must be greater than zero.")
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
        self.log("Auto Refresh started with interval: " + str(interval_seconds) + " seconds")
        
        # Save settings when auto refresh started
        self.saveSettings()

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
        self.log("Auto Refresh stopped.")

    def setAllowedHosts(self, event):
        self.allowed_hosts = self.allowed_hosts_field.getText().strip()
        self.log("Allowed hosts updated to: " + self.allowed_hosts)
        # Save settings after updating allowed hosts
        self.saveSettings()

    def setTargetHeader(self, event):
        self.target_header = self.target_header_field.getText().strip()
        self.log("Target header updated to: " + self.target_header)
        # Save settings after updating target header
        self.saveSettings()

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
    
    # Extension state listener methods
    def extensionUnloaded(self):
        """Handle extension unloading - save settings before unloading."""
        self.stopAutoRefresh(None)  # Stop auto-refresh if running
        self.saveSettings()
        self.log("Extension unloaded, settings saved")
