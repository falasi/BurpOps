from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JButton, JFileChooser, JLabel, JTextField, JTextArea, Timer, JScrollPane
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout
import threading

'''
Read file, and adds the contents into the headers. Works with (Repeater,Proxy,Intruder).

'''

class BurpExtender(IBurpExtender, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        # Save callbacks and helpers.
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auth Header Injector")
        
        # Global variable to hold the auth header (e.g. "Authorization: Bearer <token>")
        self.auth_header = None
        # Timer instance; will be created when auto-refresh is started.
        self.autoRefreshTimer = None

        # Create the UI panel for our extension.
        self.panel = JPanel(BorderLayout())
        top_panel = JPanel()  # Panel to hold our UI components
        
        # Text field to display the file path.
        self.file_path_field = JTextField(30)
        # Button to load the file.
        self.load_button = JButton("Select File", actionPerformed=self.loadFile)
        # Button to manually refresh (re-read) the file.
        self.refresh_button = JButton("Read File", actionPerformed=self.refreshFile)
        
        # New components for auto refresh:
        self.interval_field = JTextField("10", 5)  # default interval in seconds
        self.start_timer_button = JButton("Start Auto Refresh", actionPerformed=self.startAutoRefresh)
        self.stop_timer_button = JButton("Stop Auto Refresh", actionPerformed=self.stopAutoRefresh)
        
        # Add components to the top panel.
        top_panel.add(JLabel("File: "))
        top_panel.add(self.file_path_field)
        top_panel.add(self.load_button)
        top_panel.add(self.refresh_button)
        top_panel.add(JLabel("Read File Contents Every (seconds): "))
        top_panel.add(self.interval_field)
        top_panel.add(self.start_timer_button)
        top_panel.add(self.stop_timer_button)
        
        self.panel.add(top_panel, BorderLayout.NORTH)
        
        # Create a text area (wrapped in a scroll pane) to display the file contents.
        self.file_contents_area = JTextArea(10, 50)
        self.file_contents_area.setEditable(False)
        scroll_pane = JScrollPane(self.file_contents_area)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Register our extension tab with Burp.
        callbacks.addSuiteTab(self)
        # Register this extension as an HTTP listener.
        callbacks.registerHttpListener(self)

    #
    # ITab methods
    #
    def getTabCaption(self):
        return "File Read Header Injector"
    
    def getUiComponent(self):
        return self.panel

    #
    # UI methods
    #
    def loadFile(self, event):
        """Open a file chooser to select the file that holds the auth header."""
        chooser = JFileChooser()
        # For example, we expect a plain text file.
        file_filter = FileNameExtensionFilter("Text Files", ["txt"])
        chooser.setFileFilter(file_filter)
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            # Show the file path in the text field.
            self.file_path_field.setText(file.getAbsolutePath())
            # Read the header from the file.
            self.readAuthHeader(file.getAbsolutePath())

    def refreshFile(self, event):
        """Re-read the file from the saved file path (in case it has been updated)."""
        file_path = self.file_path_field.getText()
        if file_path:
            self.readAuthHeader(file_path)

    def readAuthHeader(self, file_path):
        """Read the header value from the specified file and update the UI."""
        try:
            f = open(file_path, "r")
            # Read the entire file and strip whitespace.
            contents = f.read().strip()
            f.close()
            self.auth_header = contents
            print "Auth header loaded:", self.auth_header
            # Update the text area with the file contents.
            self.file_contents_area.setText(contents)
        except Exception as e:
            print "Failed to load auth header:", str(e)
            self.auth_header = None
            self.file_contents_area.setText("Error loading file.")

    def startAutoRefresh(self, event):
        """Start the auto-refresh timer that re-reads the file every X seconds."""
        try:
            interval_seconds = int(self.interval_field.getText())
        except ValueError:
            print "Invalid interval specified."
            return

        if interval_seconds <= 0:
            print "Interval must be greater than zero."
            return

        delay = interval_seconds * 1000  # Timer delay is in milliseconds

        # Stop any previously running timer.
        if self.autoRefreshTimer is not None:
            self.autoRefreshTimer.stop()

        # Create and start the Swing Timer.
        self.autoRefreshTimer = Timer(delay, self.onAutoRefresh)
        self.autoRefreshTimer.start()
        print "Auto Refresh started with interval:", interval_seconds, "seconds"

    def onAutoRefresh(self, event):
        """Timer callback to refresh the file automatically."""
        file_path = self.file_path_field.getText()
        if file_path:
            self.readAuthHeader(file_path)

    def stopAutoRefresh(self, event):
        """Stop the auto-refresh timer."""
        if self.autoRefreshTimer is not None:
            self.autoRefreshTimer.stop()
            print "Auto Refresh stopped."

    #
    # IHttpListener method
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests (not responses)
        if not messageIsRequest:
            return

        # Get the current request.
        request = messageInfo.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        headers = list(analyzedRequest.getHeaders())

        # If we have a header from the file, inject it.
        if self.auth_header:
            new_headers = []
            # Remove any existing Authorization header(s)
            for header in headers:
                if header.lower().startswith("authorization:"):
                    continue
                new_headers.append(header)
            # Append the new Authorization header.
            new_headers.append(self.auth_header)
            
            # Get the body of the request (if any).
            body = request[analyzedRequest.getBodyOffset():]
            # Rebuild the HTTP message with the new headers.
            new_request = self._helpers.buildHttpMessage(new_headers, body)
            messageInfo.setRequest(new_request)
