# -*- coding: utf-8 -*-
"""
BurpFinder500 by /6h4ack (@6h4ack)
"""
from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IHttpRequestResponse
from java.awt import Component
from javax.swing import JScrollPane, JTextArea

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpFinder500")
        callbacks.registerHttpListener(self)
        callbacks.issueAlert("Registered BurpFinder500")
        print("BurpFinder500 extension loaded.")
        return

    def getResponseHeadersAndBody(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response is not None:
                if self._helpers.analyzeResponse(response).getStatusCode() == 500:
                    self._callbacks.issueAlert("Found 500 Error. Check Issue Activity!")

                    self._callbacks.addScanIssue(Error500ScanIssue(
                        messageInfo.getHttpService(),
                        self._helpers.analyzeRequest(messageInfo).getUrl(),
                        [messageInfo]
                    ))

    def getTabCaption(self):
        return "BurpFinder500"

    def getUiComponent(self):
        return self.customPanel

class Error500ScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "500 Error Detected"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return "The response contains a 500 Internal Server Error, indicating a potential issue."

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
         return self._httpMessages

    def getHttpService(self):
        return self._httpService

# Registra la extensión en Burp
if __name__ in ('__main__', '__builtin__'):
    BurpExtender()
