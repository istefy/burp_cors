from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IExtensionHelpers

from exceptions_fix import FixBurpExceptions
from urlparse import urlparse

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("CORS check")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):

        payloads = ["https://vasya.xyz", "null"]  
        requestURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        response = baseRequestResponse.getResponse()
        res_type = self._helpers.analyzeResponse(response).getStatedMimeType()
        
        if self._callbacks.isInScope(requestURL) and (res_type == "JSON" or res_type == "HTML"):
            requestHeaders = list(self._helpers.analyzeRequest(baseRequestResponse).getHeaders())
            # Post-domain wildcard
            payloads.append("https://"+requestURL.getHost()+".vasya.xyz")
            # Pre-domain wildcard
            payloads.append("https://vasya"+requestURL.getHost())
            # Whitespace check
            payloads.append("https://"+requestURL.getHost()+" vasya.xyz")

            for i in payloads:
                newHeaders = list()
                for header in requestHeaders:
                    if not "If-None-Match:" in header and not "If-Modified-Since:" in header:
                        if "Origin:" in header:
                            newHeaders.append("Origin: {}".format(i))
                        else:
                            newHeaders.append(header)
                if not any("Origin:" in h for h in newHeaders):
                    newHeaders.append("Origin: {}".format(i))

                request = (self._helpers.buildHttpMessage(newHeaders, None))
                response = self._callbacks.makeHttpRequest(requestURL.getHost(), requestURL.getPort(), False if requestURL.getProtocol() == "http" else True, request)
                responseHeaders = list(self._helpers.analyzeResponse(response).getHeaders())

                if "Access-Control-Allow-Origin: {}".format(i) in responseHeaders and "Access-Control-Allow-Credentials: true" in responseHeaders:
                    return [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse],
                        "CORS Misconfig",
                        "CORS Misconfiguration with Origin: "+i,
                        # @TODO A class which implements IHttpRequestResponse needs to be created for a byte > ihttprequestresponse conversion. There's no helper for this
                        "Medium")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
 
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

FixBurpExceptions()