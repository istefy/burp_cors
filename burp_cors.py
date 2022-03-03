from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IExtensionHelpers

from exceptions_fix import FixBurpExceptions

from java.io import PrintWriter
import sys
class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):

        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = PrintWriter(callbacks.getStdout(), True)
        sys.stderr = PrintWriter(callbacks.getStdout(), True)
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("CORS check")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    def _generate_payloads(self, url):

        host = url.getHost()
        payloads = {}

        # trust any origin
        payload_url = 'https://vasya.xyz'
        payloads['trust_any_origin'] = {'origin': payload_url, 'description': 'Site trust any origin', 'severity': 'High'}
        # trust insecure protocol
        payload_url = 'http://{}'.format(host)
        payloads['trust_http'] = {'origin': payload_url, 'description': 'Site trust insecure protocol', 'severity': 'Low'}
        # trust any subdomain
        # payload_url = 'https://vasya.{}'.format(host)
        # payloads['trust_any_subdomain'] = {'origin': payload_url, 'description': 'Site trust any subdomain', 'severity': 'Low'}
        # trust null
        payload_url = 'null'
        payloads['trust_null'] = {'origin': payload_url, 'description': 'Site trust null origin', 'severity': 'High'}
        # prefix match
        payload_url = 'https://{}.vasya.xyz'.format(host)
        payloads['trust_prefix'] = {'origin': payload_url, 'description': 'Site trust prefix', 'severity': 'High'}
        # suffix match
        # payload_url = 'https://vasya.xyz.{}'.format(host)
        # payloads['trust_suffix'] = {'origin': payload_url, 'description': 'Site trust suffix', 'severity':'Low'}
        # underscope bypass
        payload_url = 'https://{}_vasya.xyz'.format(host)
        payloads['underscope_bypass'] = {'origin': payload_url, 'description': 'Underscope bypass', 'severity':'High'}
        # whitespace bypass
        payload_url = 'https://{} vasya.xyz'.format(host)
        payloads['whitespace_check'] = {'origin': payload_url, 'description': 'Whitespace bypass', 'severity': 'High'}
        # trust invalid dot escape
        if host.count('.') > 1:
            last_index = host.rfind('.')
            payload_url = 'https://{}'.format(host[0:last_index].replace('.','x')+host[last_index:])
            payloads['trust_invalid_regex'] = {'origin': payload_url, 'description': 'Site trust origin with unescaped dot', 'severity': 'High'}
        return payloads

    def _add_origin(self, headers, value):
        new_headers = [h for h in headers if not "Origin:" in h]
        new_headers.append("Origin: {}".format(value))
        return new_headers

    def doPassiveScan(self, baseRequestResponse):

        request_url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        response = baseRequestResponse.getResponse()
        res_type = self._helpers.analyzeResponse(response).getStatedMimeType()

        if self._callbacks.isInScope(request_url) and (res_type == "JSON" or res_type == "HTML"):
            response_headers = list(self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders()) 
            for response_header in response_headers:
                if 'access-control-allow-origin' in response_header.lower() or 'access-control-allow-credentials' in response_header.lower():
                    request_headers = list(self._helpers.analyzeRequest(baseRequestResponse).getHeaders())

                    # wildcard check
                    if response_header.lower() == 'access-control-allow-origin: *':
                        return CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        request_url,
                        [baseRequestResponse],
                        'CORS Misconfiguration',
                        'Site trust any origin',
                        'Medium'
                    )

                    issues = []
                    payloads = self._generate_payloads(request_url)

                    for payload in payloads.values():
                        payload_headers = self._add_origin(request_headers, payload['origin'])

                        body_offset = self._helpers.analyzeRequest(baseRequestResponse).getBodyOffset()
                        request_body = baseRequestResponse.getRequest()[body_offset:]

                        if len(request_body) == 0:
                            request = self._helpers.buildHttpMessage(payload_headers, None)
                        else:
                            request = self._helpers.buildHttpMessage(payload_headers, request_body)

                        response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request)
                        response_headers = list(self._helpers.analyzeResponse(response.getResponse()).getHeaders())

                        for response_header in response_headers:
                            if 'access-control-allow-origin'.lower() in response_header:
                                issues.append(
                                    CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        request_url,
                                        [response],
                                        'CORS Misconfiguration',
                                        payload['origin']+"<br><br>"+payload['description'],
                                        payload['severity']
                                    )
                                )
                                break

                    return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
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
        self._confidence = 'Certain'
        return

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

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