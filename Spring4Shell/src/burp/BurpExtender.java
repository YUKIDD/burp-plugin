package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * @author yukidddd
 * @date 2022/7/14 13:58
 */
public class BurpExtender implements IBurpExtender,IScannerCheck {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("SpringScan");

        // obtain our output and error streams
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        // write a message to our output stream
        stdout.println("Hello output");

        // 注册扫描插件
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        byte[] request = iHttpRequestResponse.getRequest();
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        String reqMethod = helpers.analyzeRequest(iHttpRequestResponse).getMethod();
        byte contentType = helpers.analyzeRequest(iHttpRequestResponse).getContentType();
        byte type = parseType(reqMethod,contentType);
        IParameter newParameter = helpers.buildParameter("class.module.classLoader.DefaultAssertionStatus","x",type);
        byte[] newRequest = helpers.updateParameter(request,newParameter);
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        IHttpRequestResponse newIHttpRequestResponse = callbacks.makeHttpRequest(httpService,newRequest);
        byte[] response = newIHttpRequestResponse.getResponse();
        int code = helpers.analyzeResponse(response).getStatusCode();
        if (code == 400) {
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    httpService,
                    url,
                    new IHttpRequestResponse[]{ newIHttpRequestResponse },
                    "Spring4Shell(CVE-2022-22965)",
                    "Found Vulnerability Spring4Shell(CVE-2022-22965)",
                    "High"
            ));
            return issues;
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    public byte parseType(String reqMethod, byte contentType) {
        byte type = IParameter.PARAM_BODY;
        if (reqMethod == "GET") {
            type = IParameter.PARAM_URL;
        } else if (reqMethod == "POST") {
            if (contentType == IRequestInfo.CONTENT_TYPE_JSON) {
                type = IParameter.PARAM_JSON;
            } else if (contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
                type = IParameter.PARAM_BODY;
            }
        }
        return type;
    }
}
