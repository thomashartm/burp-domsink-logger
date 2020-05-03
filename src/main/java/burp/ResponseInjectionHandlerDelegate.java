package burp;

import biz.netcentric.security.Constants;
import biz.netcentric.security.InjectionPayloadProvider;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class ResponseInjectionHandlerDelegate {

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private InjectionPayloadProvider payloadProvider;

    private AtomicBoolean isSinkLogEnabled = new AtomicBoolean(false);

    private String currentNeedle;

    public ResponseInjectionHandlerDelegate(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloadProvider = new InjectionPayloadProvider();
        this.currentNeedle = Constants.TAINT_STRING_DEFAULT;
    }

    public void setSinkLogging(final boolean state) {
        this.isSinkLogEnabled.set(state);
    }

    public void handleResponseMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            return;
        }

        if (!this.isSinkLogEnabled.get()) {
            //this.callbacks.printOutput("Ignoring response. Logging state: " + this.isSinkLogEnabled.get());
            return;
        }

        byte[] rawResponse = message.getMessageInfo().getResponse();
        final IResponseInfo analyzedResponse = this.helpers.analyzeResponse(rawResponse);

        // inject only into html pages
        if (StringUtils.containsAny(analyzedResponse.getInferredMimeType(), "html", "HTML")) {
            List<String> headers = this.helpers.analyzeResponse(rawResponse).getHeaders();
            try {
                byte[] processedResponse = processResponse(rawResponse);
                byte[] editedResponse = this.helpers.buildHttpMessage(headers, processedResponse);

                message.getMessageInfo().setResponse(editedResponse);
                message.setInterceptAction(message.ACTION_FOLLOW_RULES);
            } catch (IOException e) {
                this.callbacks.printError(e.getMessage());
            }
        } else {
            this.callbacks.printOutput("Ignoring response. Logging state: " + this.isSinkLogEnabled.get() + " and mime " + analyzedResponse
                    .getInferredMimeType());
        }
    }

    protected byte[] processResponse(byte[] rawResponse) throws IOException {
        final IResponseInfo analyzedResponse = this.helpers.analyzeResponse(rawResponse);

        final byte[] responseBody = getResponseBody(rawResponse, analyzedResponse);
        final String readableResponseBody = this.helpers.bytesToString(responseBody).trim();
        final String responseLeftPeek = StringUtils.left(readableResponseBody, 100);

        if (StringUtils.startsWithAny(responseLeftPeek.toLowerCase(), "<html", "<!doctype html")) {
            return this.injectIntoHtml(readableResponseBody);
        }

        return responseBody;
    }

    protected byte[] injectIntoHtml(String readableResponseBody) throws IOException {
        int headIndex = StringUtils.indexOfIgnoreCase(readableResponseBody, "<head");
        if (headIndex > 0) {
            final String metaCsp = this.payloadProvider.retrieveTrustedTypesCSPMetaTag();

            String trustedTypesPayload = this.payloadProvider.retrieveTrustedTypesPayload();
            if (StringUtils.isNotBlank(this.currentNeedle)) {
                trustedTypesPayload = trustedTypesPayload
                        .replace("const TAINT_VALUE = \"\";", "const TAINT_VALUE = \"" + this.currentNeedle + "\";")
                        .replace("const checkTaint = false;", "const checkTaint = true;");
            }

            final String modifiedResponse = StringUtils
                    .replaceOnceIgnoreCase(readableResponseBody, "<head>",
                            "<head>" + metaCsp + trustedTypesPayload);
            return this.helpers.stringToBytes(modifiedResponse);
        }

        return this.helpers.stringToBytes(readableResponseBody);
    }

    private byte[] getResponseBody(byte[] rawResponse, IResponseInfo analyzedResponse) {
        int bodyOffset = analyzedResponse.getBodyOffset();
        return Arrays.copyOfRange(rawResponse, bodyOffset, rawResponse.length);
    }

    public void setCurrentNeedle(String currentNeedle) {
        this.currentNeedle = currentNeedle;
    }

    public AtomicBoolean getIsSinkLogEnabled() {
        return isSinkLogEnabled;
    }

    public String getCurrentNeedle() {
        return currentNeedle;
    }
}