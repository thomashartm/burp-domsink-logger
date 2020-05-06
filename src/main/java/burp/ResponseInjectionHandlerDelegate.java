package burp;

import biz.netcentric.security.Constants;
import biz.netcentric.security.InjectionPayloadProvider;
import org.apache.commons.lang3.StringUtils;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class ResponseInjectionHandlerDelegate implements PropertyChangeListener {

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private InjectionPayloadProvider payloadProvider;

    private AtomicBoolean isSinkLogEnabled = new AtomicBoolean(false);

    private String currentNeedle;

    private AtomicBoolean isTaintMode = new AtomicBoolean(false);

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
            return;
        }

        byte[] rawResponse = message.getMessageInfo().getResponse();
        final IResponseInfo analyzedResponse = this.helpers.analyzeResponse(rawResponse);

        // inject only into html pages
        if (StringUtils.containsAny(analyzedResponse.getInferredMimeType(), "html", "HTML")) {
            List<String> headers = this.helpers.analyzeResponse(rawResponse).getHeaders();

            // get rid of CSPs if logging is enabled
            List<String> sanitizedHeaders = headers;
            if (this.getIsSinkLogEnabled().get()) {
                sanitizedHeaders = headers.stream()
                        .map(header -> {
                            if (this.getIsSinkLogEnabled().get() && header.contains("Content-Security-Policy: ")) {
                                return StringUtils.EMPTY;
                            }
                            return header;
                        })
                        .filter(header -> StringUtils.isNotEmpty(header))
                        .collect(Collectors.toList());
            }

            try {
                byte[] processedResponse = processResponse(rawResponse);
                byte[] editedResponse = this.helpers.buildHttpMessage(sanitizedHeaders, processedResponse);

                message.getMessageInfo().setResponse(editedResponse);
                message.setInterceptAction(message.ACTION_FOLLOW_RULES);
            } catch (IOException e) {
                this.callbacks.printError(e.getMessage());
            }
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

    protected String takeCareOfCSPs(final String responseBody) {
        if (this.getIsSinkLogEnabled().get()) {
            return responseBody.replaceAll(Constants.CSP_DETECTION_PATTERN, StringUtils.EMPTY);
        }
        return responseBody;
    }

    protected byte[] injectIntoHtml(String readableResponseBody) throws IOException {
        int headIndex = StringUtils.indexOfIgnoreCase(readableResponseBody, "<head");
        if (headIndex > 0) {
            final String preparedResponse = takeCareOfCSPs(readableResponseBody);
            final String metaCsp = this.payloadProvider.retrieveTrustedTypesCSPMetaTag();

            String trustedTypesPayload = this.payloadProvider.retrieveTrustedTypesPayload();
            if (StringUtils.isNotBlank(this.currentNeedle)) {
                trustedTypesPayload = trustedTypesPayload
                        .replace("const TAINT_VALUE = \"\";", "const TAINT_VALUE = \"" + this.currentNeedle + "\";");
            }

            if(this.isTaintMode.get()){
                trustedTypesPayload = trustedTypesPayload.replace("const checkTaint = false;", "const checkTaint = true;");
            }else{
                trustedTypesPayload = trustedTypesPayload.replace("const checkTaint = true;", "const checkTaint = false;");
            }

            final String modifiedResponse = StringUtils
                    .replaceOnceIgnoreCase(preparedResponse, "<head>",
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

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        final String propertyName = event.getPropertyName();
        final Object eventValue = event.getNewValue();

        if (Property.ENABLED.same(propertyName)) {
            this.isSinkLogEnabled.set((Boolean) eventValue);
        } else if (Property.OPERATIONS_MODE.same(propertyName)) {
            this.isTaintMode.set((Boolean) eventValue);
        } else if (Property.TAINT_NEEDLE.same(propertyName)) {
            this.currentNeedle = (String) eventValue;
        }
    }
}