package burp;

import biz.netcentric.security.InjectionPayloadProvider;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This plugin injects a trusted types default policy into a page.
 * See https://w3c.github.io/webappsec-trusted-types/dist/spec/#trusted-html
 * <p>
 * This allows to log any payload and sink whenever html or a script is created through a DOM operation.
 * It is using the TT polyfill and adds it in combination with the trusted types CSP to enable the behaviour.
 * Use it with a recent Chrome version.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, ITab {

    private static final String EXTENSION_NAME = "Burp DomSink Injector";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private InjectionPayloadProvider payloadProvider;

    private AtomicBoolean isSinkLogEnabled = new AtomicBoolean(false);

    private JPanel pluginConfigurationPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = iBurpExtenderCallbacks.getHelpers();

        this.createUserInterface();
        this.callbacks.addSuiteTab(this);

        this.callbacks.registerProxyListener(this);
        this.payloadProvider = new InjectionPayloadProvider();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest){
            return;
        }

        if(!this.isSinkLogEnabled.get()){
            this.callbacks.printOutput("Ignoring response. Logging state: " + this.isSinkLogEnabled.get());
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
        }else{
            this.callbacks.printOutput("Ignoring response. Logging state: " + this.isSinkLogEnabled.get() + " and mime " + analyzedResponse.getInferredMimeType());
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
            final String trustedTypesPayload = this.payloadProvider.retrieveTrustedTypesPayload();
            final String modifiedResponse = StringUtils
                    .replaceOnceIgnoreCase(readableResponseBody, "<head>",
                            "<head>" + metaCsp + trustedTypesPayload);
            return this.helpers.stringToBytes(modifiedResponse);
        }

        return this.helpers.stringToBytes(readableResponseBody);
    }

    private boolean checkContentType(List<String> headers, String[] includedContentTypes) {
        return false;
    }

    private byte[] getResponseBody(byte[] rawResponse, IResponseInfo analyzedResponse) {
        int bodyOffset = analyzedResponse.getBodyOffset();
        return Arrays.copyOfRange(rawResponse, bodyOffset, rawResponse.length);
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return this.pluginConfigurationPanel;
    }

    private void createUserInterface() {
        this.pluginConfigurationPanel = new JPanel();
        this.pluginConfigurationPanel.setLayout(new FlowLayout(FlowLayout.LEFT));

        final JCheckBox triggerCheckbox = new JCheckBox(
                "Enable Dom Sink logging.", this.isSinkLogEnabled.get());
        triggerCheckbox.addItemListener(event -> {
            if (event.getStateChange() == ItemEvent.SELECTED) {
                this.isSinkLogEnabled.set(true);
            } else {
                this.isSinkLogEnabled.set(false);
            }
            this.callbacks.printOutput("Logging state: " + this.isSinkLogEnabled.get());
        });

        this.pluginConfigurationPanel.add(new JLabel("DOM Sink Logging using Trusted Types. "));
        this.pluginConfigurationPanel.add(triggerCheckbox);
        this.pluginConfigurationPanel.add(new JLabel("You might need to empty the browser cache."));

    }
}