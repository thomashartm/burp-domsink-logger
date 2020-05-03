package burp;

import biz.netcentric.security.Constants;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * This plugin injects a trusted types default policy into a page.
 * See https://w3c.github.io/webappsec-trusted-types/dist/spec/#trusted-html
 * <p>
 * This allows to log any payload and sink whenever html or a script is created through a DOM operation.
 * It is using the TT polyfill and adds it in combination with the trusted types CSP to enable the behaviour.
 * Use it with a recent Chrome version.
 */
public class BurpExtender implements IBurpExtender, IProxyListener, ITab {

    private static final String EXTENSION_NAME = "Dom Injector";

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private JPanel pluginConfigurationPanel;

    private ResponseInjectionHandlerDelegate injectionDelegate;

    private JPanel component;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = iBurpExtenderCallbacks.getHelpers();

        this.injectionDelegate = new ResponseInjectionHandlerDelegate(callbacks, helpers);
        this.createUserInterface();

        this.callbacks.addSuiteTab(this);
        this.callbacks.registerProxyListener(this);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        this.injectionDelegate.handleResponseMessage(messageIsRequest, message);
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return new JScrollPane(component);
    }

    private void createUserInterface() {
        component = new JPanel();
        this.pluginConfigurationPanel = new JPanel(new GridLayout(7,2,2,0));
        this.pluginConfigurationPanel.add(new JLabel("DOM Sink Logging using Trusted Types. "
                + "You might need to empty the browser cache before the payload getÄs effective.", SwingConstants.LEFT));

        this.addLoggingEnabledCheckbox();
        this.addNeedleInputField();

        component.add(this.pluginConfigurationPanel);
        callbacks.customizeUiComponent(component);
    }

    private void addLoggingEnabledCheckbox() {
        final JCheckBox triggerCheckbox = new JCheckBox(
                "Enable Dom Sink logging.", this.injectionDelegate.getIsSinkLogEnabled().get());
        triggerCheckbox.addItemListener(event -> {
            if (event.getStateChange() == ItemEvent.SELECTED) {
                this.injectionDelegate.setSinkLogging(true);
            } else {
                this.injectionDelegate.setSinkLogging(false);
            }
            this.callbacks.printOutput("Logging state: " + this.injectionDelegate.getIsSinkLogEnabled().get());
        });

        this.pluginConfigurationPanel.add(triggerCheckbox);
        this.pluginConfigurationPanel.add(new JLabel());
    }

    private void addNeedleInputField() {
        JLabel currentNeedle = new JLabel("");

        JTextField needleTextField = new JTextField("Enter a needle.", 20);
        currentNeedle.setText(this.injectionDelegate.getCurrentNeedle());
        needleTextField.setText("");

        Consumer<String> consumer = (textToReplace) -> {
            if (StringUtils.isNotBlank(textToReplace)) {
                this.injectionDelegate.setCurrentNeedle(textToReplace);
                currentNeedle.setText(textToReplace);
                needleTextField.setText("");
            } else {
                this.callbacks.printOutput("Needle text field is empty.");
            }
        };

        JButton saveAction = new JButton("Save Needle");
        saveAction.addActionListener(event -> consumer.accept(needleTextField.getText()));

        JButton saveDefaultAction = new JButton("Set Default Needle");
        saveDefaultAction.addActionListener(event -> consumer.accept(Constants.TAINT_STRING_DEFAULT));

        JPanel needlePanel = new JPanel(new GridLayout(2,1));
        needlePanel.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        needlePanel.add(new JLabel("Current taint string (needle) to check for."));
        needlePanel.add(currentNeedle);
        needlePanel.add(needleTextField);
        needlePanel.add(saveAction);

        this.pluginConfigurationPanel.add(needlePanel);
    }
}