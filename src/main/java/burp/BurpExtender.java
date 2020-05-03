package burp;

import biz.netcentric.security.Constants;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
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
        this.pluginConfigurationPanel = new JPanel(new GridLayout(7, 2, 1, 0));
        this.pluginConfigurationPanel.add(new JLabel("DOM Sink Logging using Trusted Types. "
                + "You might need to empty the browser cache before the payload is effective.", SwingConstants.LEFT));

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
        currentNeedle.setFocusable(true);
        needleTextField.setText("");

        Consumer<String> consumer = (textToReplace) -> {
            final String taintString = StringUtils.isNotBlank(textToReplace) ? textToReplace : StringUtils.EMPTY;
            this.injectionDelegate.setCurrentNeedle(taintString);

            currentNeedle.setText(taintString);
            needleTextField.setText(StringUtils.EMPTY);
        };

        JButton saveNeedleAction = new JButton("Save Needle");
        saveNeedleAction.addActionListener(event -> consumer.accept(needleTextField.getText()));

        JButton revertToDefaultAction = new JButton("Set Default Needle");
        revertToDefaultAction.addActionListener(event -> consumer.accept(Constants.TAINT_STRING_DEFAULT));

        JButton clearNeedleAction = new JButton("Remove Needle");
        clearNeedleAction.addActionListener(event -> consumer.accept(StringUtils.EMPTY));

        JPanel needlePanel = new JPanel(new GridLayout(3, 2));

        needlePanel.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
        needlePanel.add(new JLabel("Current taint string (needle) to check for."));
        needlePanel.add(currentNeedle);
        needlePanel.add(needleTextField);

        needlePanel.add(saveNeedleAction);
        needlePanel.add(revertToDefaultAction);
        needlePanel.add(clearNeedleAction);
        needlePanel.add(new JLabel("Clear the needle to enable general logging for all sinks."));

        this.pluginConfigurationPanel.add(needlePanel);
    }
}