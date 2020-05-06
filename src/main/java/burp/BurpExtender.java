package burp;

import biz.netcentric.security.Constants;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.beans.PropertyChangeListener;
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

    private ResponseInjectionHandlerDelegate injectionDelegate;

    private JPanel userInterface;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = iBurpExtenderCallbacks.getHelpers();

        this.injectionDelegate = new ResponseInjectionHandlerDelegate(callbacks, helpers);

        this.userInterface = this.createUserInterface(this.injectionDelegate);
        callbacks.customizeUiComponent(userInterface);

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
        return new JScrollPane(userInterface);
    }

    private JPanel createUserInterface(final PropertyChangeListener... propertyChangeListeners) {
        final ConfigurationUserInterface userInterface = new ConfigurationUserInterface(this.callbacks);
        for(final PropertyChangeListener listener : propertyChangeListeners){
            userInterface.register(listener);
        }

        return userInterface.createUI();

    }
}