package burp;

import biz.netcentric.security.Constants;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class ConfigurationUserInterface implements PropertyChangeEventProvider{

    private final JPanel panel;

    private final GridBagConstraints constraints;

    private final IBurpExtenderCallbacks callbacks;

    private int rowIndex;

    private List<PropertyChangeListener> propertyChangeListeners;

    public ConfigurationUserInterface(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.propertyChangeListeners = new ArrayList<>();
        panel = new JPanel(new GridBagLayout()); //Create a pane to house all content, and give it a GridBagLayout
        panel.setLayout(new GridBagLayout());
        constraints = new GridBagConstraints();
        constraints.insets = new Insets(5, 5, 0, 0);  //top padding
        this.rowIndex = 0;
    }

    // The main method's purpose is to play with it in isolation
    public static void main(final String args[]) {
        ConfigurationUserInterface userInterface = new ConfigurationUserInterface(null);

        JFrame frame = new JFrame(""); //Create the JFrame and give it a title
        frame.setSize(512, 256); //512 x 256px size
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE); //Quit the application when the JFrame is closed

        JPanel jpanel = userInterface.createUI();
        frame.setContentPane(jpanel);
        frame.setVisible(true); //Show the window
    }

    public JPanel createUI() {
        nextRow();
        enablePluginUI();

        nextRow();
        operationsModeUi();

        nextRow();
        taintValueConfigUi();

        return panel;
    }

    private void taintValueConfigUi() {
        JLabel taintConfig = new JLabel("Taint Needle:");
        panel.add(taintConfig, position(rowIndex, 0, 1));

        JTextField taintNeedle =new JTextField(Constants.TAINT_STRING_DEFAULT);
        taintNeedle.setEditable(false);
        taintNeedle.setBorder(null);
        taintNeedle.setForeground(Color.MAGENTA);
        taintNeedle.setBackground(Color.WHITE);
        panel.add(taintNeedle, position(rowIndex, 2, 2));

        nextRow();
        JLabel needleTextFieldLabel = new JLabel("Enter a needle");
        panel.add(needleTextFieldLabel, position(rowIndex, 0, 1));

        JTextField needleTextField = new JTextField("", 20);
        needleTextField.setName("Taint Needle");
        needleTextField.setToolTipText("Taint Needle");
        needleTextField.setText(Constants.TAINT_STRING_DEFAULT);
        panel.add(needleTextField, position(rowIndex, 1, 2));

        nextRow();

        Consumer<String> consumer = (textToReplace) -> {
            final String taintString = StringUtils.isNotBlank(textToReplace) ? textToReplace : StringUtils.EMPTY;
            updatePropertyChangeListeners(Property.TAINT_NEEDLE.value(), StringUtils.EMPTY, taintString);
            taintNeedle.setText(taintString);
            needleTextField.setText(StringUtils.EMPTY);
        };

        JButton button = new JButton("Save");
        button.addActionListener(event -> consumer.accept(needleTextField.getText()));
        panel.add(button, position(rowIndex, 0, 1));

        button = new JButton("Default");
        button.addActionListener(event -> consumer.accept(Constants.TAINT_STRING_DEFAULT));
        panel.add(button, position(rowIndex, 1, 1));

        button = new JButton("Clear");
        button.addActionListener(event -> consumer.accept(StringUtils.EMPTY));
        panel.add(button, position(rowIndex, 2, 1));

        nextRow();
    }

    private void operationsModeUi() {
        JLabel switchMode = new JLabel("Check to enable taint value analysis.");
        panel.add(switchMode, position(rowIndex, 0, 3));

        nextRow();

        final JCheckBox opsModeCheckbox = new JCheckBox("Operations Mode", false);
        final JLabel opsModeStatus = new JLabel(Constants.LOGGING_MODE);
        opsModeStatus.setForeground(Color.BLUE);

        panel.add(opsModeStatus, position(rowIndex, 2, 1));

        opsModeCheckbox.addItemListener(event -> {
            final boolean updateValue = (event.getStateChange() == ItemEvent.SELECTED);
            updatePropertyChangeListeners(Property.OPERATIONS_MODE.value(), !updateValue, updateValue );

            final String labelUpdateValue = StringUtils.equals(opsModeStatus.getText(), Constants.LOGGING_MODE) ? Constants.TAINT_MODE : Constants.LOGGING_MODE;
            opsModeStatus.setText(labelUpdateValue);
        });
        panel.add(opsModeCheckbox, position(rowIndex, 0, 1));
    }

    private void enablePluginUI() {
        JLabel enableDisableAll = new JLabel("Enable/Disable DomSink Interceptor completely");
        panel.add(enableDisableAll, position(rowIndex, 0, 3));

        nextRow();
        final JCheckBox triggerCheckbox = new JCheckBox("Enable/Disable", false);
        triggerCheckbox.addItemListener(event -> {
            final boolean updateValue = (event.getStateChange() == ItemEvent.SELECTED);
            updatePropertyChangeListeners(Property.ENABLED.value(), !updateValue, updateValue);
        });

        panel.add(triggerCheckbox, position(rowIndex, 0, 3));
    }

    private void nextRow() {
        this.rowIndex++;
    }

    private GridBagConstraints position(final int row, final int col, final int width) {
        this.constraints.fill = GridBagConstraints.BOTH;
        this.constraints.weightx = 0.35;
        this.constraints.gridx = col;
        this.constraints.gridy = row;
        this.constraints.gridwidth = width;

        return this.constraints;
    }

    public void updatePropertyChangeListeners(final String propertyName, final Object oldValue, final Object newValue) {
        PropertyChangeEvent changeEvent = new PropertyChangeEvent(this, propertyName, oldValue, newValue);
        for(PropertyChangeListener listener : propertyChangeListeners){
            if(this.callbacks != null) {
                this.callbacks.printOutput(String.format("Property: [%s], Old: [%s], New: [%s]", propertyName, oldValue, newValue));
            }
            listener.propertyChange(changeEvent);
        }
    }

    @Override
    public void register(PropertyChangeListener listener) {
        this.propertyChangeListeners.add(listener);
    }
}