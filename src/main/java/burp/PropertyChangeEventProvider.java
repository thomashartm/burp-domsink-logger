package burp;

import java.beans.PropertyChangeListener;

public interface PropertyChangeEventProvider {

    /**
     * Register a change event listening to property changes
     * @param listener
     */
    void register(PropertyChangeListener listener);
}
