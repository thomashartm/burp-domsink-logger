package burp;

import org.apache.commons.lang3.StringUtils;

public enum Property {

    ENABLED("enabled.all"),
    OPERATIONS_MODE("ops.mode"),
    TAINT_NEEDLE("taint.needle");

    String value;

    Property(final String value) {
        this.value  = value;
    }

    public String value(){
        return this.value;
    }

    public boolean same(final String value){
        return StringUtils.equals(this.value, value);
    }
}
