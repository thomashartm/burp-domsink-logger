package biz.netcentric.security;

import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class InjectionPayloadProviderTest {

    private InjectionPayloadProvider payloadProvider;

    @BeforeEach
    public void setup(){
        this.payloadProvider = new InjectionPayloadProvider();
    }

    @Test
    public void retrieveTrustedTypesPayload() throws IOException {
        String payload = this.payloadProvider.retrieveTrustedTypesPayload();
        Assert.assertTrue(payload.contains("trustedTypesPolyfill"));
        Assert.assertTrue(payload.contains("trustedTypesPolicyDefault"));
    }
}