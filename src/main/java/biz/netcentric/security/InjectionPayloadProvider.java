package biz.netcentric.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class InjectionPayloadProvider {

    public static final String TRUSTED_TYPES_PAYLOAD = "trusted-types-payload.js";

    private static final String META_CSP_DEFAULT = "<meta http-equiv=content-security-policy content=\"trusted-types default\">\n";

    private static final String SCRIPT = "<script src=\"https://w3c.github.io/webappsec-trusted-types/dist/es5/trustedtypes.build.js\" data-csp=\"trusted-types default;\"></script>\n";

    private static final String INJECTED_SCRIPTS = SCRIPT + "<script>%s</script>\n";

    public String retrieveTrustedTypesCSPMetaTag() throws IOException {
        return META_CSP_DEFAULT;
    }

    public String retrieveTrustedTypesPayload() throws IOException {
        String payload = readResourceInputStream(String.format("/%s", TRUSTED_TYPES_PAYLOAD));
        return String.format(INJECTED_SCRIPTS,payload);
    }

    private String readResourceInputStream(final String location) throws IOException {
        InputStream inputStream = null;
        try {
            inputStream = this.getClass().getResourceAsStream(location);

            final StringBuilder resultStringBuilder = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = br.readLine()) != null) {
                    resultStringBuilder.append(line).append("\n");
                }
            }
            return resultStringBuilder.toString();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
