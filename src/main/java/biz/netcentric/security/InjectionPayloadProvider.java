package biz.netcentric.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class InjectionPayloadProvider {

    public String retrieveTrustedTypesCSPMetaTag() throws IOException {
        return Constants.META_CSP_DEFAULT;
    }

    public String retrieveTrustedTypesPayload() throws IOException {
        String payload = readResourceInputStream(String.format("/%s", Constants.TRUSTED_TYPES_PAYLOAD));
        return String.format(Constants.INJECTED_SCRIPTS, payload);
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
