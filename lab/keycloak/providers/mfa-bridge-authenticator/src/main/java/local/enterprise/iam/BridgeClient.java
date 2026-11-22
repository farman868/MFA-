package local.enterprise.iam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.util.JsonSerialization;

/**
 * Minimal JSON-over-HTTP client for the mfa-otp-bridge service.
 * Keycloak never sees or stores the OTP value itself: the bridge generates it,
 * delivers it (SMTP / mock SMS gateway), stores only an HMAC and verifies it.
 */
final class BridgeClient {

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    private final String baseUrl;
    private final String apiKey;

    BridgeClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey == null ? "" : apiKey;
    }

    /** POSTs a JSON body; returns the parsed JSON response plus "_status" (HTTP status code). */
    @SuppressWarnings("unchecked")
    Map<String, Object> post(String path, Map<String, Object> body) throws Exception {
        String json = JsonSerialization.writeValueAsString(body);
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(8))
                .header("Content-Type", "application/json")
                .header("X-Bridge-Key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        Map<String, Object> out = new HashMap<>();
        String raw = response.body();
        if (raw != null && !raw.isBlank()) {
            Object parsed = JsonSerialization.readValue(raw, Map.class);
            if (parsed instanceof Map) {
                out.putAll((Map<String, Object>) parsed);
            }
        }
        out.put("_status", response.statusCode());
        return out;
    }

    static int status(Map<String, Object> response) {
        Object s = response.get("_status");
        return s instanceof Integer ? (Integer) s : 0;
    }

    static String str(Map<String, Object> response, String key) {
        Object v = response.get(key);
        return v == null ? null : String.valueOf(v);
    }
}
