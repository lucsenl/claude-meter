package dev.lucsenl.claudemeter;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Pure-Java Claude subscription OAuth protocol helpers. */
public final class ClaudeOAuthProtocol {
    public static final String CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
    public static final String AUTHORIZE_URL = "https://claude.com/cai/oauth/authorize";
    public static final String TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
    public static final String REDIRECT_URI = "https://platform.claude.com/oauth/code/callback";
    public static final String SCOPES = "user:profile user:inference";
    public static final String OAUTH_BETA = "oauth-2025-04-20";
    public static final String USAGE_URL = "https://api.anthropic.com/api/oauth/usage";
    public static final String PROFILE_URL = "https://api.anthropic.com/api/oauth/profile";

    private static final SecureRandom RANDOM = new SecureRandom();

    private ClaudeOAuthProtocol() {}

    public static LoginRequest beginLogin() throws Exception {
        String verifier = randomUrlSafe(32);
        String state = randomUrlSafe(24);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256")
                        .digest(verifier.getBytes(StandardCharsets.US_ASCII)));

        String url = AUTHORIZE_URL
                + "?code=true"
                + "&client_id=" + encode(CLIENT_ID)
                + "&response_type=code"
                + "&redirect_uri=" + encode(REDIRECT_URI)
                + "&scope=" + encode(SCOPES)
                + "&code_challenge=" + encode(challenge)
                + "&code_challenge_method=S256"
                + "&state=" + encode(state);
        return new LoginRequest(url, verifier, state);
    }

    public static AuthorizationResult parseAuthorizationResult(String input) {
        String raw = input == null ? "" : input.trim();
        if (raw.isEmpty()) return new AuthorizationResult("", "");

        try {
            if (raw.contains("://")) {
                URI uri = URI.create(raw);
                return new AuthorizationResult(
                        queryValue(uri.getRawQuery(), "code"),
                        queryValue(uri.getRawQuery(), "state"));
            }
        } catch (Exception ignored) {}

        if (raw.contains("#")) {
            String[] parts = raw.split("#", 2);
            return new AuthorizationResult(parts[0].trim(),
                    parts.length > 1 ? parts[1].trim() : "");
        }
        if (raw.contains("code=")) {
            return new AuthorizationResult(
                    queryValue(raw, "code"), queryValue(raw, "state"));
        }
        return new AuthorizationResult(raw, "");
    }

    /** True if another request already replaced the access token rejected by a 401. */
    public static boolean wasAccessTokenReplaced(String rejected, String current) {
        return rejected != null && !rejected.isEmpty()
                && current != null && !current.isEmpty()
                && !rejected.equals(current);
    }

    public static boolean stateMatches(String actual, String expected) {
        if (actual == null || actual.isEmpty()) return true;
        if (expected == null || expected.isEmpty()) return false;
        return MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    private static String queryValue(String query, String name) {
        if (query == null) return "";
        for (String pair : query.split("[&#]")) {
            int index = pair.indexOf('=');
            if (index <= 0 || !pair.substring(0, index).equals(name)) continue;
            try {
                return URLDecoder.decode(
                        pair.substring(index + 1), StandardCharsets.UTF_8.name());
            } catch (Exception ignored) {
                return pair.substring(index + 1);
            }
        }
        return "";
    }

    private static String randomUrlSafe(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String encode(String value) throws Exception {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
    }

    public static final class LoginRequest {
        public final String url;
        public final String verifier;
        public final String state;

        LoginRequest(String url, String verifier, String state) {
            this.url = url;
            this.verifier = verifier;
            this.state = state;
        }
    }

    public static final class AuthorizationResult {
        public final String code;
        public final String state;

        AuthorizationResult(String code, String state) {
            this.code = code == null ? "" : code.trim();
            this.state = state == null ? "" : state.trim();
        }
    }
}
