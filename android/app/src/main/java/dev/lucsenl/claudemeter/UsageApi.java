package dev.lucsenl.claudemeter;

import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;

/** Claude subscription profile and usage transport. */
public final class UsageApi {
    private UsageApi() {}

    public static UsageSnapshot refreshAndCacheLocked(Context context) throws Exception {
        Context app = context.getApplicationContext();
        long started = SystemClock.elapsedRealtime();
        try {
            ClaudeOAuthCredential credential = ClaudeOAuth.validCredential(app, false);
            Response usage = get(app, ClaudeOAuthProtocol.USAGE_URL, credential.accessToken);
            if (usage.status == 401) {
                credential = ClaudeOAuth.validCredential(app, true, credential.accessToken);
                usage = get(app, ClaudeOAuthProtocol.USAGE_URL, credential.accessToken);
            }
            requireSuccess(usage, "subscription usage");

            Response profile = get(app, ClaudeOAuthProtocol.PROFILE_URL, credential.accessToken);
            if (profile.status == 401) {
                credential = ClaudeOAuth.validCredential(app, true, credential.accessToken);
                profile = get(app, ClaudeOAuthProtocol.PROFILE_URL, credential.accessToken);
            }
            requireSuccess(profile, "profile");

            UsageSnapshot snapshot = UsageParser.parse(
                    usage.body, profile.body, System.currentTimeMillis());
            AppPreferences.saveSnapshot(app, snapshot);
            AppPreferences.setLastError(app, "");
            WidgetRenderer.updateAll(app);
            app.sendBroadcast(new Intent(AppConstants.ACTION_USAGE_UPDATED)
                    .setPackage(app.getPackageName()), AppConstants.INTERNAL_PERMISSION);

            DiagnosticLog.info(app, "refresh", "claude_subscription_usage_succeeded",
                    "duration_ms", SystemClock.elapsedRealtime() - started,
                    "five_hour", snapshot.fiveHourUtilization,
                    "seven_day", snapshot.sevenDayUtilization,
                    "plan", snapshot.plan);
            return snapshot;
        } catch (Exception exception) {
            AppPreferences.setLastError(app, safeMessage(exception));
            DiagnosticLog.error(app, "refresh", "claude_subscription_usage_failed", exception,
                    "duration_ms", SystemClock.elapsedRealtime() - started);
            throw exception;
        }
    }

    private static Response get(Context context, String url, String accessToken) throws Exception {
        HttpsURLConnection connection =
                (HttpsURLConnection) URI.create(url).toURL().openConnection();
        long started = SystemClock.elapsedRealtime();
        try {
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(25000);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + accessToken);
            connection.setRequestProperty("anthropic-beta", ClaudeOAuthProtocol.OAUTH_BETA);
            connection.setRequestProperty("User-Agent", AppConstants.userAgent());

            int status = connection.getResponseCode();
            String body = readBody(connection, status);
            DiagnosticLog.info(context, "network", "claude_oauth_request_finished",
                    "host", "api.anthropic.com",
                    "status", status,
                    "duration_ms", SystemClock.elapsedRealtime() - started);
            return new Response(status, body);
        } finally {
            connection.disconnect();
        }
    }

    private static void requireSuccess(Response response, String operation) throws Exception {
        if (response.status >= 200 && response.status < 300) return;
        if (response.status == 401) {
            throw new Exception("Claude sign-in expired. Sign in again.");
        }
        if (response.status == 403) {
            throw new Exception("Claude did not grant access to " + operation
                    + ". Sign in again to refresh permissions.");
        }
        if (response.status == 404) {
            throw new Exception("Claude's " + operation
                    + " endpoint is unavailable. Claude Meter may need an update.");
        }
        if (response.status == 429) {
            throw new Exception("Claude is rate-limiting usage checks. Try again later.");
        }
        throw new Exception("Claude " + operation + " request failed (HTTP "
                + response.status + ").");
    }

    private static String readBody(HttpsURLConnection connection, int status) throws Exception {
        InputStream input = status >= 200 && status < 400
                ? connection.getInputStream() : connection.getErrorStream();
        if (input == null) return "";
        try (InputStream stream = input;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = stream.read(buffer)) != -1) {
                output.write(buffer, 0, read);
                if (output.size() > 4 * 1024 * 1024) {
                    throw new Exception("Claude response exceeded the supported size.");
                }
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    static String safeMessage(Exception exception) {
        String message = exception == null ? "" : exception.getMessage();
        if (message == null || message.trim().isEmpty()) return "Claude request failed.";
        String value = message.replaceAll("[\\r\\n\\t]+", " ").trim();
        return value.length() > 240 ? value.substring(0, 240) : value;
    }

    private static final class Response {
        final int status;
        final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body == null ? "" : body;
        }
    }
}
