package dev.lucsenl.claudemeter;

public final class ParserSelfTest {
    public static void main(String[] args) throws Exception {
        testUsageAndProfile();
        testNullWindows();
        testSnapshotRoundTrip();
        testOAuthProtocol();
        System.out.println("Claude Meter subscription parser tests passed.");
    }

    private static void testUsageAndProfile() throws Exception {
        String usage = "{"
                + "\"five_hour\":{\"utilization\":15.0,"
                + "\"resets_at\":\"2026-11-04T18:00:00+00:00\"},"
                + "\"seven_day\":{\"utilization\":36.0,"
                + "\"resets_at\":\"2026-11-09T18:00:00+00:00\"},"
                + "\"extra_usage\":{\"is_enabled\":true},"
                + "\"member_dashboard_available\":true,"
                + "\"limits\":["
                + "{\"kind\":\"session\",\"percent\":15,\"scope\":null},"
                + "{\"kind\":\"weekly_scoped\",\"percent\":71,"
                + "\"resets_at\":\"2026-11-09T18:00:00+00:00\","
                + "\"scope\":{\"model\":{\"display_name\":\"Fable\"}},"
                + "\"is_active\":true}"
                + "]}";
        String profile = "{"
                + "\"account\":{\"email\":\"user@example.com\","
                + "\"display_name\":\"Example User\"},"
                + "\"organization\":{\"organization_type\":\"claude_max\","
                + "\"rate_limit_tier\":\"default_claude_max_20x\","
                + "\"subscription_status\":\"active\"}}";

        UsageSnapshot value = UsageParser.parse(usage, profile, 123456L);
        assert "Example User".equals(value.displayName);
        assert "user@example.com".equals(value.email);
        assert "Max 20×".equals(value.plan) : value.plan;
        assert value.fiveHourUtilization == 15d;
        assert value.sevenDayUtilization == 36d;
        assert value.extraUsageEnabled;
        assert value.memberDashboardAvailable;
        assert value.scopedLimits.size() == 1 : value.scopedLimits.size();
        assert "Fable · Weekly".equals(value.scopedLimits.get(0).label);
        assert value.scopedLimits.get(0).utilization == 71d;
        assert value.scopedLimits.get(0).active;
    }

    private static void testNullWindows() throws Exception {
        UsageSnapshot value = UsageParser.parse(
                "{\"five_hour\":null,\"seven_day\":null}",
                "{\"account\":{},\"organization\":{}}",
                1L);
        assert !value.hasFiveHour();
        assert !value.hasSevenDay();
        assert "Claude".equals(value.plan);
    }

    private static void testOAuthProtocol() throws Exception {
        ClaudeOAuthProtocol.LoginRequest request = ClaudeOAuthProtocol.beginLogin();
        assert request.url.startsWith("https://claude.com/cai/oauth/authorize?");
        assert request.url.contains("client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e");
        assert request.url.contains("code_challenge_method=S256");
        assert request.url.contains("scope=user%3Aprofile+user%3Ainference");
        assert request.verifier.length() >= 43;
        assert !request.state.isEmpty();

        ClaudeOAuthProtocol.AuthorizationResult pasted =
                ClaudeOAuthProtocol.parseAuthorizationResult("abc#state123");
        assert "abc".equals(pasted.code);
        assert "state123".equals(pasted.state);

        ClaudeOAuthProtocol.AuthorizationResult callback =
                ClaudeOAuthProtocol.parseAuthorizationResult(
                        "https://platform.claude.com/oauth/code/callback"
                                + "?code=hello%20world&state=s1");
        assert "hello world".equals(callback.code);
        assert "s1".equals(callback.state);
        assert ClaudeOAuthProtocol.stateMatches("same", "same");
        assert !ClaudeOAuthProtocol.stateMatches("one", "two");
        assert ClaudeOAuthProtocol.wasAccessTokenReplaced("old", "new");
        assert !ClaudeOAuthProtocol.wasAccessTokenReplaced("same", "same");
        assert !ClaudeOAuthProtocol.wasAccessTokenReplaced("", "new");
        assert !ClaudeOAuthProtocol.wasAccessTokenReplaced("old", null);
    }

    private static void testSnapshotRoundTrip() throws Exception {
        UsageSnapshot original = UsageParser.parse(
                "{\"five_hour\":{\"utilization\":22.5},"
                        + "\"seven_day\":{\"utilization\":48.0}}",
                "{\"account\":{\"email\":\"a@b.test\"},"
                        + "\"organization\":{\"organization_type\":\"claude_pro\"}}",
                999L);
        UsageSnapshot restored = UsageSnapshot.fromJson(original.toJson());
        assert restored != null;
        assert "Pro".equals(restored.plan);
        assert restored.fiveHourUtilization == 22.5d;
        assert restored.sevenDayUtilization == 48d;
        assert restored.fetchedAtMillis == 999L;
    }
}
