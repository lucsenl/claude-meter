package dev.lucsenl.claudemeter;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Browser-based Claude subscription sign-in using OAuth PKCE. */
public final class OnboardingActivity extends AppCompatActivity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private LinearLayout content;
    private boolean dark;
    private EditText codeInput;
    private Button completeButton;
    private String verifier = "";
    private String expectedState = "";

    @Override protected void onCreate(Bundle state) {
        Ui.applySelectedTheme(this);
        super.onCreate(state);
        dark = Ui.isDark(this);
        content = Ui.installPage(this, "Sign in to Claude", true).content;
        render();
    }

    @Override protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    @Override public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    private void render() {
        content.removeAllViews();

        LinearLayout card = Ui.card(this, dark);
        TextView title = Ui.text(this, "Sign in with Claude", 26, Ui.mainText(dark));
        title.setTypeface(Ui.mediumTypeface(this));
        card.addView(title);

        TextView body = Ui.text(this,
                "Claude Meter opens Claude in your browser. Sign in with the account whose "
                        + "subscription you want to monitor. Sign-in happens entirely through Claude.",
                15, Ui.secondaryText(dark));
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, -2);
        bp.setMargins(0, Ui.dp(this, 10), 0, Ui.dp(this, 18));
        card.addView(body, bp);

        Button signIn = Ui.nativePrimaryButton(this, "Open Claude sign-in");
        signIn.setOnClickListener(v -> beginLogin());
        card.addView(signIn, new LinearLayout.LayoutParams(-1, Ui.dp(this, 60)));

        TextView step = Ui.text(this,
                "After Claude finishes signing in, the browser shows an authorization code. "
                        + "Copy that code (or the full callback value) and paste it below.",
                13, Ui.secondaryText(dark));
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(-1, -2);
        sp.setMargins(0, Ui.dp(this, 16), 0, Ui.dp(this, 8));
        card.addView(step, sp);

        codeInput = new EditText(this);
        codeInput.setHint("Authorization code");
        codeInput.setSingleLine(false);
        codeInput.setMinLines(2);
        codeInput.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        card.addView(codeInput, new LinearLayout.LayoutParams(-1, -2));

        completeButton = Ui.button(this, "Complete sign-in", false, dark);
        completeButton.setEnabled(!verifier.isEmpty());
        completeButton.setOnClickListener(v -> completeLogin());
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(-1, Ui.dp(this, 56));
        cp.setMargins(0, Ui.dp(this, 10), 0, 0);
        card.addView(completeButton, cp);
        content.addView(card);

        Ui.addSpacer(content, 16);
        LinearLayout note = Ui.card(this, dark);
        TextView noteTitle = Ui.text(this, "What Claude Meter reads", 18, Ui.mainText(dark));
        noteTitle.setTypeface(Ui.mediumTypeface(this));
        note.addView(noteTitle);
        TextView detail = Ui.text(this,
                "Your Claude profile and subscription usage windows: 5-hour session, 7-day "
                        + "allowance, reset times, and model-scoped weekly limits when Claude "
                        + "returns them. Access and refresh tokens stay encrypted on this device.",
                14, Ui.secondaryText(dark));
        LinearLayout.LayoutParams dp = new LinearLayout.LayoutParams(-1, -2);
        dp.setMargins(0, Ui.dp(this, 8), 0, 0);
        note.addView(detail, dp);
        content.addView(note);

        if (AppPreferences.isOnboardingComplete(this)) {
            Button cancel = Ui.button(this, "Cancel", false, dark);
            cancel.setOnClickListener(v -> finish());
            LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, Ui.dp(this, 56));
            p.setMargins(0, Ui.dp(this, 12), 0, 0);
            content.addView(cancel, p);
        }
    }

    private void beginLogin() {
        try {
            ClaudeOAuthProtocol.LoginRequest request = ClaudeOAuthProtocol.beginLogin();
            verifier = request.verifier;
            expectedState = request.state;
            completeButton.setEnabled(true);
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(request.url)));
        } catch (Exception exception) {
            Toast.makeText(this, UsageApi.safeMessage(exception), Toast.LENGTH_LONG).show();
        }
    }

    private void completeLogin() {
        String code = codeInput.getText() == null ? "" : codeInput.getText().toString().trim();
        if (verifier.isEmpty() || expectedState.isEmpty()) {
            Toast.makeText(this, "Start Claude sign-in first.", Toast.LENGTH_LONG).show();
            return;
        }
        if (code.isEmpty()) {
            codeInput.setError("Paste the authorization code");
            return;
        }

        completeButton.setEnabled(false);
        completeButton.setText("Signing in…");
        executor.execute(() -> {
            String error = "";
            boolean signedIn = false;
            try {
                ClaudeOAuth.exchangeCode(getApplicationContext(), code, verifier, expectedState);
                // The one-time code has now been exchanged; complete login before
                // contacting usage/profile endpoints so a failure cannot cause code reuse.
                AppPreferences.completeOnboarding(getApplicationContext());
                RefreshScheduler.schedulePeriodic(getApplicationContext());
                signedIn = true;
                try {
                    UsageApi.refreshAndCacheLocked(getApplicationContext());
                } catch (Exception ignored) {
                    // UsageApi stores the failure for the dashboard; sign-in still succeeded.
                }
            } catch (Exception exception) {
                error = UsageApi.safeMessage(exception);
            }
            String finalError = error;
            boolean finalSignedIn = signedIn;
            runOnUiThread(() -> {
                completeButton.setEnabled(true);
                completeButton.setText("Complete sign-in");
                if (!finalSignedIn) {
                    Toast.makeText(this, finalError.isEmpty()
                            ? "Claude sign-in failed." : finalError, Toast.LENGTH_LONG).show();
                    return;
                }
                startActivity(new Intent(this, MainActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP
                                | Intent.FLAG_ACTIVITY_SINGLE_TOP));
                finish();
            });
        });
    }
}
