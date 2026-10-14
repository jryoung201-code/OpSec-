package aurick.opsec.mod.config;

import aurick.opsec.mod.Opsec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * Checks for releases published by this OpSec fork.
 */
public final class UpdateChecker {
    private static final String RELEASES_URL =
            "https://api.github.com/repos/jryoung201-code/OpSec-/releases/latest";
    private static final String FALLBACK_RELEASE_URL =
            "https://github.com/jryoung201-code/OpSec-/releases/latest";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private static volatile String latestVersion = null;
    private static volatile String releaseUrl = null;
    private static volatile boolean updateAvailable = false;
    private static volatile boolean checkComplete = false;
    private static volatile boolean shownThisSession = false;

    private UpdateChecker() {}

    public static void checkForUpdate() {
        CompletableFuture.runAsync(() -> {
            try {
                String currentVersion = Opsec.getVersion();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(RELEASES_URL))
                        .header("User-Agent", "OpSec-Fork/" + currentVersion)
                        .header("Accept", "application/vnd.github+json")
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build();

                HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    Opsec.LOGGER.debug("[OpSec] Fork release API returned {}", response.statusCode());
                    return;
                }

                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                String tagName = json.has("tag_name") ? json.get("tag_name").getAsString() : null;
                String htmlUrl = json.has("html_url") ? json.get("html_url").getAsString() : null;
                if (tagName == null) return;

                String version = (tagName.startsWith("v") || tagName.startsWith("V"))
                        ? tagName.substring(1) : tagName;
                latestVersion = version;
                releaseUrl = htmlUrl != null ? htmlUrl : FALLBACK_RELEASE_URL;
                updateAvailable = !version.equals(currentVersion);
                if (updateAvailable) {
                    Opsec.LOGGER.info("[OpSec] Update available: {} -> {} ({})",
                            currentVersion, version, releaseUrl);
                } else {
                    Opsec.LOGGER.debug("[OpSec] Fork build is up to date ({})", currentVersion);
                }
            } catch (Exception e) {
                Opsec.LOGGER.debug("[OpSec] Fork update check failed: {}", e.toString());
            } finally {
                checkComplete = true;
            }
        });
    }

    public static boolean isUpdateAvailable() {
        return checkComplete && updateAvailable && !shownThisSession
                && !OpsecConfig.getInstance().getSettings().isVersionSkipped(latestVersion);
    }

    public static String getLatestVersion() {
        return latestVersion;
    }

    public static String getReleaseUrl() {
        return releaseUrl != null ? releaseUrl : FALLBACK_RELEASE_URL;
    }

    public static void markShown() {
        shownThisSession = true;
    }

    public static void resetShown() {
        shownThisSession = false;
    }

    public static String getCurrentVersion() {
        return Opsec.getVersion();
    }
}
