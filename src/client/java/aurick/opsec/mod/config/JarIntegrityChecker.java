package aurick.opsec.mod.config;

import aurick.opsec.mod.Opsec;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.fabricmc.loader.api.FabricLoader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * Checks the installed JAR against assets published in this fork's GitHub release.
 * A mismatch is a warning for investigation, not proof of malware.
 */
public final class JarIntegrityChecker {
    private static final String RELEASES_BASE_URL =
            "https://api.github.com/repos/jryoung201-code/OpSec-/releases/tags/V";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private static volatile boolean tamperDetected = false;
    private static volatile boolean checkComplete = false;
    private static volatile boolean shownThisSession = false;
    private static volatile String expectedDigest = null;
    private static volatile String actualDigest = null;

    private JarIntegrityChecker() {}

    public static void checkIntegrity() {
        CompletableFuture.runAsync(() -> {
            try {
                Path jarPath = FabricLoader.getInstance()
                        .getModContainer(Opsec.MOD_ID)
                        .flatMap(mod -> mod.getOrigin().getPaths().stream().findFirst())
                        .orElse(null);

                if (jarPath == null || !Files.isRegularFile(jarPath)
                        || !jarPath.toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
                    Opsec.LOGGER.debug("[OpSec] Not running from a JAR; skipping integrity check");
                    return;
                }

                try (var input = Files.newInputStream(jarPath)) {
                    MessageDigest localDigest = MessageDigest.getInstance("SHA-256");
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        localDigest.update(buffer, 0, read);
                    }
                    actualDigest = bytesToHex(localDigest.digest());
                }

                String currentVersion = Opsec.getVersion();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(RELEASES_BASE_URL + currentVersion))
                        .header("User-Agent", "OpSec-Fork/" + currentVersion)
                        .header("Accept", "application/vnd.github+json")
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build();

                HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 404) {
                    Opsec.LOGGER.debug("[OpSec] No matching fork release for version {}; skipping integrity check", currentVersion);
                    return;
                }
                if (response.statusCode() != 200) {
                    Opsec.LOGGER.debug("[OpSec] Fork release API returned {}; skipping integrity check", response.statusCode());
                    return;
                }

                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                if (!json.has("assets") || !json.get("assets").isJsonArray()) return;

                String mcVersion = FabricLoader.getInstance()
                        .getModContainer("minecraft")
                        .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
                        .orElse(null);
                if (mcVersion == null) return;

                JsonObject matchingAsset = findMatchingAsset(json.getAsJsonArray("assets"), mcVersion);
                if (matchingAsset == null || !matchingAsset.has("digest")) {
                    Opsec.LOGGER.debug("[OpSec] No matching JAR digest in fork release; skipping integrity check");
                    return;
                }

                String digestField = matchingAsset.get("digest").getAsString();
                if (!digestField.startsWith("sha256:")) return;

                expectedDigest = digestField.substring("sha256:".length()).toLowerCase(java.util.Locale.ROOT);
                tamperDetected = !MessageDigest.isEqual(
                        expectedDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        actualDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                if (tamperDetected) {
                    Opsec.LOGGER.warn("[OpSec] JAR integrity check mismatch. Expected: {}, Actual: {}. A mismatch can result from a modified build and is not by itself proof of malware.",
                            expectedDigest, actualDigest);
                } else {
                    Opsec.LOGGER.info("[OpSec] Installed JAR matches the fork's published release digest");
                }
            } catch (Exception e) {
                Opsec.LOGGER.debug("[OpSec] Integrity check unavailable: {}", e.toString());
            } finally {
                checkComplete = true;
            }
        });
    }

    public static boolean isCheckComplete() {
        return checkComplete;
    }

    public static boolean isTamperDetected() {
        return checkComplete && tamperDetected && !shownThisSession
                && !OpsecConfig.getInstance().getSettings().isTamperWarningDismissed();
    }

    public static void markShown() {
        shownThisSession = true;
    }

    public static void resetShown() {
        shownThisSession = false;
    }

    public static String getExpectedDigest() {
        return expectedDigest;
    }

    public static String getActualDigest() {
        return actualDigest;
    }

    private static JsonObject findMatchingAsset(JsonArray assets, String mcVersion) {
        for (JsonElement element : assets) {
            if (!element.isJsonObject()) continue;
            JsonObject asset = element.getAsJsonObject();
            String name = asset.has("name") ? asset.get("name").getAsString() : "";
            if (!name.startsWith("opsec-") || !name.endsWith(".jar")) continue;

            int rangeEnd = name.indexOf("+v");
            if (rangeEnd <= "opsec-".length()) continue;
            String range = name.substring("opsec-".length(), rangeEnd);
            int dash = range.indexOf('-');
            if (dash < 0) {
                if (range.equals(mcVersion)) return asset;
            } else {
                String min = range.substring(0, dash);
                String max = range.substring(dash + 1);
                if (compareVersions(mcVersion, min) >= 0 && compareVersions(mcVersion, max) <= 0) return asset;
            }
        }
        return null;
    }

    private static int compareVersions(String a, String b) {
        String[] aParts = a.split("\\.");
        String[] bParts = b.split("\\.");
        int len = Math.max(aParts.length, bParts.length);
        for (int i = 0; i < len; i++) {
            int aNum = i < aParts.length ? parseVersionPart(aParts[i]) : 0;
            int bNum = i < bParts.length ? parseVersionPart(bParts[i]) : 0;
            if (aNum != bNum) return Integer.compare(aNum, bNum);
        }
        return 0;
    }

    private static int parseVersionPart(String part) {
        String digits = part.replaceAll("[^0-9].*$", "");
        return digits.isEmpty() ? 0 : Integer.parseInt(digits);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
