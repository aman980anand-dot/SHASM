
document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scanForm");
    const targetInput = document.getElementById("target");
    const safeModeSelect = document.getElementById("safeMode");
    const maxDepthInput = document.getElementById("maxDepth");
    const messageDiv = document.getElementById("message");

    if (!scanForm || !targetInput || !messageDiv) {
        console.error("SHASM: Required form elements not found.");
        return;
    }

    scanForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        displayMessage("", "");

        const targetURL = targetInput.value.trim();

        if (!targetURL) {
            displayMessage("Please enter a website URL.", "error");
            targetInput.focus();
            return;
        }

        let parsedURL;

        try {
            parsedURL = new URL(
                targetURL.includes("://")
                    ? targetURL
                    : `https://${targetURL}`
            );
        } catch {
            displayMessage("Please enter a valid URL.", "error");
            return;
        }

        if (!["http:", "https:"].includes(parsedURL.protocol)) {
            displayMessage(
                "Only HTTP and HTTPS URLs are supported.",
                "error"
            );
            return;
        }

        const safeMode = safeModeSelect
            ? safeModeSelect.value === "true"
            : true;

        const parsedDepth = maxDepthInput
            ? Number.parseInt(maxDepthInput.value, 10)
            : 1;

        const maxDepth = Number.isFinite(parsedDepth)
            ? Math.min(Math.max(parsedDepth, 1), 5)
            : 1;

        displayMessage("Submitting scan request...", "info");

        try {
            if (typeof createScan !== "function") {
                throw new Error(
                    "createScan() not found. Check api.js loading order."
                );
            }

            const data = await createScan({
                target: parsedURL.href,
                safeMode: safeMode,
                maxDepth: maxDepth
            });

            if (!data || data.error || !data.id) {
                throw new Error(
                    data?.error || "Backend did not return a scan ID."
                );
            }

            sessionStorage.setItem("currentScanId", data.id);
            sessionStorage.setItem(
                "currentScanTarget",
                parsedURL.href
            );
            sessionStorage.setItem(
                "currentScanSafeMode",
                String(safeMode)
            );
            sessionStorage.setItem(
                "currentScanMaxDepth",
                String(maxDepth)
            );
            sessionStorage.setItem(
                "scanStartTime",
                new Date().toISOString()
            );

            displayMessage(
                "Scan accepted. Opening progress page...",
                "success"
            );

            window.setTimeout(() => {
                window.location.href = "progress.html";
            }, 700);

        } catch (error) {
            console.error("SHASM scan error:", error);

            displayMessage(
                `Could not start scan: ${error.message}. ` +
                "Check whether the Python backend is running.",
                "error"
            );
        }
    });

    function displayMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = type
            ? `message-${type}`
            : "";
    }
});
