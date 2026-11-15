document.addEventListener("DOMContentLoaded", () => {
  const statusDiv = document.getElementById("status");
  const bar = document.getElementById("bar");
  const scanId = sessionStorage.getItem("currentScanId");

  if (!statusDiv || !bar) {
    console.error("SHASM: progress page requires #status and #bar.");
    return;
  }
  if (!scanId) {
    statusDiv.textContent = "No active scan. Return to the scan page and try again.";
    return;
  }

  let elapsed = 0, stopped = false, timer = null;
  function setProgress(value) {
    bar.style.width = `${value}%`;
    bar.setAttribute("aria-valuenow", String(value));
  }

  async function poll() {
    if (stopped) return;
    try {
      const data = await getScan(scanId);
      if (data.status === "queued") {
        statusDiv.textContent = "Scan queued. Waiting for an available scanner...";
        setProgress(5);
      } else if (data.status === "running") {
        elapsed += 2;
        statusDiv.textContent =
          `Scan running (${elapsed}s elapsed). Indicator shows activity, not measured completion.`;
        setProgress(Math.min(85, 15 + Math.floor(elapsed / 2) * 3));
      } else if (data.status === "completed") {
        stopped = true;
        setProgress(100);
        statusDiv.textContent = "Scan completed. Opening report...";
        window.setTimeout(() => { window.location.href = "results.html"; }, 500);
        return;
      } else if (data.status === "failed") {
        stopped = true;
        statusDiv.textContent = `Scan failed: ${data.error || "Unknown scanner error."}`;
        bar.style.backgroundColor = "#c0392b";
        return;
      } else {
        stopped = true;
        statusDiv.textContent = data.error || `Unexpected scan status: ${data.status}`;
        return;
      }
    } catch (error) {
      stopped = true;
      statusDiv.textContent = `Connection error: ${error.message}. Check that backend is running.`;
      bar.style.backgroundColor = "#c0392b";
      return;
    }
    if (!stopped) timer = window.setTimeout(poll, 2000);
  }

  poll();
  window.addEventListener("beforeunload", () => {
    stopped = true;
    if (timer) window.clearTimeout(timer);
  });
});
