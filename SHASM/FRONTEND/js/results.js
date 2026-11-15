document.addEventListener("DOMContentLoaded", () => {
  const resultsDiv = document.getElementById("results");
  const scanId = sessionStorage.getItem("currentScanId");
  if (!resultsDiv) {
    console.error("SHASM: results page requires #results.");
    return;
  }
  if (!scanId) {
    resultsDiv.textContent = "No scan ID found. Start a new scan.";
    return;
  }

  function addText(parent, tag, label, value) {
    const el = document.createElement(tag);
    if (label) {
      const strong = document.createElement("strong");
      strong.textContent = label;
      el.append(strong, document.createTextNode(" "));
    }
    el.appendChild(document.createTextNode(
      value === undefined || value === null || value === "" ? "Not provided" : String(value)
    ));
    parent.appendChild(el);
  }

  function render(data) {
    resultsDiv.replaceChildren();
    const report = data.result || {};
    const findings = Array.isArray(data.findings) ? data.findings : [];
    if (data.status !== "completed") {
      const p = document.createElement("p");
      p.className = "no-results";
      p.textContent = data.error || `Report not ready (status: ${data.status || "unknown"}).`;
      resultsDiv.appendChild(p);
      return;
    }

    const summary = document.createElement("section");
    summary.className = "result-item info";
    const heading = document.createElement("h2");
    heading.textContent = "Scan Summary";
    summary.appendChild(heading);
    addText(summary, "p", "Target:", report.target);
    addText(summary, "p", "Final URL:", report.final_url);
    addText(summary, "p", "HTTP status:", report.status_code);
    addText(summary, "p", "Scan type:", report.scan_type);
    addText(summary, "p", "Scanned at:", report.scanned_at);
    addText(summary, "p", "Summary:", report.summary);
    resultsDiv.appendChild(summary);

    const title = document.createElement("h2");
    title.textContent = `Findings (${findings.length})`;
    resultsDiv.appendChild(title);
    if (!findings.length) {
      const p = document.createElement("p");
      p.className = "no-results";
      p.textContent =
        "No issues were detected by the passive checks performed. This does not prove the website is vulnerability-free.";
      resultsDiv.appendChild(p);
    }

    findings.forEach(f => {
      const card = document.createElement("article");
      const level = String(f.severity || "Info").toLowerCase();
      card.className = `result-item ${
        level === "high" || level === "critical" ? "vulnerability" :
        level === "medium" ? "warning" : "info"
      }`;
      const h = document.createElement("h2");
      h.textContent = f.title || "Untitled observation";
      card.appendChild(h);
      addText(card, "p", "Severity:", f.severity);
      addText(card, "p", "Confidence:", f.confidence);
      addText(card, "p", "Category:", f.category);
      addText(card, "p", "Evidence:", f.evidence);
      addText(card, "p", "Remediation:", f.remediation);
      resultsDiv.appendChild(card);
    });

    if (Array.isArray(report.limitations) && report.limitations.length) {
      const section = document.createElement("section");
      section.className = "result-item info";
      const h = document.createElement("h2");
      h.textContent = "Scan Limitations";
      section.appendChild(h);
      const ul = document.createElement("ul");
      report.limitations.forEach(item => {
        const li = document.createElement("li");
        li.textContent = String(item);
        ul.appendChild(li);
      });
      section.appendChild(ul);
      resultsDiv.appendChild(section);
    }
  }

  async function load() {
    resultsDiv.textContent = "Fetching report from server...";
    try {
      render(await getResults(scanId));
    } catch (error) {
      resultsDiv.textContent = `Failed to load results: ${error.message}`;
    }
  }
  load();
});
