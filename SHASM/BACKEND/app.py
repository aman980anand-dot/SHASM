"""SHASM local Flask API."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading, uuid
from flask import Flask, jsonify, request
from flask_cors import CORS
from scanner import perform_scan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
CORS(app, resources={r"/api/*": {"origins": [
    "http://127.0.0.1:5500", "http://localhost:5500",
    "http://127.0.0.1:5501", "http://localhost:5501"]}})
pool = ThreadPoolExecutor(max_workers=3)
scans, lock = {}, threading.Lock()
MAX_SCANS = 100

def now():
    return datetime.now(timezone.utc).isoformat()

def prune():
    finished = [k for k, v in scans.items() if v["status"] in ("completed", "failed")]
    while len(scans) >= MAX_SCANS and finished:
        scans.pop(finished.pop(0), None)

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "SHASM", "scanner": "safe_passive", "time": now()})

@app.post("/api/scan")
def start_scan():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object."}), 400
    target = data.get("target")
    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "A non-empty target URL is required."}), 400
    target = target.strip()
    if len(target) > 2048:
        return jsonify({"error": "Target URL is too long."}), 400

    sid, stamp = str(uuid.uuid4()), now()
    with lock:
        prune()
        if len(scans) >= MAX_SCANS:
            return jsonify({"error": "Scanner busy; wait for active scans to finish."}), 503
        scans[sid] = {"id": sid, "status": "queued", "created_at": stamp,
                      "updated_at": stamp, "target": target, "result": None, "error": None}

    def job():
        with lock:
            if sid not in scans:
                return
            scans[sid]["status"], scans[sid]["updated_at"] = "running", now()
        try:
            result = perform_scan(target)
            if not isinstance(result, dict):
                raise TypeError("Scanner returned an unexpected result.")
            error = result.get("error")
            with lock:
                if sid in scans:
                    scans[sid].update(status="failed" if error else "completed",
                                      updated_at=now(), result=result, error=error)
        except Exception as exc:
            app.logger.exception("Scan %s failed", sid)
            message = f"{type(exc).__name__}: {exc}"
            with lock:
                if sid in scans:
                    scans[sid].update(status="failed", updated_at=now(), error=message,
                                      result={"target": target, "scanned_at": now(),
                                              "error": message, "findings": []})
    try:
        pool.submit(job)
    except RuntimeError:
        with lock:
            scans.pop(sid, None)
        return jsonify({"error": "Scanner is shutting down; try again."}), 503
    return jsonify({"id": sid, "status": "queued"}), 202

@app.get("/api/scan/<sid>")
def get_status(sid):
    with lock:
        scan = scans.get(sid)
        if scan is None:
            return jsonify({"status": "not_found", "error": "Scan ID not found."}), 404
        return jsonify({k: scan[k] for k in
                        ("id", "status", "created_at", "updated_at", "error")})

@app.get("/api/results/<sid>")
def get_results(sid):
    with lock:
        scan = scans.get(sid)
        if scan is None:
            return jsonify({"error": "Scan ID not found.", "findings": []}), 404
        result = scan.get("result") or {}
        return jsonify({"id": sid, "status": scan["status"],
                        "findings": result.get("findings", []),
                        "result": result, "error": scan.get("error")})

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request body is too large."}), 413

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
