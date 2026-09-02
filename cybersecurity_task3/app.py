import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from config import Config
from models import init_db, Scan, Vulnerability, db
from scanners import get_scanner_for_file
from utils import calculate_security_score, risk_level_from_score
from pdf_generator import generate_pdf_report

app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)
init_db(app)


def allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in app.config["ALLOWED_EXTENSIONS"]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    total_scans = Scan.query.count()
    total_vulns = db.session.query(db.func.sum(Scan.total_vulnerabilities)).scalar() or 0
    critical = db.session.query(db.func.sum(Scan.critical_count)).scalar() or 0
    high = db.session.query(db.func.sum(Scan.high_count)).scalar() or 0
    medium = db.session.query(db.func.sum(Scan.medium_count)).scalar() or 0
    low = db.session.query(db.func.sum(Scan.low_count)).scalar() or 0

    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        total_vulns=total_vulns,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        recent_scans=recent_scans,
    )


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file uploaded.", "error")
            return redirect(request.url)

        file = request.files["file"]
        if not file or not file.filename:
            flash("No file selected.", "error")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("File type not allowed.", "error")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        scan_id = str(uuid.uuid4())
        base_name, ext = os.path.splitext(filename)
        safe_filename = f"{scan_id}{ext}"

        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
        file.save(upload_path)

        with open(upload_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        scanner = get_scanner_for_file(filename, content)
        findings = scanner.scan()

        # Create Scan record
        scan = Scan(
            scan_name=f"Scan {scan_id[:8]}",
            file_name=filename,
            file_path=safe_filename,
            language=filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown",
        )

        for f in findings:
            vuln = Vulnerability(
                vuln_name=f.vuln_name,
                vuln_type=f.vuln_type,
                cwe_id=f.cwe_id,
                cwe_name=f.cwe_name,
                owasp_category=f.owasp_category,
                severity=f.severity,
                cvss_score=f.cvss_score,
                file_name=f.file_name,
                line_number=f.line_number,
                code_snippet=f.code_snippet,
                description=f.description,
                risk_explanation=f.risk_explanation,
                remediation=f.remediation,
                confidence=f.confidence,
            )
            scan.vulnerabilities.append(vuln)

        scan.total_vulnerabilities = len(findings)
        scan.critical_count = sum(1 for f in findings if f.severity == "Critical")
        scan.high_count = sum(1 for f in findings if f.severity == "High")
        scan.medium_count = sum(1 for f in findings if f.severity == "Medium")
        scan.low_count = sum(1 for f in findings if f.severity == "Low")

        score = calculate_security_score(findings)
        scan.security_score = score
        scan.risk_level = risk_level_from_score(score)

        db.session.add(scan)
        db.session.commit()

        # Generate PDF report
        pdf_filename = f"{scan_id}.pdf"
        pdf_path = os.path.join(app.config["REPORTS_FOLDER"], pdf_filename)
        generate_pdf_report(scan, pdf_path)

        flash("Scan completed successfully.", "success")
        return redirect(url_for("results", scan_id=scan.id))

    return render_template("scan.html")


@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = scan.vulnerabilities.order_by(Vulnerability.severity, Vulnerability.line_number).all()
    return render_template("results.html", scan=scan, vulns=vulns)


@app.route("/history")
def history():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("history.html", scans=scans)


@app.route("/delete_scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    # Optionally delete PDF/report files here if you track them
    db.session.delete(scan)
    db.session.commit()
    flash("Scan deleted.", "success")
    return redirect(url_for("history"))


@app.route("/download_report/<int:scan_id>")
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    # Assuming PDF filename is based on UUID; for simplicity, list files and match by scan_id in name
    # Here we just regenerate on the fly if needed, but for demo, assume it exists with pattern:
    import glob

    reports_dir = app.config["REPORTS_FOLDER"]
    # We don't store mapping; for demo, regenerate:
    pdf_filename = f"report_{scan.id}.pdf"
    pdf_path = os.path.join(reports_dir, pdf_filename)
    if not os.path.exists(pdf_path):
        generate_pdf_report(scan, pdf_path)
    return send_from_directory(reports_dir, pdf_filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)