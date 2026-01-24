from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import os


def build_report(target, assets, endpoints, findings):
    env = Environment(
        loader=FileSystemLoader("reporting/templates")
    )

    template = env.get_template("report.html")

    severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for f in findings:
        sev = f.get("severity", "Low")
        severity.setdefault(sev, 0)
        severity[sev] += 1

    html = template.render(
        target=target,
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        assets=assets,
        endpoints=endpoints,
        findings=findings,
        severity=severity
    )

    os.makedirs("output", exist_ok=True)

    html_path = "output/report.html"
    pdf_path = "output/report.pdf"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # -----------------------------
    # PDF GENERATION
    # -----------------------------
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    y = height - 40
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, y, "SentinelX Penetration Testing Report")

    y -= 40
    c.setFont("Helvetica", 12)
    c.drawString(40, y, f"Target: {target}")
    y -= 20
    c.drawString(40, y, f"Date: {datetime.utcnow()}")

    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Findings Summary")

    y -= 20
    for k, v in severity.items():
        c.drawString(60, y, f"{k}: {v}")
        y -= 18

    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Vulnerabilities")

    c.setFont("Helvetica", 10)
    y -= 20

    for f in findings:
        if y < 80:
            c.showPage()
            y = height - 40

        c.drawString(50, y, f"- {f.get('type')} [{f.get('severity')}]")
        y -= 14
        c.drawString(70, y, f"URL: {f.get('url', '')}")
        y -= 14
        c.drawString(70, y, f"Impact: {f.get('business_impact','')}")
        y -= 20

    c.save()

    return pdf_path
