import json
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os


def build_report(target, assets, endpoints, findings):
    env = Environment(
        loader=FileSystemLoader("reporting/templates")
    )

    template = env.get_template("report.html")

    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for f in findings:
        sev = f.get("severity", "Low")
        severity_count[sev] += 1

    html = template.render(
        target=target,
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        assets=assets,
        endpoints=endpoints,
        findings=findings,
        severity=severity_count
    )

    os.makedirs("output", exist_ok=True)

    with open("output/report.html", "w", encoding="utf-8") as f:
        f.write(html)

    return "output/report.html"
