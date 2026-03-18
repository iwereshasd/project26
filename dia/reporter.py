import json

class Reporter:
    def to_json(self, report):
        return json.dumps({
            "container": report.container_name,
            "risk": report.risk_score,
            "domains": [{ "name": d.name, "score": d.score, "details": d.details } for d in report.domains],
            "recommendations": report.recommendations
        }, indent=2)
