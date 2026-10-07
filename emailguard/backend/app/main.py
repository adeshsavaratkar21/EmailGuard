from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import models
from .config import ALLOW_ACTIVE_URL_CHECKS, APP_NAME, MAX_EMAIL_BYTES
from .database import Base, engine, get_db
from .service import analyze_email_bytes, analyze_single_url

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=APP_NAME,
    description="Multi-layer email and web security analysis with an explainable prototype risk model.",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    network_checks: bool = False


def _save_record(db: Session, report: dict[str, Any], kind: str, **fields: Any) -> None:
    record = models.AnalysisRecord(
        id=report["analysis_id"],
        kind=kind,
        filename=fields.get("filename"),
        sender=fields.get("sender"),
        recipient=fields.get("recipient"),
        subject=fields.get("subject"),
        url=fields.get("url"),
        safety_score=report["safety_score"],
        risk_score=report["risk_score"],
        classification=report["classification"],
        recommendation=report["recommendation"],
        payload=report,
    )
    db.add(record)
    db.commit()


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _summary(record: models.AnalysisRecord) -> dict:
    return {
        "analysis_id": record.id,
        "kind": record.kind,
        "filename": record.filename,
        "sender": record.sender,
        "subject": record.subject,
        "url": record.url,
        "safety_score": record.safety_score,
        "risk_score": record.risk_score,
        "classification": record.classification,
        "recommendation": record.recommendation,
        "created_at": _iso_utc(record.created_at),
    }


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "EmailGuard",
        "version": app.version,
        "active_url_checks_enabled": ALLOW_ACTIVE_URL_CHECKS,
        "database": "connected",
    }


@app.post("/api/analyze/email")
async def analyze_email(
    file: UploadFile = File(...),
    network_checks: bool = Query(default=False),
    # Optional operator-supplied SMTP transport context for local SPF testing.
    # These are NOT trusted receiver data; they are labelled operator_supplied_context.
    spf_client_ip: str | None = Query(default=None, description="Operator-supplied connecting SMTP IP (for local SPF testing only, not trusted receiver data)"),
    spf_mailfrom: str | None = Query(default=None, description="Operator-supplied SMTP envelope sender"),
    spf_helo: str | None = Query(default=None, description="Operator-supplied SMTP HELO identity"),
    db: Session = Depends(get_db),
) -> dict:
    filename = Path(file.filename or "uploaded.eml").name
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Upload an .eml file. Attachments are not accepted as the message itself.")
    raw = await file.read(MAX_EMAIL_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=400, detail="The uploaded .eml file is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail=f"Email exceeds the {MAX_EMAIL_BYTES // (1024 * 1024)} MB upload limit.")
    operator_context: dict | None = None
    if spf_client_ip or spf_mailfrom:
        operator_context = {
            k: v for k, v in {
                "client_ip": spf_client_ip,
                "smtp_mailfrom": spf_mailfrom,
                "helo": spf_helo,
            }.items() if v
        }
    try:
        report = analyze_email_bytes(raw, filename, network_checks=network_checks, operator_context=operator_context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse this email: {str(exc)[:180]}") from exc
    _save_record(
        db,
        report,
        "email",
        filename=filename,
        sender=report["email"].get("sender"),
        recipient=report["email"].get("to"),
        subject=report["email"].get("subject"),
    )
    return report


@app.post("/api/analyze/url")
def analyze_url(request: URLAnalysisRequest, db: Session = Depends(get_db)) -> dict:
    try:
        report = analyze_single_url(request.url, network_checks=request.network_checks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _save_record(db, report, "url", url=report["url_analysis"].get("url"))
    return report


@app.get("/api/analyze/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    record = db.get(models.AnalysisRecord, analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return record.payload


@app.get("/api/history")
def history(limit: int = Query(default=50, ge=1, le=100), db: Session = Depends(get_db)) -> dict:
    records = db.scalars(select(models.AnalysisRecord).order_by(desc(models.AnalysisRecord.created_at)).limit(limit)).all()
    return {"items": [_summary(record) for record in records], "count": len(records)}


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)) -> dict:
    records = db.scalars(select(models.AnalysisRecord)).all()
    total = len(records)
    distribution = {key: sum(1 for record in records if record.classification == key) for key in ("SAFE", "SUSPICIOUS", "MALICIOUS")}
    average = round(sum(record.safety_score for record in records) / total) if total else 0
    recent = [
        {
            "analysis_id": record.id,
            "kind": record.kind,
            "label": record.filename or (record.url or "URL scan"),
            "classification": record.classification,
            "safety_score": record.safety_score,
            "created_at": _iso_utc(record.created_at),
        }
        for record in sorted(records, key=lambda row: (_iso_utc(row.created_at) or ""), reverse=True)[:6]
    ]
    return {
        "total_analyzed": total,
        "safe": distribution["SAFE"],
        "suspicious": distribution["SUSPICIOUS"],
        "malicious": distribution["MALICIOUS"],
        "average_safety_score": average,
        "recent_detections": [item for item in recent if item["classification"] != "SAFE"],
        "recent_activity": recent,
        "sample_data": total == 0,
    }
