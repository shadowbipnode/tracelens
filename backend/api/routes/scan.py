import json
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings
from backend.database import Database, Scan, utc_now
from backend.models.target import ScanCreate
from backend.orchestrator import parse_iso_datetime, run_passive_scan
from backend.report_builder import enrich_report


router = APIRouter(prefix="/api/scans", tags=["scans"])


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _scan_summary(scan: Scan) -> Dict[str, Any]:
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
    }


@router.post("", status_code=201)
def create_scan(
    payload: ScanCreate,
    database: Database = Depends(get_database),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    with database.session() as session:
        scan = Scan(target=payload.target, status="running", created_at=utc_now())
        session.add(scan)
        session.flush()
        scan_id = scan.id

    try:
        report = run_passive_scan(payload.target, settings)
        with database.session() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise RuntimeError("scan record disappeared during execution")
            scan.status = report["status"]
            scan.completed_at = parse_iso_datetime(report["completed_at"])
            report["scan_id"] = scan_id
            scan.report_json = json.dumps(report)
            scan.error_json = json.dumps(
                [
                    {"source": source, "errors": result["errors"]}
                    for source, result in report["collectors"].items()
                    if result["errors"]
                ]
            )
        return {"scan_id": scan_id, "status": report["status"]}
    except Exception as exc:
        with database.session() as session:
            scan = session.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.completed_at = utc_now()
                scan.error_json = json.dumps([str(exc)])
        raise HTTPException(status_code=500, detail="Scan execution failed") from exc


@router.get("")
def list_scans(
    database: Database = Depends(get_database),
) -> List[Dict[str, Any]]:
    with database.session() as session:
        scans = session.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
        return [_scan_summary(scan) for scan in scans]


@router.get("/{scan_id}")
def get_scan(
    scan_id: int, database: Database = Depends(get_database)
) -> Dict[str, Any]:
    with database.session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        report = scan.report() or {}
        response = _scan_summary(scan)
        response["collector_statuses"] = report.get("collector_statuses", {})
        response["errors"] = scan.errors()
        return response


@router.get("/{scan_id}/report")
def get_report(
    scan_id: int, database: Database = Depends(get_database)
) -> Dict[str, Any]:
    with database.session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        report = scan.report()
        if report is None:
            raise HTTPException(status_code=409, detail="Scan report is not available")
        return enrich_report(report)
