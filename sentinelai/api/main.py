"""
FastAPI REST API for SentinelAI
"""
import asyncio
from datetime import datetime
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn
from sqlalchemy import select

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinelai")
logger.setLevel(logging.INFO)

from ..core.scanner import SecurityScanner, ScanConfig, ScanStatus
from ..models.database import get_async_session, ScanResult, Vulnerability, init_db
from ..automation.scheduler import ScanScheduler


# Pydantic models
class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    max_depth: int = Field(3, ge=1, le=10)
    max_pages: int = Field(100, ge=1, le=1000)
    concurrency: int = Field(10, ge=1, le=50)
    modules: List[str] = Field(default=["injection", "xss", "auth", "config", "api"])
    ai_analysis: bool = Field(True)
    payload_intensity: str = Field("medium", pattern="^(low|medium|high)$")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://example.com",
                "max_depth": 3,
                "max_pages": 100,
                "modules": ["injection", "xss", "auth"]
            }
        }


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    message: str


class VulnerabilityResponse(BaseModel):
    id: int
    type: str
    severity: str
    url: str
    description: str
    risk_score: Optional[float] = None
    subtype: Optional[str] = None
    confidence: Optional[float] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[Any] = None
    remediation: Optional[str] = None
    ai_remediation: Optional[str] = None
    exploit_complexity: Optional[str] = None
    false_positive: Optional[bool] = False
    notes: Optional[str] = None
    exploitation_confirmed: Optional[bool] = False
    exploitation_proof: Optional[str] = None
    module: Optional[str] = None
    created_at: Optional[str] = None
    
    class Config:
        from_attributes = True


# Global state
active_scans = {}
scan_results = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    await init_db()
    yield
    # Shutdown
    for scanner in active_scans.values():
        await scanner.close()


app = FastAPI(
    title="SentinelAI API",
    description="AI-Powered Security Scanner API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


@app.get("/")
async def root():
    return {
        "name": "SentinelAI",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "scan": "/api/v1/scan",
            "scans": "/api/v1/scans",
            "vulnerabilities": "/api/v1/vulnerabilities",
            "websocket": "/ws/scan/{scan_id}"
        }
    }


@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a new security scan
    """
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(request.target_url) % 10000}"
    
    config = ScanConfig(
        target_url=request.target_url,
        max_depth=request.max_depth,
        max_pages=request.max_pages,
        concurrency=request.concurrency,
        included_modules=request.modules,
        ai_analysis=request.ai_analysis,
        payload_intensity=request.payload_intensity
    )
    
    scanner = SecurityScanner(config)
    scanner.status.scan_id = scan_id  # Unify outer API scan_id with scanner status scan_id
    active_scans[scan_id] = scanner
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, scanner)
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        target=request.target_url,
        message="Scan started successfully"
    )


async def run_scan(scan_id: str, scanner: SecurityScanner):
    """Run scan and store results"""
    from ..models.database import async_session_maker
    async with async_session_maker() as session:
        scanner.db_session = session  # Inject db session for scan persistence
        try:
            status = await scanner.start_scan()
            scan_results[scan_id] = scanner.get_report()
        except Exception as e:
            scanner.status.status = "failed"
            scanner.status.error_message = str(e)
        finally:
            await scanner.close()
            active_scans.pop(scan_id, None)


@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, db = Depends(get_async_session)):
    """
    Get scan status and progress
    """
    if scan_id in active_scans:
        scanner = active_scans[scan_id]
        return scanner.get_report()
    
    # Try loading from database
    stmt = select(ScanResult).where(ScanResult.scan_id == scan_id)
    res = await db.execute(stmt)
    db_scan = res.scalar_one_or_none()
    if db_scan:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vulns_list = []
        if db_scan.findings:
            vulns_list = db_scan.findings
            for v in vulns_list:
                sev = v.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "scan_id": db_scan.scan_id,
            "target": db_scan.target,
            "status": db_scan.status.value if db_scan.status else "completed",
            "duration": (db_scan.end_time - db_scan.start_time).total_seconds() if db_scan.end_time and db_scan.start_time else 0,
            "summary": {
                "pages_discovered": db_scan.pages_discovered,
                "pages_scanned": db_scan.pages_scanned,
                "vulnerabilities_found": db_scan.vulnerability_count,
                "severity_distribution": severity_counts
            },
            "vulnerabilities": vulns_list,
            "modules_used": db_scan.config.get("included_modules", []) if db_scan.config else [],
            "ai_analysis_enabled": db_scan.config.get("ai_analysis", True) if db_scan.config else True
        }
    
    if scan_id in scan_results:
        return scan_results[scan_id]
        
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/v1/scan/{scan_id}/vulnerabilities")
async def get_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    db = Depends(get_async_session)
):
    """
    Get vulnerabilities for a specific scan
    """
    vulnerabilities = []
    
    if scan_id in active_scans:
        report = active_scans[scan_id].get_report()
        vulnerabilities = report.get("vulnerabilities", [])
    else:
        # Try loading from database
        stmt = select(ScanResult).where(ScanResult.scan_id == scan_id)
        res = await db.execute(stmt)
        db_scan = res.scalar_one_or_none()
        if db_scan and db_scan.findings:
            vulnerabilities = db_scan.findings
        elif scan_id in scan_results:
            vulnerabilities = scan_results[scan_id].get("vulnerabilities", [])
        else:
            raise HTTPException(status_code=404, detail="Scan results not found")
            
    # Filter
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity]
    if vuln_type:
        vulnerabilities = [v for v in vulnerabilities if v.get("type") == vuln_type]
        
    return {
        "scan_id": scan_id,
        "total": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }


@app.get("/api/v1/scans")
async def list_scans(db = Depends(get_async_session)):
    """
    List all scans
    """
    # Query from DB
    stmt = select(ScanResult).order_by(ScanResult.start_time.desc())
    res = await db.execute(stmt)
    db_scans = res.scalars().all()
    
    scans_map = {}
    for s in db_scans:
        scans_map[s.scan_id] = {
            "scan_id": s.scan_id,
            "target": s.target,
            "status": s.status.value if s.status else "completed",
            "vulnerability_count": s.vulnerability_count
        }
        
    # Overlay running/active scans
    for scan_id, scanner in active_scans.items():
        scans_map[scan_id] = {
            "scan_id": scan_id,
            "target": scanner.config.target_url,
            "status": scanner.status.status,
            "vulnerability_count": scanner.status.vulnerabilities_found
        }
        
    # Add fallback in-memory results if not present
    for scan_id, report in scan_results.items():
        if scan_id not in scans_map:
            scans_map[scan_id] = {
                "scan_id": scan_id,
                "target": report.get("target"),
                "status": report.get("status"),
                "vulnerability_count": report.get("summary", {}).get("vulnerabilities_found", 0)
            }
            
    return {"scans": list(scans_map.values())}


@app.get("/api/v1/vulnerabilities")
async def get_all_vulnerabilities(
    severity: Optional[str] = None,
    limit: int = 100,
    db = Depends(get_async_session)
):
    """
    Get all vulnerabilities across all scans
    """
    # Query from DB
    stmt = select(Vulnerability)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    stmt = stmt.limit(limit)
    
    res = await db.execute(stmt)
    db_vulns = res.scalars().all()
    all_vulns = [v.to_dict() for v in db_vulns]
    
    # Add active scan findings in-memory
    for scanner in active_scans.values():
        report = scanner.get_report()
        vulns = report.get("vulnerabilities", [])
        if severity:
            vulns = [v for v in vulns if v.get("severity") == severity]
        all_vulns.extend(vulns)
        
    # Add fallback in-memory findings (prevent duplicates)
    db_vuln_ids = {v.get("id") for v in all_vulns if v.get("id") is not None}
    for report in scan_results.values():
        vulns = report.get("vulnerabilities", [])
        for v in vulns:
            if v.get("id") not in db_vuln_ids:
                if severity and v.get("severity") != severity:
                    continue
                all_vulns.append(v)
                
    return {
        "total": len(all_vulns),
        "vulnerabilities": all_vulns[:limit]
    }


@app.post("/api/v1/vulnerability/{vuln_id}/false-positive")
async def toggle_false_positive(
    vuln_id: int,
    db = Depends(get_async_session)
):
    """
    Toggle false positive status of a vulnerability
    """
    import logging
    logger = logging.getLogger(__name__)
    
    found = False
    new_status = False
    
    # 1. Update in-memory scan_results
    for report in scan_results.values():
        vulns = report.get("vulnerabilities", [])
        for v in vulns:
            if v.get("id") == vuln_id:
                v["false_positive"] = not v.get("false_positive", False)
                new_status = v["false_positive"]
                found = True
                break
        if found:
            break

    # 2. Update database
    try:
        from ..models.database import Vulnerability, ScanResult
        stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
        res = await db.execute(stmt)
        db_vuln = res.scalar_one_or_none()
        if db_vuln:
            db_vuln.false_positive = not db_vuln.false_positive
            new_status = db_vuln.false_positive
            await db.commit()
            
            # Also update the findings JSON list in the ScanResult model
            scan_stmt = select(ScanResult).where(ScanResult.scan_id == db_vuln.scan_id)
            scan_res = await db.execute(scan_stmt)
            db_scan = scan_res.scalar_one_or_none()
            if db_scan and db_scan.findings:
                updated_findings = []
                for f in db_scan.findings:
                    if f.get("id") == vuln_id:
                        f["false_positive"] = db_vuln.false_positive
                    updated_findings.append(f)
                db_scan.findings = updated_findings
                await db.commit()
            
            found = True
    except Exception as e:
        logger.error(f"Database error toggling false positive: {e}")

    if not found:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    return {"id": vuln_id, "false_positive": new_status}


@app.get("/api/v1/stats")
async def get_statistics(db = Depends(get_async_session)):
    """
    Get overall statistics
    """
    # Query from DB
    stmt_scans = select(ScanResult)
    res_scans = await db.execute(stmt_scans)
    db_scans = res_scans.scalars().all()
    
    scans_map = {}
    for s in db_scans:
        scans_map[s.scan_id] = s.vulnerability_count
        
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in db_scans:
        if s.findings:
            for v in s.findings:
                sev = v.get("severity", "info")
                severity_dist[sev] = severity_dist.get(sev, 0) + 1
                
    # Include active scans
    for scan_id, scanner in active_scans.items():
        scans_map[scan_id] = scanner.status.vulnerabilities_found
        report = scanner.get_report()
        for v in report.get("vulnerabilities", []):
            sev = v.get("severity", "info")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
            
    # Include fallback in-memory results
    for scan_id, report in scan_results.items():
        if scan_id not in scans_map:
            scans_map[scan_id] = report.get("summary", {}).get("vulnerabilities_found", 0)
            dist = report.get("summary", {}).get("severity_distribution", {})
            for sev, count in dist.items():
                severity_dist[sev] = severity_dist.get(sev, 0) + count
                
    total_scans = len(scans_map)
    total_vulns = sum(scans_map.values())
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "severity_distribution": severity_dist,
        "active_scans": len(active_scans)
    }


@app.delete("/api/v1/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scanner = active_scans[scan_id]
    # In a real implementation, you'd signal cancellation
    scanner.status.status = "cancelled"
    
    return {"message": "Scan cancelled", "scan_id": scan_id}


# WebSocket for real-time updates
@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    
    if scan_id not in active_scans:
        await websocket.send_json({"error": "Scan not found"})
        await websocket.close()
        return
    
    scanner = active_scans[scan_id]
    
    try:
        while True:
            # Send current status
            status = scanner.get_report()
            await websocket.send_json(status)
            
            # Check if scan completed
            if status.get("status") in ["completed", "failed", "cancelled"]:
                break
            
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"error": str(e)})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)