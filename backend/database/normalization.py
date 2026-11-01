"""Idempotent migration of the legacy repeatable and name-based relations."""

import json

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from backend.database.db import engine
from backend.models.alert_anomaly import AlertAnomaly
from backend.models.alerts import Alert  # noqa: F401 - registers referenced table metadata


def _columns(bind, table: str) -> set[str]:
    inspector = inspect(bind)
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _decode_anomalies(raw_value) -> list:
    if raw_value is None:
        return []
    value = json.loads(raw_value) if isinstance(raw_value, (str, bytes, bytearray)) else raw_value
    if not isinstance(value, list):
        raise RuntimeError("alerts.anomalies contains a non-list value; migration stopped")
    return value


def _migrate_alert_anomalies(connection) -> int:
    if "anomalies" not in _columns(connection, "alerts"):
        return 0

    migrated = 0
    rows = connection.exec_driver_sql(
        "SELECT id, anomaly_type, anomalies FROM alerts ORDER BY id"
    ).fetchall()
    for alert_id, primary_type, raw_value in rows:
        anomalies = _decode_anomalies(raw_value)
        connection.exec_driver_sql(
            "DELETE FROM alert_anomalies WHERE alert_id = ?", (alert_id,)
        )
        for position, anomaly in enumerate(anomalies):
            if isinstance(anomaly, str):
                anomaly_type = primary_type if position == 0 else None
                message = anomaly
                severity = None
            elif isinstance(anomaly, dict):
                anomaly_type = anomaly.get("type") or anomaly.get("anomaly_type")
                message = anomaly.get("message")
                severity = anomaly.get("severity")
                if message is None:
                    raise RuntimeError(
                        f"alerts.anomalies item {position} for alert {alert_id} has no message"
                    )
                if severity is not None:
                    severity = float(severity)
            else:
                raise RuntimeError(
                    f"alerts.anomalies item {position} for alert {alert_id} has an unsupported type"
                )
            connection.exec_driver_sql(
                "INSERT INTO alert_anomalies "
                "(alert_id, position, anomaly_type, message, severity) "
                "VALUES (?, ?, ?, ?, ?)",
                (alert_id, position, anomaly_type, str(message), severity),
            )
            migrated += 1

    stored = connection.exec_driver_sql("SELECT COUNT(*) FROM alert_anomalies").scalar_one()
    if stored != migrated:
        raise RuntimeError(
            f"alert anomaly migration count mismatch: expected {migrated}, found {stored}"
        )
    connection.exec_driver_sql("ALTER TABLE alerts DROP COLUMN anomalies")
    return migrated


def _validate_department_name_matches(connection, source: str) -> None:
    if source == "device_metadata":
        query = (
            "SELECT COUNT(*) FROM device_metadata AS metadata "
            "JOIN devices AS device ON device.device_id = metadata.device_id "
            "LEFT JOIN departments AS department "
            "ON department.company_id = device.company_id "
            "AND department.name = metadata.department "
            "WHERE metadata.department IS NOT NULL "
            "AND trim(metadata.department) != '' AND department.id IS NULL"
        )
    else:
        query = (
            "SELECT COUNT(*) FROM department_baselines AS baseline "
            "LEFT JOIN departments AS department "
            "ON department.company_id = baseline.company_id "
            "AND department.name = baseline.department "
            "WHERE department.id IS NULL"
        )
    unmatched = connection.exec_driver_sql(query).scalar_one()
    if unmatched:
        raise RuntimeError(
            f"{source} has {unmatched} department value(s) without one tenant-scoped match; "
            "migration stopped without discarding them"
        )


def _migrate_device_departments(connection) -> int:
    columns = _columns(connection, "device_metadata")
    if "department" not in columns:
        return 0

    _validate_department_name_matches(connection, "device_metadata")
    if "department_id" not in columns:
        connection.exec_driver_sql(
            "ALTER TABLE device_metadata ADD COLUMN department_id INTEGER "
            "REFERENCES departments(id)"
        )
    connection.exec_driver_sql(
        "UPDATE device_metadata SET department_id = ("
        "SELECT department.id FROM devices AS device "
        "JOIN departments AS department ON department.company_id = device.company_id "
        "AND department.name = device_metadata.department "
        "WHERE device.device_id = device_metadata.device_id"
        ") WHERE department IS NOT NULL AND trim(department) != ''"
    )
    assigned = connection.exec_driver_sql(
        "SELECT COUNT(*) FROM device_metadata "
        "WHERE department IS NOT NULL AND trim(department) != ''"
    ).scalar_one()
    mapped = connection.exec_driver_sql(
        "SELECT COUNT(*) FROM device_metadata "
        "WHERE department IS NOT NULL AND trim(department) != '' "
        "AND department_id IS NOT NULL"
    ).scalar_one()
    if mapped != assigned:
        raise RuntimeError(
            f"device department migration count mismatch: expected {assigned}, mapped {mapped}"
        )
    connection.exec_driver_sql("ALTER TABLE device_metadata DROP COLUMN department")
    connection.exec_driver_sql(
        "CREATE INDEX IF NOT EXISTS ix_device_metadata_department_id "
        "ON device_metadata (department_id)"
    )
    return mapped


def _migrate_department_baselines(connection) -> int:
    columns = _columns(connection, "department_baselines")
    if "department" not in columns:
        return 0

    _validate_department_name_matches(connection, "department_baselines")
    count = connection.exec_driver_sql("SELECT COUNT(*) FROM department_baselines").scalar_one()
    risk_delta_mean = "baseline.risk_delta_mean" if "risk_delta_mean" in columns else "0.0"
    risk_delta_var = "baseline.risk_delta_var" if "risk_delta_var" in columns else "0.0"

    connection.exec_driver_sql("DROP TABLE IF EXISTS department_baselines__normalized")
    connection.exec_driver_sql(
        "CREATE TABLE department_baselines__normalized ("
        "department_id INTEGER NOT NULL PRIMARY KEY REFERENCES departments(id), "
        "files_accessed_mean FLOAT NOT NULL DEFAULT 0.0, "
        "files_accessed_var FLOAT NOT NULL DEFAULT 0.0, "
        "login_hour_mean FLOAT NOT NULL DEFAULT 0.0, "
        "login_hour_var FLOAT NOT NULL DEFAULT 0.0, "
        "failed_logins_mean FLOAT NOT NULL DEFAULT 0.0, "
        "failed_logins_var FLOAT NOT NULL DEFAULT 0.0, "
        "risk_delta_mean FLOAT NOT NULL DEFAULT 0.0, "
        "risk_delta_var FLOAT NOT NULL DEFAULT 0.0, "
        "sample_count INTEGER NOT NULL DEFAULT 0, "
        "login_hour_sample_count INTEGER NOT NULL DEFAULT 0, "
        "updated_at DATETIME)"
    )
    connection.exec_driver_sql(
        "INSERT INTO department_baselines__normalized ("
        "department_id, files_accessed_mean, files_accessed_var, "
        "login_hour_mean, login_hour_var, failed_logins_mean, failed_logins_var, "
        "risk_delta_mean, risk_delta_var, sample_count, "
        "login_hour_sample_count, updated_at) "
        "SELECT department.id, baseline.files_accessed_mean, baseline.files_accessed_var, "
        "baseline.login_hour_mean, baseline.login_hour_var, "
        "baseline.failed_logins_mean, baseline.failed_logins_var, "
        f"{risk_delta_mean}, {risk_delta_var}, "
        "baseline.sample_count, baseline.login_hour_sample_count, baseline.updated_at "
        "FROM department_baselines AS baseline "
        "JOIN departments AS department ON department.company_id = baseline.company_id "
        "AND department.name = baseline.department"
    )
    copied = connection.exec_driver_sql(
        "SELECT COUNT(*) FROM department_baselines__normalized"
    ).scalar_one()
    if copied != count:
        raise RuntimeError(
            f"department baseline migration count mismatch: expected {count}, copied {copied}"
        )
    connection.exec_driver_sql("DROP TABLE department_baselines")
    connection.exec_driver_sql(
        "ALTER TABLE department_baselines__normalized RENAME TO department_baselines"
    )
    return copied


def migrate_normalized_schema(bind: Engine = engine) -> dict[str, int]:
    """Migrate supported legacy SQLite layouts in one transaction.

    Fresh databases already have the normalized model layout. A legacy
    non-SQLite database is stopped for an explicit managed migration rather
    than receiving dialect-specific DDL by accident.
    """
    AlertAnomaly.__table__.create(bind=bind, checkfirst=True)
    legacy = {
        "alerts.anomalies": "anomalies" in _columns(bind, "alerts"),
        "device_metadata.department": "department" in _columns(bind, "device_metadata"),
        "department_baselines.department": "department" in _columns(bind, "department_baselines"),
    }
    if bind.dialect.name != "sqlite" and any(legacy.values()):
        raise RuntimeError(
            "Legacy relational normalization requires a reviewed migration for "
            f"the {bind.dialect.name} dialect"
        )

    result = {"alert_anomalies": 0, "device_departments": 0, "department_baselines": 0}
    if not any(legacy.values()):
        return result

    with bind.begin() as connection:
        result["alert_anomalies"] = _migrate_alert_anomalies(connection)
        result["device_departments"] = _migrate_device_departments(connection)
        result["department_baselines"] = _migrate_department_baselines(connection)
        violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(
                f"foreign-key validation found {len(violations)} violation(s); migration rolled back"
            )
    return result
