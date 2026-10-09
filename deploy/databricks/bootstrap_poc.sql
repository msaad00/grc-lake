-- GRC Lake Databricks evidence-lake POC bootstrap (Unity Catalog).
--
-- Run as a user who can create a catalog and read system.access.audit (a
-- metastore/account admin, or someone granted USE SCHEMA + SELECT on
-- system.access). The script creates only GRC Lake-owned objects and read
-- grants. It does not create service principals, tokens, warehouses, external
-- locations, or network access.
--
-- Default objects:
--   catalog: grc-lake
--   schema:  grc-lake.evidence
--   reader:  a service principal, referenced by its application id
--
-- On SQL warehouses, Unity Catalog evaluates the view owner's permissions on
-- underlying tables, so the reader needs SELECT on these views only - never on
-- system.access.audit itself. Row-level views keep the latest 10,000 events so
-- a single read stays under the Statement Execution API INLINE limit (25 MiB).

CREATE CATALOG IF NOT EXISTS grc-lake COMMENT 'GRC Lake governed evidence lake POC';
CREATE SCHEMA IF NOT EXISTS grc-lake.evidence COMMENT 'Curated read-only evidence views for GRC Lake';

CREATE OR REPLACE VIEW grc-lake.evidence.GRC_LAKE_AUDIT_EVENTS AS
SELECT
  event_id AS audit_id,
  user_identity.email AS actor,
  concat(service_name, '.', action_name) AS object_name,
  CASE WHEN response.statusCode >= 400 THEN 'open' ELSE 'observed' END AS status,
  CASE
    WHEN response.statusCode IN (401, 403) THEN 'medium'
    WHEN response.statusCode >= 400 THEN 'low'
    ELSE 'info'
  END AS severity,
  event_id AS evidence_ref,
  request_id AS query_id,
  action_name AS event_action
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), 7)
ORDER BY event_time DESC
LIMIT 10000;

CREATE OR REPLACE VIEW grc-lake.evidence.GRC_LAKE_CONTROL_POSTURE AS
SELECT
  'DATABRICKS-AUDIT-LOGGING' AS control_id,
  CASE WHEN count(*) > 0 THEN 'passed' ELSE 'open' END AS status,
  CASE WHEN count(*) > 0 THEN 10 ELSE 70 END AS risk_score,
  CASE WHEN count(*) > 0 THEN 'low' ELSE 'high' END AS severity,
  'databricks-system-access-audit' AS evidence_ref,
  'SOC2' AS framework_id,
  0.95 AS confidence
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), 7)
UNION ALL
SELECT
  'DATABRICKS-DENIED-ACCESS-REVIEW' AS control_id,
  CASE WHEN count_if(response.statusCode IN (401, 403)) = 0 THEN 'passed' ELSE 'open' END AS status,
  CASE WHEN count_if(response.statusCode IN (401, 403)) = 0 THEN 10 ELSE 60 END AS risk_score,
  CASE WHEN count_if(response.statusCode IN (401, 403)) = 0 THEN 'low' ELSE 'medium' END AS severity,
  'databricks-denied-requests' AS evidence_ref,
  'SOC2' AS framework_id,
  0.85 AS confidence
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), 7);

CREATE OR REPLACE VIEW grc-lake.evidence.GRC_LAKE_ASSET_RISK AS
SELECT
  concat('databricks:workspace:', workspace_id) AS asset_id,
  'workspace' AS asset_type,
  'databricks' AS owner,
  'prod' AS environment,
  CASE WHEN count_if(response.statusCode IN (401, 403)) > 0 THEN 60 ELSE 10 END AS risk_score,
  CASE WHEN count_if(response.statusCode IN (401, 403)) > 0 THEN 'open' ELSE 'observed' END AS status,
  CASE WHEN count_if(response.statusCode IN (401, 403)) > 0 THEN 'medium' ELSE 'low' END AS severity,
  concat('databricks-workspace-', workspace_id) AS evidence_ref
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), 7)
GROUP BY workspace_id;

CREATE OR REPLACE VIEW grc-lake.evidence.GRC_LAKE_EVIDENCE_BUNDLES AS
SELECT
  event_id AS bundle_id,
  event_id AS evidence_ref,
  CASE WHEN response.statusCode >= 400 THEN 'open' ELSE 'observed' END AS status,
  CASE WHEN response.statusCode >= 400 THEN 'medium' ELSE 'info' END AS severity,
  sha2(concat_ws(':', event_id, service_name, action_name, cast(event_time AS STRING)), 256) AS hash_sha256,
  concat('databricks://system/access/audit/', event_id) AS object_uri
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), 7)
ORDER BY event_time DESC
LIMIT 10000;

-- Replace <grc-lake-sp-application-id> with the service principal's
-- application id. The schema holds only GRC Lake views, so a schema-level
-- SELECT grant is no broader than granting each view.
GRANT USE CATALOG ON CATALOG grc-lake TO `<grc-lake-sp-application-id>`;
GRANT USE SCHEMA ON SCHEMA grc-lake.evidence TO `<grc-lake-sp-application-id>`;
GRANT SELECT ON SCHEMA grc-lake.evidence TO `<grc-lake-sp-application-id>`;
-- Also grant the service principal CAN USE on one SQL warehouse in the
-- workspace UI or Permissions API; GRC Lake needs no other warehouse right.

-- Validation (run as the service principal, or with its grants): every query
-- should succeed.
SELECT count(*) AS audit_events FROM grc-lake.evidence.GRC_LAKE_AUDIT_EVENTS;
SELECT count(*) AS control_posture FROM grc-lake.evidence.GRC_LAKE_CONTROL_POSTURE;
SELECT count(*) AS asset_risk FROM grc-lake.evidence.GRC_LAKE_ASSET_RISK;
SELECT count(*) AS evidence_bundles FROM grc-lake.evidence.GRC_LAKE_EVIDENCE_BUNDLES;
