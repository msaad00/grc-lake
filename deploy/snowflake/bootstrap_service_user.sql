-- GRC Lake Snowflake service-user bootstrap.
--
-- Run after bootstrap_poc.sql from ACCOUNTADMIN or a governed GRC admin role
-- allowed to manage users and grant GRC_LAKE_READER.
--
-- This script creates a non-human Snowflake service user for scheduled
-- GRC Lake ingestion. It does not create passwords, PATs, network integrations,
-- stages, or write privileges.
--
-- Before running, generate or retrieve an RSA public key from your secret
-- manager process, remove BEGIN/END delimiters and line breaks, then set:
--
--   SET GRC_LAKE_SERVICE_RSA_PUBLIC_KEY = '<public-key-body-without-delimiters>';
--
-- The matching private key stays outside Snowflake and outside this repo. Mount
-- it into the GRC Lake runtime and reference it with SNOWFLAKE_PRIVATE_KEY_FILE.

USE ROLE ACCOUNTADMIN;

SET GRC_LAKE_SERVICE_USER = 'GRC_LAKE_INGEST_SVC';

CREATE USER IF NOT EXISTS IDENTIFIER($GRC_LAKE_SERVICE_USER)
  TYPE = SERVICE
  DEFAULT_ROLE = GRC_LAKE_READER
  DEFAULT_WAREHOUSE = GRC_LAKE_READ_WH
  COMMENT = 'GRC Lake read-only evidence ingestion service user';

ALTER USER IDENTIFIER($GRC_LAKE_SERVICE_USER)
  SET RSA_PUBLIC_KEY = $GRC_LAKE_SERVICE_RSA_PUBLIC_KEY;

GRANT ROLE GRC_LAKE_READER TO USER IDENTIFIER($GRC_LAKE_SERVICE_USER);

-- Optional verification. RSA_PUBLIC_KEY_FP should be populated, and the user
-- should have only GRC_LAKE_READER for this POC path.
DESC USER IDENTIFIER($GRC_LAKE_SERVICE_USER);
SHOW GRANTS TO USER IDENTIFIER($GRC_LAKE_SERVICE_USER);
