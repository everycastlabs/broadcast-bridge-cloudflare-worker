-- Migration number: 0001 	 2024-08-12T12:43:56.874Z
CREATE TABLE workos_user_lookup (
  workos_user_id TEXT PRIMARY KEY,
  firebase_user_id TEXT
);

CREATE TABLE workos_organisation_lookup (
  workos_organisation_id TEXT PRIMARY KEY,
  firestore_org_id TEXT
);

