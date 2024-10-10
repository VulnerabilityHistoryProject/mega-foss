CREATE TABLE IF NOT EXISTS cve_data (
    cve_id TEXT,
    state TEXT,
  	assigner_vendor TEXT,
    affected_vendor TEXT,
    affected_product TEXT,
    urls TEXT[]
);
