SELECT DISTINCT UNNEST(cwe_ids) AS cwe_id
FROM cve_patches;
