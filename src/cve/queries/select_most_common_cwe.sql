SELECT cwe_id, COUNT(cve_id) AS cve_count, COUNT(DISTINCT(project))
FROM c_cve_cwe_project
GROUP BY cwe_id
ORDER BY cve_count DESC;
