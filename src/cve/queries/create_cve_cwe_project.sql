CREATE TABLE cve_cwe_project AS
	SELECT DISTINCT
		  cve_patches.cve_id,
		  UNNEST(cwe_ids) AS cwe_id,
		  CONCAT(affected_vendor, '/', affected_product) AS project
		FROM cve_patches
		JOIN cve_data ON cve_patches.cve_id = cve_data.cve_id
		WHERE affected_vendor != 'n/a' OR affected_product != 'n/a';
