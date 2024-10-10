SELECT cve_id, cwe_ids, commits FROM cve_patches
	WHERE urls::TEXT ILIKE %s;
