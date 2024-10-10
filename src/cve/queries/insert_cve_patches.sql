WITH array_data AS (
    SELECT cve_json_data.data,
           ARRAY(
               SELECT url_element::TEXT
               FROM jsonb_path_query_array(cve_json_data.data, '$.**.references.**.url') AS urls,
                    jsonb_array_elements_text(urls) AS url_element
               WHERE url_element::TEXT ~ '^https?://(www\.)?github.com.*/\w+/\w+.*$'
           ) AS urls,
		   ARRAY(
               SELECT val_element::TEXT
               FROM jsonb_path_query_array(cve_json_data.data, '$.**') AS values,
                    jsonb_array_elements_text(values) AS val_element
               WHERE val_element::TEXT ~ '^https?://(www\.)?github.com.*/\w+/\w+/commit/([\da-f]{40}).*$'
           ) AS commits,
		   ARRAY(
               SELECT cwe_element::TEXT
               FROM jsonb_path_query_array(cve_json_data.data, '$.**.cweId') AS cwes,
                    jsonb_array_elements_text(cwes) AS cwe_element
           ) AS cwe_ids
    FROM cve_json_data
)
INSERT INTO cve_patches (cve_id, cwe_ids, commits, urls)
SELECT
    jt.cve_id AS cve_id,
    COALESCE(array_data.cwe_ids, '{}') AS cwe_ids,
    array_data.commits AS commits,
    array_data.urls AS urls
FROM array_data,
LATERAL JSON_TABLE(
    array_data.data,
    '$[*]'
    COLUMNS(
        cve_id TEXT PATH '$.cveMetadata.cveId'
    )
) AS jt
-- WHERE array_data.urls::TEXT ILIKE '%%s%'
