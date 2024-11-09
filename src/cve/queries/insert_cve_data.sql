WITH url_data AS (
    SELECT cve_json_data.data,
           ARRAY(
               SELECT url_element::TEXT
               FROM jsonb_path_query_array(cve_json_data.data, '$.**.url') AS urls,
                    jsonb_array_elements_text(urls) AS url_element
               WHERE url_element::TEXT ~ '^https?://(www\.)?github.com.*/\w+/\w+.*([\da-f]{40}).*$'
           ) AS urls
    FROM cve_json_data
)
INSERT INTO cve_data (cve_id, state, assigner_vendor, affected_vendor, affected_product, urls)
SELECT
    jt.cve_id AS cve_id,
    jt.state AS state,
    jt.assigner_short_name AS assigner_vendor,
    COALESCE(NULLIF(cna_affected.vendor, 'n/a'), NULLIF(adp_affected.vendor, 'n/a'), 'n/a') AS affected_vendor,
    COALESCE(NULLIF(cna_affected.product, 'n/a'), NULLIF(adp_affected.product, 'n/a'), 'n/a') AS affected_product,
    url_data.urls AS urls
FROM url_data,
LATERAL JSON_TABLE(
    url_data.data,
    '$[*]'
    COLUMNS(
        cve_id TEXT PATH '$.cveMetadata.cveId',
        type TEXT PATH '$.dataType',
        affected JSON PATH '$.containers.cna.affected',
        assigner_id TEXT PATH '$.cveMetadata.assignerOrgId',
        assigner_short_name TEXT PATH '$.cveMetadata.assignerShortName',
        state TEXT PATH '$.cveMetadata.state'
    )
) AS jt
LEFT JOIN LATERAL JSON_TABLE(
    jt.affected,
    '$[*]'
    COLUMNS (
        vendor TEXT PATH '$.vendor',
        product TEXT PATH '$.product'
    )
) AS cna_affected ON TRUE
LEFT JOIN LATERAL JSON_TABLE(
    url_data.data,
    '$.containers.adp[*].affected[*]'
    COLUMNS (
        vendor TEXT PATH '$.vendor',
        product TEXT PATH '$.product'
    )
) AS adp_affected ON TRUE;
