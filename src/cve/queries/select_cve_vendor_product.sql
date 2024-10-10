SELECT * FROM cve_data
WHERE (affected_vendor ILIKE %s OR urls::TEXT ILIKE %s)
   AND (affected_product ILIKE %s OR affected_product ILIKE %s);
