SELECT * FROM cve_data
WHERE
   (affected_product ILIKE %s OR affected_product ILIKE %s);
