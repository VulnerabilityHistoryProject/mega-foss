SELECT cve_id, assigner_vendor FROM cve_data
  WHERE state != 'REJECT' AND state != 'RESERVED' AND assigner_vendor = ANY(%s);
