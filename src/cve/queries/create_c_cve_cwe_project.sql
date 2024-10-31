CREATE TABLE c_cve_cwe_project AS
				SELECT * FROM cve_cwe_project
				WHERE project=ANY(%s);

CREATE TABLE c_cve_project_no_cwe AS
				SELECT * FROM cve_project_no_cwe
				WHERE project=ANY(%s);
