import os
import re
from config import read_config, mg_connect

cfg = read_config()
database = mg_connect(cfg)

PIPELINES = {
    "cve_cwe": "pipelines/mongo-cve-cwe.py",
    "cve_full_map": "pipelines/mongo-cve-full-map.py",
    "cve_patches": "pipelines/mongo-nvdcve.py",
    "cve_vendor_product": "pipelines/mongo-vendor-product.py",
    "cve_metrics": "pipelines/mongo-cve-metrics.py",
}

def load_pipeline(file_path: str):
    """Load a MongoDB aggregation pipeline from a Python file."""
    full_path = os.path.join(os.path.dirname(__file__), file_path)
    with open(full_path, "r") as f:
        return eval(f.read())

def create_view(name: str, pipeline):
    """Create or replace a MongoDB view safely."""
    try:
        database.command("drop", name)
    except Exception:
        pass
    database.command("create", name, pipeline=pipeline, viewOn="nvdcve")

def main():
    for view_name, file_path in PIPELINES.items():
        pipeline = load_pipeline(file_path)
        create_view(view_name, pipeline)
    print("Views created successfully.")

if __name__ == "__main__":
    main()
