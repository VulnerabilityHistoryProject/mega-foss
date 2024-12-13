import os
from config import mg_connect
import re

# Connection Details
db = mg_connect()

# Input files/folders
cve_cwe_map = os.path.join(os.path.dirname(__file__), "pipelines/mongo-cve-cwe.py")
cve_full_map = os.path.join(os.path.dirname(__file__), "pipelines/mongo-cve-full-map.py")
patches_map = os.path.join(os.path.dirname(__file__), "pipelines/mongo-nvdcve.py")
vendor_product_map = os.path.join(os.path.dirname(__file__), "pipelines/mongo-vendor-product.py")
cve_vector_metrics_map = os.path.join(os.path.dirname(__file__), "pipelines/mongo-cve-metrics.py")

def load_pipeline(file):
  with open(file, "r") as f:
    return eval(f.read())

def create_view(name, pipeline):
  try:
    db.command("drop", name)
  except:
    pass
  db.command("create", name, pipeline=pipeline, viewOn="nvdcve")

def main():
  create_view("cve_cwe", load_pipeline(cve_cwe_map))
  create_view("cve_patches", load_pipeline(patches_map))
  create_view("cve_vendor_product", load_pipeline(vendor_product_map))
  create_view("cve_metrics", load_pipeline(cve_vector_metrics_map))
  create_view("cve_full_map", load_pipeline(cve_full_map))
  print("Views created successfully.")


if __name__ == "__main__":
  main()
