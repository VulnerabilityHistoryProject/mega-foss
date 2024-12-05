"""
Mapping for CVSS v2 and v3 metrics
"""
import orjson

MAP_3_2 = {
  "AV": {
    "N": "network",
    "A": "adjacent",
    "L": "local",
    "P": "physical",
  },
  "AC": {
    "L": "low",
    "H": "high",
  },
  "PR": {
    "N": "none",
    "L": "low",
    "H": "high",
  },
  "UI": {
    "N": "none",
    "R": "required",
  },
  "S": {
    "U": "unchanged",
    "C": "changed",
  },
  "C": {
    "N": "none",
    "L": "low",
    "H": "high",
  },
  "I": {
    "N": "none",
    "L": "low",
    "H": "high",
  },
  "A": {
    "N": "none",
    "L": "low",
    "H": "high",
  }
}

MAP_2_0 = {
  "AV": {
    "L": "local",
    "A": "adjacent",
    "N": "network",
  },
  "AC": {
    "H": "high",
    "M": "medium",
    "L": "low",
  },
  "Au": {
    "N": "none",
    "S": "single",
    "M": "multiple",
  },
  "C": {
    "N": "none",
    "P": "partial",
    "C": "complete",
  },
  "I": {
    "N": "none",
    "P": "partial",
    "C": "complete",
  },
  "A": {
    "N": "none",
    "P": "partial",
    "C": "complete",
  }
}

def vector_to_json(vector_str: str):
  """
  Converts a CVSS vector string to JSON format.

  Args:
      vector_str (str): CVSS vector string in format "METRIC:VALUE/METRIC:VALUE/..."

  Returns:
      bytes: JSON representation of the vector metrics as a bytes object
  """
  json = {}
  metrics = vector_str.split("/")
  for metric in metrics:
    key, value = metric.split(":")
    try:
      json[key] = MAP_3_2[key][value].upper()
    except: # Fallback to v2 mapping
      json[key] = MAP_2_0[key][value].upper()

  return orjson.dumps(json)


def json_to_vector(json_str: str):
  """
  Converts JSON format CVSS metrics back to vector string format.

  Args:
      json_str (str): JSON string containing CVSS metric values

  Returns:
      str: CVSS vector string in format "METRIC:VALUE/METRIC:VALUE/..."
  """
  json = orjson.loads(json_str)
  vector = ""
  for key, value in json.items():
    try:
      vector += f"{key}:{list(MAP_3_2[key].keys())[list(MAP_3_2[key].values()).index(value.lower())]}/"
    except:
      vector += f"{key}:{list(MAP_2_0[key].keys())[list(MAP_2_0[key].values()).index(value.lower())]}/"

  return vector[:-1]
