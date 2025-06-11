import json

with open('lists/nvdcve-vendor-product.json') as f:
    data = json.load(f)

#with open('src/cve/graphql/trial.json') as f:
    #data = json.load(f)
    
seen = set()
extracted_pairs = []

# Extract unique vendor-product pairs from the JSON data
for pair in [{'vendor': item.get('vendor'), 'product': item.get('product')} for item in data if item.get('vendor') is not None and item.get('product') is not None]:
    key = (pair['vendor'], pair['product'])
    if key not in seen:
        seen.add(key)
        extracted_pairs.append(pair)
