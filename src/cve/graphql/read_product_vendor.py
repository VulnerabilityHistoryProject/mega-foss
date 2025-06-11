import json

with open('lists/nvdcve-vendor-product.json') as f:
    data = json.load(f)

#with open('src/cve/graphql/trial.json') as f:
    #data = json.load(f)
    
extracted_pairs = [{'vendor': item.get('vendor'), 'product': item.get('product')} for item in data if item.get('vendor') is not None and item.get('product') is not None]
print(extracted_pairs)
