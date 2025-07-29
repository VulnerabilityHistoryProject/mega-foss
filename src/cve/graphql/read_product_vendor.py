import json
import csv
import sys
import os
sys.path.append(os.path.dirname(__file__))


with open('lists/nvdcve-vendor-product.json') as f:
    data = json.load(f)

#with open('src/cve/graphql/trial.json') as f:
    #data = json.load(f)
    
seen = set()
extracted_pairs = []

csv_path = 'lists/products_vendors.csv'

# Extract unique vendor-product pairs from the JSON data
for pair in [{'vendor': item.get('vendor'), 'product': item.get('product')} for item in data if item.get('vendor') is not None and item.get('product') is not None]:
    key = (pair['vendor'], pair['product'])
    if key not in seen:
        seen.add(key)
        extracted_pairs.append(pair)


"""_summary_
		Prints the unique vendor/product pairs into the 'lists/product_vendors.csv' file
"""  
def print_product_vendors_to_csv():
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['vendor', 'product'])
        writer.writeheader()
        writer.writerows(extracted_pairs)


"""_summary_
		Finds the index for the vendor/product pair
  
    Args:
			vendor   (str)
            product  (str)
"""   
def find_starting_index(vendor=None,product=None):
    if not vendor or not product:
        return 0
    if product and vendor:
        return extracted_pairs.index({'vendor': vendor, 'product': product})
   

if __name__ == "__main__":
    #print(extracted_pairs[52060:])
    start_index = extracted_pairs.index({'vendor': 'tri', 'product': 'gigpress'})
    print(start_index)
    print(find_starting_index('answer'))
   
