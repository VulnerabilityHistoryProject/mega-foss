from gql import gql, Client
from read_product_vendor import *

from gql.transport.requests import RequestsHTTPTransport

import time

# Load environment variables from .env file
from dotenv import load_dotenv
import os
load_dotenv()

# Set up the GraphQL client with the transport
transport = RequestsHTTPTransport(
    url='https://api.github.com/graphql',
    headers={'Authorization': f"bearer {os.getenv('GQL_ACCESS_TOKEN')}"},
)

client = Client(transport=transport, fetch_schema_from_transport=True)

csv_path = 'lists/graphql_csv_data.csv'

#THIS IS AN EXAMPLE QUERY THAT WILL BE RAN FOR EVERY PRODUCT/VENUE PAIR
# query = gql("""
# {
#   repository(owner: "freebsd",name:"freebsd"){
#       description
#     	isEmpty
#     	createdAt
#     	homepageUrl
#     }
# }
# """)
# result = client.execute(query)
# print(result)


#This is our standard graphql query to find matching repositories and other information
query = gql("""
query ($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    description
    createdAt
    url
    homepageUrl
    diskUsage
  }
}
""")



"""_summary_
		Queries the unique vendor/product pairs and writes the queires that 
        successfully returns a matching repository into the 'lists/graphql_csv_data.csv' file
        
        Has the option to start with a given vendor/product pair
  
    Args:
			vendor   (str)
            product  (str)
"""
def gql_query_to_csv(vendor=None,product=None):
    starting_index = find_starting_index(vendor,product)
    with open(csv_path, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['vendor', 'product', 'url', 'homepageUrl', 'description', 'createdAt', 'diskUsage'])
        writer.writeheader()
        for item in extracted_pairs[starting_index:]:
            vendor = item['vendor']
            product = item['product']
            try:
                result = client.execute(query, variable_values={'owner': vendor, 'name': product})
                repo = result.get("repository")
                if repo:
                    print(f"{vendor}/{product}: {result['repository']}")
                    writer.writerow({
                        'vendor': vendor,
                        'product': product,
                        'url': repo.get('url', ''),
                        'homepageUrl': repo.get('homepageUrl', ''),
                        'description': repo.get('description', ''),
                        'createdAt': repo.get('createdAt', ''),
                        'diskUsage': repo.get('diskUsage', '')
                    })
                else:
                    print(f"{vendor}/{product} → No repository found.")
            except Exception as e:
                #result_msg = f"Error: {str(e)}"
                continue
            finally:
                time.sleep(0.75)
                pass
                
            
"""_summary_
		Queries the unique vendor/product pairs and 
        successfully returns a matching repository.
        
        Has the option to start with a given vendor/product pair
  
    Args:
			vendor   (str)
            product  (str)
"""                
def standard_gql_query(vendor=None,product=None):
    starting_index = find_starting_index(vendor,product)
    for item in extracted_pairs[starting_index:]:
        vendor = item['vendor']
        product = item['product']

        try:
            result = client.execute(query, variable_values={'owner': vendor, 'name': product})
            #time.sleep(0.75)
            if result.get("repository"):
                print(f"{vendor}/{product}: {result['repository']}")
            else:
                print(f"{vendor}/{product} → No repository found.")
        except Exception as e:
            continue
        finally:
            time.sleep(0.75)

def get_repo_url(vendor, product):
    query = gql("""
        query ($owner: String!, $name: String!) {
            repository(owner: $owner, name: $name) {
                url
            }
        }
    """)
    
    try:
        result = client.execute(query, variable_values={'owner': vendor, 'name': product})
        repo = result.get('repository')
        if repo:
            return repo.get('url')
        else:
            print(f"No repository found for {vendor}/{product}")
            return None
    except Exception as e:
        print(f"Error querying {vendor}/{product}: {e}")
        return None


if __name__ == "__main__":
    #gql_query_to_csv("hylafax","hylafax")
    print(get_repo_url("jcollie","asterisk"))