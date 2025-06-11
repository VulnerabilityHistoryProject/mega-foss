from gql import gql, Client
from read_product_vendor import *

from gql.transport.requests import RequestsHTTPTransport



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

query = gql("""
query ($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    description
    createdAt
    homepageUrl
    diskUsage
  }
}
""")

for item in extracted_pairs:
    vendor = item['vendor']
    product = item['product']

    try:
        result = client.execute(query, variable_values={'owner': vendor, 'name': product})
        if result.get("repository"):
            print(f"{vendor}/{product}: {result['repository']}")
        else:
            print(f"{vendor}/{product} → No repository found.")
    except Exception as e:
        #print(f"{vendor}/{product} → Error: {e}")
        continue

#result = client.execute(query)
#print(result)