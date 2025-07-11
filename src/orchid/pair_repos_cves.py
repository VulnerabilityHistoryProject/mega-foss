import csv
import json
from pymongo import MongoClient
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
import os
import subprocess
import time
from dotenv import load_dotenv

# ######### CURRENT PROCESS #########
# Read data rows from processed graphql_csv_data file.
# For each repo (vendor/product), retrieve all related CVE IDs from nvd_data file.
# With the list of CVE IDs, query the mongoDB for descriptions and cpe_match strings.
# From the cpe_match strings extract, filter and sort versions related to the current repo. (Version filtering can be improved)
# Using a bash script, clone the repo and iterate over commits to get commit hashes, messages and related tags.
# Finally format everything and write to the json output file.

load_dotenv()

# CSV file with: vendor,product,url,homepageUrl,description,createdAt,diskUsage
csv_file_path = "lists/test_repo_cve_pairing.csv" # for testing purposes
# csv_file_path = "lists/graphql_csv_data.csv" 

# JSON file with: _id, cve_id, vendor, product
nvd_json_file_path = "lists/nvdcve-vendor-product.json"

# JSON output file to store the results
json_output_path = "lists/cves_repos_and_commits.json"


# MongoDB connection setup
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["nvdcve"]
cve_collection = db["nvdcve"]

# GraphQL client setup
transport = RequestsHTTPTransport(
    url="https://api.github.com/graphql",
    headers={"Authorization": f"bearer {os.getenv('GQL_ACCESS_TOKEN')}"},
)
gql_client = Client(transport=transport, fetch_schema_from_transport=True)


def get_cves_for_vendor_product(vendor: str, product: str) -> list:
    """
    Fetches CVE IDs for a given vendor and product from the NVD JSON file.

    Args:
        vendor (str): The vendor name.
        product (str): The product name.

    Returns:
        list: A list of CVE IDs associated with the vendor and product.
    """
    with open(nvd_json_file_path, "r", encoding="utf-8") as f:
        nvd_data = json.load(f)

    cves = []
    for entry in nvd_data:
        if entry["vendor"] == vendor and entry["product"] == product:
            cves.append(entry["cve_id"])

    return cves


def fetch_cve_details_from_mongo(cves: list) -> list:
    """
    Query MongoDB to fetch CVE details for a list of CVE IDs.

    Args:
        cves (list): A list of CVE IDs to query.

    Returns:
        list: A list of dictionaries containing CVE ID, description, and CPE match strings
        for the specified CVEs.
    """
    cve_results = cve_collection.aggregate(
        [
            {"$match": {"cve.CVE_data_meta.ID": {"$in": cves}}},
            {
                "$project": {
                    "cve_id": "$cve.CVE_data_meta.ID",
                    "cve_description": {
                        "$arrayElemAt": ["$cve.description.description_data.value", 0]
                    },
                    "cpe_match": {
                        "$arrayElemAt": ["$configurations.nodes.cpe_match.cpe23Uri", 0]
                    },
                }
            },
        ]
    )
    return list(cve_results)


def extract_versions_from_cpe_matches(cpe_matches: set, vendor: str, product: str) -> set:
    """
    Extracts unique versions from a set of CPE match strings.

    Args:
        cpe_matches (set): A set of CPE match strings.

    Returns:
        set: A sorted set of unique version strings extracted from the CPE matches.
    """
    versions = set()
    for cpe_match in cpe_matches:
        # Only keep versions related to the product
        if f":{product}:" in cpe_match:
            version = cpe_match.split(":")[5]
            if version not in ("*", "", "-"):
                versions.add(version)
    return sorted(versions)


def build_cve_data(cve_fields: list, vendor: str, product: str) -> list:
    """
    Extracts affected versions from CPE matches and formats the CVE data.

    Args:
        cve_fields (list): A list of dictionaries containing CVE ids, description and cpe23URI strings.

    Returns:
        list: A list of dictionaries containing CVE id, description, and affected versions.
    """

    cve_data = []
    for cve_field in cve_fields:
        versions = extract_versions_from_cpe_matches(cve_field["cpe_match"], vendor, product)
        cve_data.append(
            {
                "cve_id": cve_field["cve_id"],
                "cve_description": cve_field["cve_description"],
                "affected_versions": versions,
            }
        )
    return cve_data


def get_commit_hashes_and_tags_for_repo(vendor: str, product: str, repo_url: str) -> list:
    """
    Uses a bash script to clone the repository, iterate over commits to get hashes, messages and related tags

    Args:
        vendor (str): The vendor name.
        product (str): The product name.
        repository (str): The repository URL.

    Returns:
        list: A list of dictionaries containing commit hashes, descriptions, related versions.
    """

    # Get the default branch for the repository and use it to fetch commits
    default_branch_query = gql(
        """
        query($owner: String!, $name: String!) {
        repository(owner: $owner, name: $name) {
            defaultBranchRef {
            name
            }
        }
    }"""
    )
    default_branch = gql_client.execute(
        default_branch_query, variable_values={"owner": vendor, "name": product}
    )["repository"]["defaultBranchRef"]["name"]

    result = subprocess.run(
        ["bash", "src/orchid/commit_mining.sh", repo_url, default_branch],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True
    )

    processed = 0
    commits = []
    results = result.stdout.strip().split("\n")
    for line in results:
        print(f"Processed {processed} commits out of {len(results)}", end="\r")
        if line:
            parts = line.split("\t")
            if len(parts) == 3:
                commit_hash, commit_description, version = parts
                commits.append({
                    "commit_hash": commit_hash,
                    "commit_description": commit_description,
                    "version": version
                })
        processed += 1

    return commits


def pair_repos_to_cves():
    """
    Iterate over the vendor/product pairs from the CSV file, fetch CVEs from the NVD JSON file,
    get commit hashes from GitHub, and write the results to a JSON file.
    """

    output_data = {}

    # Read the CSV file to get the vendor/product pairs
    csv_reader = csv.DictReader(open(csv_file_path, mode="r", encoding="utf-8"))
    repo_data = [
        {"vendor": row["vendor"], "product": row["product"], "url": row["url"]} for row in csv_reader
    ]

    for repo in repo_data[:5]:
        try:
            vendor = repo["vendor"]
            product = repo["product"]
            repo = repo["url"]

            print("\033[92m" + "###########################################")
            print(f"Processing {vendor}/{product}...")
            print("###########################################" + "\033[0m")
            start_time = time.time()

            # Get CVEs for the vendor/product pair from the NVD JSON file
            cves = get_cves_for_vendor_product(vendor, product)

            if not cves:
                continue

            print(f"Found - {len(cves)} - CVEs")

            # Get CVE id, description, and affected versions from MongoDB
            cve_fields = fetch_cve_details_from_mongo(cves)
            print(f"Retrieved data on - {len(cve_fields)} - CVEs from MongoDB")
            # Format CVE data into a variable
            cve_data = build_cve_data(cve_fields, vendor, product)
            # Get commit hashes, messages and date for the vendor/product pair from GitHub
            commits = get_commit_hashes_and_tags_for_repo(vendor, product, repo)

            # Add the data to the output structure
            output_data[f"{vendor}/{product}"] = {
                "cves": cve_data,
                "commits": commits,
            }
            # Write the output data to a JSON file
            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=4)
            end_time = time.time()
            print(f"Processed {vendor}/{product} in {end_time - start_time:.2f} seconds\n")
        except Exception as e:
            print("\033[91m" + "###########################################")
            print(f"Error processing {vendor}/{product}: {e}")
            print("###########################################" + "\033[0m\n")
            continue

    # Cleanup and close MongoDB connection
    mongo_client.close()

if __name__ == "__main__":
    pair_repos_to_cves()