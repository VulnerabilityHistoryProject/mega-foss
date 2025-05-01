"""
weaviate_config.py

Configures cloud-based weaviate database for semantic embedding. Additionally, different functions are included to help
incorporate different models.

Author: @Trust-Worthy
"""

import os
import weaviate
from weaviate.classes.init import Auth
from weaviate.classes.config import Configure, VectorDistances, Property, DataType
from dotenv import load_dotenv

def create_remote_weaviate_client() -> weaviate.WeaviateClient:
    """
    Gathers weaviate credentials via env variables and connects to remote weaviate client.

    Returns:
        bool: Returns true if the weaviate client is ready.
    """

    ### Load envs
    load_dotenv()
    WEAVIATE_URL = os.getenv("WEAVIATE_URL")
    WEAVIATE_API_KEY = os.getenv("WEAVIATE_API_KEY")


    # Connect to Weaviate Cloud
    remote_client = weaviate.connect_to_weaviate_cloud(
        cluster_url=WEAVIATE_URL,
        auth_credentials=Auth.api_key(WEAVIATE_API_KEY),
    )


    return remote_client

def connect_to_local_weaviate_client() -> weaviate.WeaviateClient:
    """
    Connects to a local weaviate database on the default port via the docker container.

    Returns:
        weaviate.WeaviateClient: _description_
    """
    print("Connecting to local client...")
    local_client = weaviate.connect_to_local()

    print("Connected to local weaviate client--> is ready: " + str(local_client.is_ready()))  # Should print: `True`
    return local_client

def verify_weaviate_client_ready(client: weaviate.WeaviateClient) -> bool:
    """
    Quickly verifies that the client is ready. This function will be used a "check" before performing search and append 
    operations.

    Args:
        client (weaviate.WeaviateClient): _description_

    Returns:
        bool: _description_
    """
    is_ready: bool = client.is_ready()
    print("Weaviate client is ready " + str(is_ready))
    return is_ready

def close_weaviate_client(client: weaviate.WeaviateClient) -> None:
    """
    Closes connection to the weaviate client and turns it off.

    Args:
        client (weaviate.WeaviateClient): _description_
    """
    print("Closing connection to weaviate client")
    client.close()


def create_weaviate_collection(client: weaviate.WeaviateClient, ) -> weaviate.collections.Collection:
    """
    Defines the embedding models that will be used for vectorizing the FOSS project names
    and the embedding models that will be used for the FOSS project descriptions.

    CVE/ CPE vendor:product combinations will be turned into vector queries to match against FOSS project names.
    CVE descriptions  will be turned into vector queries to match against FOSS project descriptions.

    COSINE is the distance metric being used.
    
    Args:
        client (weaviate.WeaviateClient): Initialized weaviate client.
    """

    # For Python client v4
    foss_wvc_collection = client.collections.create(


        name="FOSS_vectors",
        # Other configuration parameters...
        # vector_index_config=Configure.VectorIndex.hnsw(
        #     distance_metric=VectorDistances.COSINE  # Set distance metric to cosine
        #     ) ,  
        description="Open source projects with name and description",
        vectorizer_config=[
            ### Named Vectors for FOSS project names / CVE vendor:product combos
            Configure.NamedVectors.none(name="ollama_nomic_name_vec"),
            Configure.NamedVectors.none(name="sbert_minilm_l6_v2_name_vec"),
            Configure.NamedVectors.none(name="sbert_minilm_l12_v2_name_vec"),
            Configure.NamedVectors.none(name="distil_bert_name_vec"),
            Configure.NamedVectors.none(name="gte_large_name_vec"),

            ### Named Vectors for FOSS project descriptions / CVE descriptions
            Configure.NamedVectors.none(name="bge_large_description_vec"),
            Configure.NamedVectors.none(name="e5_large_description_vec"),
            Configure.NamedVectors.none(name="gte_large_description_vec"),
            Configure.NamedVectors.none(name="roberta_large_description_vec"),
            Configure.NamedVectors.none(name="sbert_mpnet_base_v2_description_vec"),
        ],
        properties=[
            Property(name="name", data_type=DataType.TEXT, description="Name of the project"),
            Property(name="description", data_type=DataType.TEXT, description="Project description"),
            Property(name="hash", data_type=DataType.TEXT,description="Hash of FOSS project name")
        ]
    )

    return foss_wvc_collection

def list_weaviate_collections(client: weaviate.WeaviateClient) -> None:

    try:
        # Method 1: Simple list of collection names
        collections = client.collections.list_all(simple=True)
        print("Collection names:")
        for name in collections.keys():
            print(f"- {name}")
    
        # Method 2: One-liner with list comprehension
        collection_names = list(client.collections.list_all(simple=True).keys())
        print(f"Collections: {', '.join(collection_names)}")
        
        
        
    finally:
        client.close()
        print("Weaviate client connection closed")

def inspect_specific_weaviate_collection(client: weaviate.WeaviateClient, collection_name: str) -> None:

    print(client.collections.get(collection_name))

def retrieve_existing_weaviate_collection(collection_name: str, weaviate_client:weaviate.WeaviateClient) -> weaviate.collections.Collection:
    """
    Use this method to retrieve an existing collection in a weaviate database.

    Args:
        collection_name (str): Name of the existing collection to retrieve
        weaviate_client (weaviate.WeaviateClient): Existing & initialized weaviate connected client.

    Returns:
        weaviate.collections.Collection: Weaviate python object to make requests to weaviate. This function does not 
        make a request to the weaviate database.
    """
    return weaviate_client.collections.get(collection_name)


if __name__ == "__main__":

    local_client = connect_to_local_weaviate_client()
    print(verify_weaviate_client_ready(local_client))

    close_weaviate_client(local_client)


