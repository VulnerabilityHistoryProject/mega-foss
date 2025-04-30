"""
weaviate_config.py

Configures cloud-based weaviate database for semantic embedding. Additionally, different functions are included to help
incorporate different models.

Author: @Trust-Worthy
"""

import os
import weaviate
from weaviate.classes.init import Auth
import weaviate.classes.config as wvc_config
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
    local_client = weaviate.connect_to_local()

    print("Connected to local weaviate client--> is ready: " + local_client.is_ready())  # Should print: `True`
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
    print("Weaviate client is ready " + is_ready)
    return is_ready

def close_weaviate_client(client: weaviate.WeaviateClient) -> None:
    """
    Closes connection to the weaviate client and turns it off.

    Args:
        client (weaviate.WeaviateClient): _description_
    """
    print("Closing connection to weaviate client")
    client.close()


def create_weaviate_collection(client: weaviate.WeaviateClient) -> weaviate.collections.Collection:
    """
    Defines the embedding models that will be used for vectorizing the FOSS project names
    and the embedding models that will be used for the FOSS project descriptions.

    CVE/ CPE vendor:product combinations will be turned into vector queries to match against FOSS project names.
    CVE descriptions will be turned into vector queries to match against FOSS project descriptions.

    Args:
        client (weaviate.WeaviateClient): Initialized weaviate client.
    """

    # For Python client v4
    foss_wvc_collection = client.collections.create(


        name="FOSS_vectors",
        description="Open source projects with name and description",
        vectorizer_config=[
            ### Named Vectors for FOSS project names / CVE vendor:product combos
            wvc_config.Configure.NamedVectors.none(name="ollama_nomic_name_vec"),
            wvc_config.Configure.NamedVectors.none(name="sbert_minilm_name_vec"),
            wvc_config.Configure.NamedVectors.none(name="distil_bert_name_vec"),
            wvc_config.Configure.NamedVectors.none(name="minilm_l6_v2_name_vec"),
            wvc_config.Configure.NamedVectors.none(name="gte_large_name_vec"),

            ### Named Vectors for FOSS project descriptions / CVE descriptions
            wvc_config.Configure.NamedVectors.none(name="bge_large_description_vec"),
            wvc_config.Configure.NamedVectors.none(name="e5_large_description_vec"),
            wvc_config.Configure.NamedVectors.none(name="gte_large _description_vec"),
            wvc_config.Configure.NamedVectors.none(name="roberta_large_description_vec"),
            wvc_config.Configure.NamedVectors.none(name="sbert_mpnet_base_v2_description_vec"),
        ],
        properties=[
            wvc_config.Property(name="name", data_type=wvc_config.DataType.TEXT, description="Name of the project"),
            wvc_config.Property(name="description", data_type=wvc_config.DataType.TEXT, description="Project description"),
            wvc_config.Property(name="hash", data_type=wvc_config.DataType.TEXT,description="Hash of FOSS project name"),
            wvc_config.Property(name="tokens", data_type=wvc_config.DataType.TEXT,description="Tokens of FOSS description"),
            wvc_config.Property(name="token_attributions", data_type=wvc_config.DataType.TEXT,description="Weight of tokens numberically")
        ]
    )

    return foss_wvc_collection