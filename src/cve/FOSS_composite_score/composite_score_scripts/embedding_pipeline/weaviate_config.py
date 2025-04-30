"""
weaviate_config.py

Configures cloud-based weaviate database for semantic embedding. Additionally, different functions are included to help
incorporate different models.
"""

import os
import weaviate
from weaviate.classes.init import Auth
import weaviate.classes.config as wvc_config
from dotenv import load_dotenv

def config_weaviate_db() -> bool:
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
    client = weaviate.connect_to_weaviate_cloud(
        cluster_url=WEAVIATE_URL,
        auth_credentials=Auth.api_key(WEAVIATE_API_KEY),
    )


    return client.is_ready()

def define_weaviate_schema(client: weaviate.WeaviateClient) -> None:
    ""

    # For Python client v4
    foss_wvc_collection = client.collections.create(
        name="FOSSProject",
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
            wvc_config.Configure.NamedVectors.none(name="gte_large  _description_vec"),
            wvc_config.Configure.NamedVectors.none(name="roberta_large_description_vec"),
            wvc_config.Configure.NamedVectors.none(name="sbert_mpnet_base_v2_description_vec"),
        ],
        properties=[
            wvc_config.Property(name="name", data_type=wvc_config.DataType.TEXT, description="Name of the project"),
            wvc_config.Property(name="description", data_type=wvc_config.DataType.TEXT, description="Project description"),
            wvc_config.Property(name="foss_hash", data_type=wvc_config.DataType.TEXT,description="Hash of FOSS project name")
        ]
    )