"""
weaviate_config.py

Configures cloud-based weaviate database for semantic embedding. Additionally, different functions are included to help
incorporate different models.
"""

import os
import weaviate
from weaviate.classes.init import Auth
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

    # # Best practice: store your credentials in environment variables
    # weaviate_url = os.environ["WEAVIATE_URL"]
    # weaviate_api_key = os.environ["WEAVIATE_API_KEY"]

    # Connect to Weaviate Cloud
    client = weaviate.connect_to_weaviate_cloud(
    cluster_url=WEAVIATE_URL,
    auth_credentials=Auth.api_key(WEAVIATE_API_KEY),
    )


    return client.is_ready()