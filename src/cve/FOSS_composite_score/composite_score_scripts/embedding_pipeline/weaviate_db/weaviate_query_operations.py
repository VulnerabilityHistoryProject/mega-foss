"""

weaviate_query_operations.py


This file contains functions used to conduct search queries using
the CVE/ CPE vendor:product combos and CVE descriptions.

Author: @Trust-Worthy

"""
from weaviate.classes.query import MetadataQuery
from weaviate.proto.v1.search_get_pb2 import SearchRequest
from weaviate.collections import Collection
from weaviate import WeaviateClient
from weaviate_config import retrieve_existing_weaviate_collection


from typing import TypedDict

class QueryMetrics(TypedDict):
    """
    QueryMetrics hold the name, distance, and certianty scores from a weaviate query

    Args:
        TypedDict (_type_): _description_
    """


def query_weaviate_collection(vector_query: list[float], target_vector_query: str, weaviate_client: WeaviateClient, collection: Collection) -> None:

    response = collection.query.near_vector(
        near_vector=vector_query,
        target_vector=target_vector_query,
        return_metadata=MetadataQuery(distance=True,certainty=True)
    )


    return response

    

def get_query_response_details() -> dict[str,]

