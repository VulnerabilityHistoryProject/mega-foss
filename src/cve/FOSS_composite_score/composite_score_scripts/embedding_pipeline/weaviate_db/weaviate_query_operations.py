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
from weaviate.collections.classes.internal import QueryReturn

from typing import TypedDict

class VectorResponse(TypedDict): 
    """
    QueryMetrics hold the name, distance, and certianty scores from a weaviate query.

    Args:
        TypedDict (_type_): built in type from the typing library

    Components: 
        foss_project_name: Name of the FOSS project that was returned
        vector_distance: Cosine similarity metric. Interpretation below:

                                0 to 0.1: Extremely similar vectors (almost identical)
                                0.1 to 0.5: Highly similar vectors
                                0.5 to 1.0: Moderately similar vectors
                                1.0: Vectors are orthogonal (no similarity)
                                1.0 to 2.0: Vectors are increasingly dissimilar
                                2.0: Vectors are completely opposite

        vector_certainty: The certainty value is a normalized similarity score that ranges between 0 and 1, where:
                                
                                1.0 means the vectors are identical (perfect match)
                                0.0 means the vectors are perfect opposites
                                Values in between represent varying degrees of similarity


    """
    foss_project_name: str
    vector_distance: float
    vector_certainty: float


def query_weaviate_collection(vector_query: list[float], target_vector_query: str, weaviate_client: WeaviateClient, collection_name: str) -> QueryReturn:
    """
    Use method to query a specific weavaite collection in a specified database.

    Args:
        vector_query (list[float]): Vectorized representation of CVE/ CPE related query.
        target_vector_query (str): Name of embedding model to query against. There are 9 models (10 entires) of each FOSS proejct / description
        weaviate_client (WeaviateClient): Established weaviate client.
        collection_name (str): Name of collection to query. Collection must exist in the weaviate client.

    Returns:
        QueryReturn: object containing all of the vectors nearest to the query using cosine similarity.
    """
    weaviate_collection: Collection = retrieve_existing_weaviate_collection(collection_name=collection_name,weaviate_client=weaviate_client)

    response = weaviate_collection.query.near_vector(
        near_vector=vector_query,
        target_vector=target_vector_query,
        return_metadata=MetadataQuery(distance=True,certainty=True)
    )


    return response

    

def get_query_vector_responses(response: QueryReturn) -> list[VectorResponse]:
    """
    Use this method to parse the reponse into a more readable format. 
    This method will get the name of the FOSS project that was most clearly related, it's cosine distance,
    and it's certainty.

    Args:
        response (QueryReturn): _description_

    Returns:
        list[VectorResponse]: _description_
    """
    vector_responses = []

    for obj in response.objects:

        VectorResponse = {
            "foss_project_name": obj.properties['name'],
            "vector_distance": obj.metadata.distance,
            "vector_certainty": obj.metadata.certainty
        }

        vector_responses.append(VectorResponse)

    return vector_responses

