"""

weaviate_query_operations.py


This file contains functions used to conduct search queries using
the CVE/ CPE vendor:product combos and CVE descriptions.

Author: @Trust-Worthy

"""
from weaviate.classes.query import MetadataQuery
from weaviate.collections import Collection
from weaviate import WeaviateClient
from weaviate_config import retrieve_existing_weaviate_collection
from weaviate.collections.classes.internal import QueryReturn
from embedding_pipeline.embedding_models.model_dimensions import validate_embedding_dimensions

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


def query_weaviate_collection(vector_query: list[float], target_name_vector_query: str, weaviate_collection: Collection) -> QueryReturn:
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
    

    response = weaviate_collection.query.near_vector(
        near_vector=vector_query,
        target_vector=target_name_vector_query, ### what named vector I want to query against (10 options)
        limit=3,
        return_metadata=MetadataQuery(distance=True,certainty=True)
    )


    return response
# Safe query function that validates dimensions before querying
def safe_query_weaviate_collection(vector_query: list[float], target_name_vector_query: str, weaviate_client, collection_name: str):
    """
    Query Weaviate collection with dimension validation
    
    Args:
        vector_query: The embedding vector to query with
        target_name_vector_query: The name of the target vector in Weaviate
        weaviate_client: The Weaviate client
        collection_name: The name of the collection to query
        
    Returns:
        Query results or None if validation fails
    """
    try:
        # Validate dimensions before querying
        validate_embedding_dimensions(vector_query, target_name_vector_query)
        
        # If validation passes, proceed with query
        from embedding_pipeline.weaviate_db.weaviate_query_operations import query_weaviate_collection
        return query_weaviate_collection(
            vector_query=vector_query,
            target_name_vector_query=target_name_vector_query,
            weaviate_client=weaviate_client,
            collection_name=collection_name
        )
    except ValueError as e:
        print(f"Validation error: {e}")
        return None
    except Exception as e:
        print(f"Query error: {e}")
    

def get_query_vector_responses(response: QueryReturn) -> list[VectorResponse]:
    """
    Use this method to parse the reponse into a more readable format. 
    This method will get the name of the FOSS project that was most clearly related, it's cosine distance,
    and it's certainty.

    Args:
        response (QueryReturn): object containing all of the vectors nearest to the query using cosine similarity.

    Returns:
        list[VectorResponse]: List containing each responses detailed metrics: name of FOSS project, consine similarity (distance),
        and certainty.
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

