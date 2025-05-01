"""
weaviate_inserts.py

This script creates a data pipeline for embedding and storing FOSS project metadata in a Weaviate vector database.
Each project is hashed and embedded using 9 different SOTA embedding models. Vectors are inserted into a Weaviate
collection with named vector support for easy retrieval and interpretability.

Author: @Trust-Worthy
"""


import weaviate
import json
import hashlib
from dataclasses import dataclass

from embedding_models.nomic_embed import embed_prompt_with_nomic
from embedding_models.DISTIL_BERT_embed import embed_prompt_with_distil_bert
from embedding_models.SBERT_mini_lm_l6_embed import embed_prompt_with_sbert_mini_l6
from embedding_models.SBERT_mini_lm_l12_embed import embed_prompt_with_sbert_mini_l12

from embedding_models.BGE_large_embed import embed_prompt_with_bge_large
from embedding_models.E5_large_embed import embed_prompt_with_e5_large
from embedding_models.SBERT_mpnet_embed import embed_prompt_with_sbert_mpnet
from embedding_models.ROBERTA_large_embed import embed_prompt_with_roberta_large
from embedding_models.GTE_large_embed import embed_prompt_with_gte_large



@dataclass
class FOSSProjectDataObject:
    """
    FOSSProjectDataObject is a dataclass that stores the weaviate data object which is used to
    define the schema in the vector database. This dataclass also stores all 10 of the embedded 
    and vectorized representations of the FOSS project name and FOSS project name + descriptions.
    """
    weaviate_data_object: dict[str, str]
    nomic_name_vec: list[float]
    sbert_l6_name_vec: list[float]
    sbert_l12_name_vec: list[float]
    distil_bert_name_vec: list[float]
    gte_name_vec: list[float]

    bge_description_vec: list[float]
    e5_description_vec: list[float]
    gte_description_vec: list[float]
    roberta_description_vec: list[float]
    sbert_mpnet_description_vec: list[float]

def create_data_object(json_file: str) -> list[FOSSProjectDataObject]:

    data_objects = []
    with open(json_file,'r') as file:

        # load the json data
        data = json.load(file)

        for project in data:
            

            ### get project name from json
            project_name = project["FOSS project name"]
            print("processing & embedding " + project_name + "...")

            ### Hash project name
            hash_object = hashlib.sha1(project_name.encode())
            hashed_foss_name = hash_object.hexdigest()

            ### Get project description from json
            description = project["description"]

            ### Create combined string for vectorization
            if not project_name:
                print(f"Skipping entry with missing name: {project}")
                continue

            name_description = project_name + " " + (description or "")
            
            
            # Create data object which will be used for Weaviate
            data_object: dict[str,str] = {
                "name": project_name,
                "description": description,
                "foss_hash": hashed_foss_name
            }

            ### Create vector representations for FOSS project names ###
            nomic_name_vec, sbert_l6_name_vec, sbert_l12_name_vec, distil_bert_name_vec, gte_large_name_vec = embed_name(project_name=project_name)

            ### Create vector representations for FOSS project names + FOSS project descriptions ###
            bge_large_name_description_vec, e5_large_name_description_vec, sbert_mpnet_name_description_vec , roberta_large_name_description_vec, gte_large_name_description_vec  = embed_name_description(name_description=name_description)


            data_objects.append(

                FOSSProjectDataObject(
                    weaviate_data_object=data_object,

                    nomic_name_vec=nomic_name_vec,
                    sbert_l6_name_vec= sbert_l6_name_vec,
                    sbert_l12_name_vec= sbert_l12_name_vec,
                    distil_bert_name_vec=distil_bert_name_vec,
                    gte_name_vec= gte_large_name_vec,

                    bge_description_vec= bge_large_name_description_vec,
                    e5_description_vec= e5_large_name_description_vec,
                    gte_description_vec= gte_large_name_description_vec,
                    roberta_description_vec= roberta_large_name_description_vec,
                    sbert_mpnet_description_vec= sbert_mpnet_name_description_vec
                )  
            )

    return data_objects

def embed_name(project_name: str) -> tuple[list[float]]:
    """
    Helper function to embed the project name using all 5 embedding models that are suited
    for short text (1-3 words).

    Args:
        project_name (str): Name of Foss project to embed.

    Returns:
        tuple[list[float]]: Project name embedded with all 5 different models.
    """
    return (
        embed_prompt_with_nomic(prompt=project_name),
        embed_prompt_with_distil_bert(prompt=project_name),
        embed_prompt_with_sbert_mini_l6(prompt=project_name),
        embed_prompt_with_sbert_mini_l12(prompt=project_name),
        embed_prompt_with_gte_large(prompt=project_name)
    )

def embed_name_description(name_description: str) -> tuple[list[float]]:
    """
    Helper function to embed the project name + description using all 5 embedding models that are suited
    for multi-sentences.

    Args:
        name_description (str): Name of Foss project appended to the description of the Foss project.

    Returns:
        tuple[list[float]]: Project name + description embedded with all 5 different models.
    """
    return (
        embed_prompt_with_bge_large(prompt=name_description),
        embed_prompt_with_e5_large(prompt=name_description),
        embed_prompt_with_sbert_mpnet(prompt=name_description),
        embed_prompt_with_roberta_large(prompt=name_description),
        embed_prompt_with_gte_large(prompt=name_description)
    )


def batch_import_data_objects(data_objects: list[FOSSProjectDataObject] ,collection: weaviate.collections.Collection) -> None:
    """
    Imports both the  name embeddings for the FOSS projects as well as the 
    name + description embeddings for all the FOSS projects.

    Args:
        data_objects (list[FOSSProjectDataObject]): dataclass containing the 10 embedded vectors.
        collection (weaviate.collections.Collection): Weaviate class used for designating parts of a weaviate database.
    """

    banner("Starting to batch import data objects into Weaviate!!!!")


    # Now batch import with error handling
    with collection.batch.dynamic() as batch:
        for obj in data_objects:
            print("Importing" + obj.weaviate_data_object["name"] + "...")
            batch.add_object(
                properties=obj.weaviate_data_object,
                vector={
                    "ollama_nomic_name_vec": obj.nomic_name_vec,
                    "sbert_minilm_l6_v2_name_vec": obj.sbert_l6_name_vec,
                    "sbert_minilm_l12_v2_name_vec": obj.sbert_l12_name_vec,
                    "distil_bert_name_vec": obj.distil_bert_name_vec,
                    "gte_large_name_vec": obj.gte_name_vec,

                    "bge_large_description_vec": obj.bge_description_vec,
                    "e5_large_description_vec": obj.e5_description_vec,
                    "gte_large_description_vec": obj.gte_description_vec,
                    "roberta_large_description_vec": obj.roberta_description_vec,
                    "sbert_mpnet_base_v2_description_vec": obj.sbert_mpnet_description_vec
                }
            )
            print("Successfully imported" + obj.weaviate_data_object["name"] + "...")
            # Monitor errors during insertion
            if batch.number_errors > 10:
                print("Batch import stopped due to excessive errors.")
                break
            

    # Check for failed objects after batch completes
    failed_objects = collection.batch.failed_objects

    if failed_objects:
        print(f"Number of failed imports: {len(failed_objects)}")
        for i, obj in enumerate(failed_objects):  # Print first 5 failures
            print(f"Failed object {i+1}: {obj}")


def banner(msg: str):
    """Print a banner with the given message, surrounded by hash lines."""
    print("\n" + "#" * 50)
    print(msg)
    print("#" * 50 + "\n")
