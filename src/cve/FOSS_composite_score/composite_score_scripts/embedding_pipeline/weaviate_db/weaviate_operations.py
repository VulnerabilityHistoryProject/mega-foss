"""
weaviate_inserts.py


This file inserts, reads, and queries the weaviate client.

Author: @Trust-Worthy


"""

from pathlib import Path
import weaviate
import weaviate.classes.config as wvc_config
import json
import hashlib

from embedding_models.nomic_embed import embed_prompt_with_nomic
from embedding_models.DISTIL_BERT_embed import embed_prompt_with_distil_bert


def create_data_object_and_store(json_file: str, collection: weaviate.collections.Collection) -> None:

    data_objects = []
    with open(json_file,'r') as file:

        # load the json data
        data = json.load(file)

        for project in data:
            

            ### get project name from json
            project_name = project["FOSS project name"]
            print("processing " + project_name + "...")

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
            data_object = {
                "name": project_name,
                "description": description,
                "foss_hash": hashed_foss_name
            }

            ### Create vector representations for FOSS project names ###
            nomic_embed_name = list [float] = embed_prompt_with_nomic(prompt=project_name)
            distil_bert_name = list[float] = embed_prompt_with_distil_bert(prompt=project_name)
            


            ### Create vector representations for FOSS project names + FOSS project descriptions ###

            ### Create vector represenations of the project names & the names + project descriptions
            vectorized_name_description: list[float] = ollama_nomic_embed(name_description)
            vectorized_name: list[float] = ollama_nomic_embed(project_name)
            

            data_objects.append((data_object, vectorized_name, vectorized_name_description))


    print("#############################################")
    print("#############################################")
    print("#############################################")
    print("#############################################")
    print("Starting to import the data into Weaviate!!!!")


    # Now batch import with error handling
    with collection.batch.dynamic() as batch:
        for data_object, nomic,sbert_l6,sbertl12,disti_bert,gte_large,bge_large,e5_large,roberta_large,sbert_mpnet in data_objects:
            batch.add_object(
                properties=data_object,
                vector={
                    "ollama_nomic_name_vec": nomic,
                    "sbert_minilm_l6_v2_name_vec" :sbert_l6,
                    "sbert_minilm_l12_v2_name_vec" :sbertl12,
                    "distil_bert_name_vec": disti_bert,
                    "gte_large_name_vec": gte_large,

                    ### Named Vectors for FOSS project descriptions +  CVE descriptions
                    "bge_large_description_vec" :bge_large,
                    "e5_large_description_vec" : e5_large,
                    "gte_large _description_vec" : gte_large,
                    "roberta_large_description_vec" : roberta_large,
                    "sbert_mpnet_base_v2_description_vec" : sbert_mpnet
                }
            )
            # Monitor errors during insertion
            if batch.number_errors > 10:
                print("Batch import stopped due to excessive errors.")
                break
            

    # Check for failed objects after batch completes
    failed_objects = collection.batch.failed_objects
    if failed_objects:
        print(f"Number of failed imports: {len(failed_objects)}")
        for i, obj in enumerate(failed_objects[:5]):  # Print first 5 failures
            print(f"Failed object {i+1}: {obj}")


