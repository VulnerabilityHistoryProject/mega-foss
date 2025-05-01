"""
weaviate_inserts.py


This file inserts, reads, and queries the weaviate client.

Author: @Trust-Worthy


"""

import weaviate
import json
import hashlib

from embedding_models.nomic_embed import embed_prompt_with_nomic
from embedding_models.DISTIL_BERT_embed import embed_prompt_with_distil_bert
from embedding_models.SBERT_mini_lm_l6_embed import embed_prompt_with_sbert_mini_l6
from embedding_models.SBERT_mini_lm_l12_embed import embed_prompt_with_sbert_mini_l12

from embedding_models.BGE_large_embed import embed_prompt_with_bge_large
from embedding_models.E5_large_embed import embed_prompt_with_e5_large
from embedding_models.SBERT_mpnet_embed import embed_prompt_with_sbert_mpnet
from embedding_models.ROBERTA_large_embed import embed_prompt_with_roberta_large
from embedding_models.GTE_large_embed import embed_prompt_with_gte_large

def create_data_object_and_store(json_file: str) -> None:

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
            data_object: dict[str,str] = {
                "name": project_name,
                "description": description,
                "foss_hash": hashed_foss_name
            }

            ### Create vector representations for FOSS project names ###
            nomic_embed_name_vec = list [float] = embed_prompt_with_nomic(prompt=project_name)
            distil_bert_name_vec = list[float] = embed_prompt_with_distil_bert(prompt=project_name)
            sbert_l6_name_vec = list [float] = embed_prompt_with_sbert_mini_l6(prompt=project_name)
            sbert_l12_name_vec = list [float] = embed_prompt_with_sbert_mini_l12(prompt=project_name)

            ### Create vector representations for FOSS project names + FOSS project descriptions ###

            bge_large_name_description_vec = list[float] = embed_prompt_with_bge_large(prompt=name_description)
            e5_large_name_description_vec = list[float] = embed_prompt_with_e5_large(prompt=name_description)
            sbert_mpnet_name_description_vec = list[float] = embed_prompt_with_sbert_mpnet(prompt=name_description)
            roberta_large_name_description_vec = list[float] = embed_prompt_with_roberta_large(prompt=name_description)
            gte_large_name_description_vec = list[float] = embed_prompt_with_gte_large(prompt=name_description)

            data_objects.append(
                (
                data_object,
                ### Name vectors
                nomic_embed_name_vec,
                sbert_l6_name_vec,
                sbert_l12_name_vec,
                distil_bert_name_vec,
                gte_large_name_description_vec,

                ### Name + description vectors
                bge_large_name_description_vec,
                e5_large_name_description_vec,
                gte_large_name_description_vec,
                roberta_large_name_description_vec,
                sbert_mpnet_name_description_vec
                )
                
            )



def batch_import_data_obejcts(data_objects: list[tuple[dict,list[float]]] ,collection: weaviate.collections.Collection) -> None:
    print("#############################################")
    print("#############################################")
    print("#############################################")
    print("#############################################")
    print("Starting to batch import data objects into Weaviate!!!!")


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
        for i, obj in enumerate(failed_objects):  # Print first 5 failures
            print(f"Failed object {i+1}: {obj}")