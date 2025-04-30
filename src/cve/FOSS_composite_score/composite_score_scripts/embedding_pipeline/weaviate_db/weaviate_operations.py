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
from embedding_models.BGE_large_embed import



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
        for data_object, name_vector, combined_vector in data_objects:
            batch.add_object(
                properties=data_object,
                vector={
                "name_vector": name_vector,
                "combined_vector": combined_vector
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


