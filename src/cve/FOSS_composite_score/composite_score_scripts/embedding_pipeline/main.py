"""
main.py

This script is the core of an interpretable NLP pipeline designed to explore semantic relationships 
between Common Vulnerabilities and Exposures (CVEs) and open-source software (FOSS) projects. 
The goal is to build an explainable embedding and attribution system that can support future efforts 
to match CVEs with responsible projects, patches, or components in an interpretable and transparent way.

The pipeline leverages a variety of state-of-the-art sentence embedding models and attention/attribution 
tools to analyze natural language descriptions, vulnerability reports, and FOSS metadata.

Embedding Models Used:
- nomic-embed-text
- BAAI/bge-large-en
- intfloat/e5-large-v2
- sentence-transformers/all-MiniLM-L6-v2
- sentence-transformers/all-MiniLM-L12-v2
- sentence-transformers/distilbert-base-nli-stsb-mean-tokens
- sentence-transformers/paraphrase-mpnet-base-v2
- Alibaba-NLP/gte-large
- roberta-large

Key components:
- Embedding generation and normalization for similarity search and clustering.
- Support for model-specific preprocessing and interpretation strategies.
- Embedding export to Weaviate-compatible formats for hybrid search and visualization.

This system is built for experimentation, insight, and extensibility in the intersection 
of vulnerability detection, FOSS analysis, and interpretable ML/NLP research.

Future Work:
- Attribution via the Captum Integrated Gradients to highlight influential tokens.
"""

from pathlib import Path
from weaviate.exceptions import WeaviateBaseError
from weaviate_db.weaviate_config import connect_to_local_weaviate_client
from weaviate_db.weaviate_config import verify_weaviate_client_ready
from weaviate_db.weaviate_config import close_weaviate_client
from weaviate_db.weaviate_config import create_weaviate_collection, list_weaviate_collections
from weaviate_db.weaviate_config import retrieve_existing_weaviate_collection


foss_proj_space_csv: Path = Path("../csv_github_data_cleaned/FOSS_projects_space.csv")
foss_name_description_json: Path = Path("../json_github_data_cleaned/github_repositories_final_ordered.json")






def main() -> None:

    try:
        local_client = connect_to_local_weaviate_client()
        print("weaviate client is ready: " + str(verify_weaviate_client_ready(local_client)))

        #foss_collection = create_weaviate_collection(local_client)
        list_weaviate_collections(local_client)
        
        
        
        
        
    except WeaviateBaseError as e:
        # Handle Weaviate-specific errors
        print(f"Weaviate error occurred: {e.message}")
        # You can handle different types of errors differently if needed
        
    except Exception as e:
        # Handle any other unexpected errors
        print(f"Unexpected error occurred: {str(e)}")
        
    finally:
        # This block will ALWAYS execute, even if exceptions occur
        if local_client is not None:
            close_weaviate_client(local_client)
            print("Weaviate client connection closed")
    
    



if __name__ == "__main__":

    main()