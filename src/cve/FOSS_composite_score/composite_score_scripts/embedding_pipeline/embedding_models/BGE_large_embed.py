"""
Using BGE_Large embedding model.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""

import torch
import torch.nn.functional as F
from embedding_pipeline.embedding_models.load_models import tokenizer_bge,model_bge_basic


def embed_prompt_with_bge_large(prompt: str) -> list[float]:
    """
    Embeds a prompt using the BGE Large model and returns the embedding vector.

    Args:
        prompt (str): Text to be embedded.

    Returns:
        list[float]: List of floats representing the embedding of the prompt.
    """

    # Tokenize the input text
    inputs = tokenizer_bge(prompt, return_tensors="pt", padding=True, truncation=True, max_length=512)
    
    # Forward pass through the model (get the embeddings)
    with torch.no_grad():
        outputs = model_bge_basic(**inputs)
    
    # Use the [CLS] token embedding (first token) as sentence representation
    cls_embedding = outputs.last_hidden_state[:, 0, :]  # shape (batch_size, hidden_size)
    
    # Normalize the embedding (optional)
    normalized = F.normalize(cls_embedding, p=2, dim=1)
    
    # Convert the embedding to a list of floats
    embedding_list = normalized.squeeze().tolist()

    return embedding_list



if __name__ == "__main__":
    
    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    

    test_prompt_2 = "Flask offers suggestions, but doesn't enforce any dependencies or project layout. " \
    "It is up to the developer to choose the tools and libraries they want to use. " \
    "There are many extensions provided by the community that make adding new functionality easy."
    
    embedding_1 = embed_prompt_with_bge_large(prompt=test_prompt_1)
    embedding_2 = embed_prompt_with_bge_large(prompt=test_prompt_2)

    

    print(len(embedding_1))
   