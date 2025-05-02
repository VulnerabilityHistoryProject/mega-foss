"""
Using BGE_Large embedding model.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""

from embedding_models.load_models import model_bge


def embed_prompt_with_bge_large(prompt: str) -> list[float]:
    """
    Embeds a prompt using the BGE Large model and returns the embedding vector.

    Args:
        prompt (str): Text to be embedded.

    Returns:
        list[float]: List of floats representing the embedding of the prompt.
    """
    
    embedding = model_bge.encode(prompt,normalize_embeddings=True)
    
    
    embedding_list = embedding.tolist()
    

    
    return embedding_list



if __name__ == "__main__":
    
    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    

    # test_prompt_2 = "Flask offers suggestions, but doesn't enforce any dependencies or project layout. " \
    # "It is up to the developer to choose the tools and libraries they want to use. " \
    # "There are many extensions provided by the community that make adding new functionality easy."
    
    embedding_1 = embed_prompt_with_bge_large(prompt=test_prompt_1)
    # embedding_2 = embed_prompt_with_bge_large(prompt=test_prompt_2)

    # print(embedding_1["token_attributions"])
    # print(embedding_2["token_attributions"])
    # print(embedding_2["tokens"])
    # vector_1 = embedding_1["vectors"]
    # vector_2 = embedding_2["vectors"]

    print(embedding_1)
    # sim = calc_cosine_similarity(vec1=vector_1,vec2=vector_2)
    # print("cosine similarity is: " + str(sim))

    ### to-do ###
    # if the tokens are different when using the attribution code, I have to change the tokens that are produced
    # with that to match the attribution numbers