"""
Using nomic-embed-text-v1.5 to embed short 2-3 word prompts.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""


from load_models import model_ollama_client, OLLAMA_NOMIC_EMBED_TEXT


def embed_prompt_with_nomic(prompt: str) -> list[float]:
    """
    Embed a prompt using nomic-embed-text-v1.5

    Args:
        prompt (str): Desired text to be embedded using the nomic-embed-text model.

    Returns:
        list[float]: Vectorized representation of the prompt. Either 768 vectors or 8192 depending on the model
    """

    response = model_ollama_client.embeddings(
        model=OLLAMA_NOMIC_EMBED_TEXT,
        prompt=prompt,
        
    )

    return response['embedding']


if __name__ == "__main__":

    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
        "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
        "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
        
    embedding_1 = embed_prompt_with_nomic(prompt=test_prompt_1)
    print(embedding_1)
    print(len(embedding_1))