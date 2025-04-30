"""
Using nomic-embed-text-v1.5 to embed short 2-3 word prompts.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""

import ollama

from config_embedding_models import OLLAMA_NOMIC_EMBED_TEXT


def embed_prompt_with_nomic(prompt: str) -> list[float]:
    """
    Embed a prompt using nomic-embed-text-v1.5

    Args:
        prompt (str): Desired text to be embedded using the nomic-embed-text model.

    Returns:
        list[float]: Vectorized representation of the prompt. Either 768 vectors or 8192 depending on the model
    """

    response = ollama.embeddings(
        model=OLLAMA_NOMIC_EMBED_TEXT,
        prompt=prompt
    )

    return response['embedding']