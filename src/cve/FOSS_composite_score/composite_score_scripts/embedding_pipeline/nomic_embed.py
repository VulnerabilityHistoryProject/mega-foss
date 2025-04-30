"""
Using nomic-embed-text-v1.5.

Returns:
    _type_: _description_
"""

import ollama

from embedding_models import NOMIC_EMBED_TXT


def embed_prompt_with_nomic(prompt: str) -> list[float]:

    response = ollama.embeddings(
        model=NOMIC_EMBED_TXT,
        prompt=prompt
    )

    return response['embedding']