from sentence_transformers import SentenceTransformer
from embedding_models import SBERT_MINI_LM_L12_V2


def embed_prompt_with_sbert_mini_l12(prompt: str) -> list[float]:

    

    # Load the model
    model = SentenceTransformer(SBERT_MINI_LM_L12_V2)

    

    # Encode (automatically normalized for cosine similarity if needed)
    embedding = model.encode(sentences=prompt, normalize_embeddings=True)  # shape: (768,)

    # Optional: convert to list if saving to DB like Weaviate
    embedding_list = embedding.tolist()

    return embedding_list


if __name__ == "__main__":

    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
        "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
        "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
        
    embedding_1 = embed_prompt_with_sbert_mini_l12(prompt=test_prompt_1)
    print(len(embedding_1))