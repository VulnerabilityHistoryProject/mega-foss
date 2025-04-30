from sentence_transformers import SentenceTransformer


from embedding_models import SBERT_MPNET


def embed_prompt_with_sbert_mpnet(prompt: str) -> list[str]:

    model = SentenceTransformer(SBERT_MPNET)

    # Generate normalized embedding (automatically normalized for cosine similarity)
    embedding = model.encode(prompt, normalize_embeddings=True).tolist()

    return embedding



if __name__ == "__main__":


    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    
    embedding_1 = embed_prompt_with_sbert_mpnet(prompt=test_prompt_1)
    print(embedding_1)
