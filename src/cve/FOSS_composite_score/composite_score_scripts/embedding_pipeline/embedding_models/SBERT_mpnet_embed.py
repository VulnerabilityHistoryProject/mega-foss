

from embedding_pipeline.embedding_models.load_models import model_mpnet


def embed_prompt_with_sbert_mpnet(prompt: str) -> list[float]:
    
    
    embedding = model_mpnet.encode(sentences=prompt,normalize_embeddings=True)
    
    
    embedding_list = embedding.tolist()
    

    
    return embedding_list




if __name__ == "__main__":


    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    
    embedding_1 = embed_prompt_with_sbert_mpnet(prompt=test_prompt_1)
    print(embedding_1)
    print(len(embedding_1))
