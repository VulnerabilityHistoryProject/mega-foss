import torch
from transformers import AutoTokenizer, AutoModel

from embedding_models import E5_LARGE



def embed_prompt_with_e5_large(prompt: str) -> list[float]:

    
    tokenizer = AutoTokenizer.from_pretrained(E5_LARGE)
    model = AutoModel.from_pretrained(E5_LARGE)

    model.eval()

    # Tokenize
    inputs = tokenizer(text=prompt, return_tensors="pt", padding=True, truncation=True)

    # Forward pass
    with torch.no_grad():
        outputs = model(**inputs)
        cls_embedding = outputs.last_hidden_state[:, 0]  # CLS token

    
    normalized = torch.nn.functional.normalize(cls_embedding, p=2, dim=1)
    embedding = normalized.squeeze().tolist()  # best for similarity


    return embedding


if __name__ == "__main__":

    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    
    embedding_1 = embed_prompt_with_e5_large(prompt=test_prompt_1)
    print(embedding_1)