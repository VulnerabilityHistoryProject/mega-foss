from transformers import AutoTokenizer, AutoModel
import torch
import torch.nn.functional as F
from embedding_pipeline.embedding_models.load_models import tokenizer_roberta_large, model_roberta_large


def embed_prompt_with_roberta_large(prompt: str) -> list[float]:

   

    model_roberta_large.eval()


    ### Creates pytorch tensors representing token IDs ###
    inputs =  tokenizer_roberta_large(
        text=prompt, 
        max_length= 512, 
        return_tensors="pt", 
        padding=True, 
        truncation=True
    )


    ### Embed ### 
    with torch.no_grad():
        outputs = model_roberta_large(**inputs)

        # Use the [CLS] token embedding as sentence representation
        cls_embedding = outputs.last_hidden_state[:, 0, :]


    normalized = F.normalize(cls_embedding, p=2, dim=1)
    embedding = normalized.squeeze().tolist()  # best for similarity

    
    return embedding


if __name__ == "__main__":
    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
        "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
        "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
        
    embedding_1 = embed_prompt_with_roberta_large(prompt=test_prompt_1)
    print(embedding_1)
    print(len(embedding_1))