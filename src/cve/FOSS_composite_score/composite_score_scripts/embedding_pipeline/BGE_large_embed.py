"""
Using BGE_Large embedding model.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""

from transformers import AutoTokenizer, AutoModel
import torch
import torch.nn.functional as F


from embedding_models import BGE_LARGE, create_readable_tokens


def embed_prompt_with_bge_large(prompt: str) -> list[float]:
    
    ### Load Tokenizer and Model ###
    tokenizer = AutoTokenizer.from_pretrained(BGE_LARGE)
    model = AutoModel.from_pretrained(BGE_LARGE)


    ### Creates pytorch tensors representing token IDs ###
    inputs =  tokenizer(text=prompt, return_tensors="pt", padding=True, truncation=True)


    ### Tokenize & Store tokens ###
    readable_tokens: list[str] = create_readable_tokens(prompt=prompt,tokenizer=tokenizer)
    
    
    ### Embed ### 
    with torch.no_grad():
        outputs = model(**inputs)

        # Use the [CLS] token embedding as sentence representation
        cls_embedding = outputs.last_hidden_state[:, 0, :]

    # Convert to list if needed
    embedding = cls_embedding.squeeze().tolist()
    
    
    return embedding


# def calc_cosine_similarity() -> float:
#     embedding = F.normalize(cls_embedding, p=2, dim=1)



if __name__ == "__main__":
