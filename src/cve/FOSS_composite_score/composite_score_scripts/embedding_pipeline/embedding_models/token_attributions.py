"""
token_attributions.py

This file exists to promote interpretability within the process of embedding FOSS project names
with different embedding models. The token attributions of every embedded FOSS project name and 
description will be included in each entry in the Weaviate database."


Author: @Trust Worthy
"""

import torch
from transformers import AutoTokenizer, AutoModel
from captum.attr import IntegratedGradients




# 2. Define embedding and attribution logic
def forward_func(input_ids, attention_mask):
    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
    return outputs.last_hidden_state[:, 0, :]  # [CLS] embedding (or mean pool)

def get_embedding_and_attribution(text: str) -> dict:
    tokens = tokenizer(text, return_tensors='pt', return_offsets_mapping=True)
    input_ids = tokens["input_ids"]
    attention_mask = tokens["attention_mask"]
    token_strs = tokenizer.convert_ids_to_tokens(input_ids[0])

    # Get embedding
    with torch.no_grad():
        embedding = forward_func(input_ids, attention_mask).squeeze(0).tolist()

    # 3. Integrated Gradients
    ig = IntegratedGradients(forward_func)
    attributions, _ = ig.attribute(inputs=input_ids,
                                   additional_forward_args=(attention_mask,),
                                   return_convergence_delta=False)
    
    # 4. Aggregate attributions per token
    token_attributions = attributions.sum(dim=-1).squeeze(0)
    token_attributions = token_attributions / torch.norm(token_attributions)
    token_attributions_list = token_attributions.tolist()

    # Skip special tokens
    final_tokens = []
    final_scores = []
    for tok, score in zip(token_strs, token_attributions_list):
        if tok not in tokenizer.all_special_tokens:
            final_tokens.append(tok)
            final_scores.append(score)

    return {
        "description": text,
        "embedding": embedding,
        "tokens": final_tokens,
        "token_attributions": [
            {"token": t, "score": round(s, 4)} for t, s in zip(final_tokens, final_scores)
        ]
    }






def get_token_attributions( model: AutoModel, tokenizer: AutoTokenizer,text: str, layer_to_extract: str = 'last_hidden_state'):
    
    model.eval()
    tokens = tokenizer(text, return_tensors='pt', return_offsets_mapping=True, padding=True, truncation=True)
    input_ids = tokens["input_ids"]
    attention_mask = tokens["attention_mask"]

    token_strs = tokenizer.convert_ids_to_tokens(input_ids[0])

    def forward_func(input_ids, attention_mask):
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        return outputs[layer_to_extract][:, 0, :]  # CLS token or pooled representation

    with torch.no_grad():
        embedding = forward_func(input_ids, attention_mask).squeeze(0).tolist()

    ig = IntegratedGradients(forward_func)
    attributions, _ = ig.attribute(inputs=input_ids,
                                   additional_forward_args=(attention_mask,),
                                   return_convergence_delta=False)

    token_attributions = attributions.sum(dim=-1).squeeze(0)
    token_attributions = token_attributions / torch.norm(token_attributions)
    token_attributions_list = token_attributions.tolist()

    final_tokens = []
    final_scores = []
    for tok, score in zip(token_strs, token_attributions_list):
        if tok not in tokenizer.all_special_tokens:
            final_tokens.append(tok)
            final_scores.append(score)

    return {
        "description": text,
        "embedding": embedding,
        "tokens": final_tokens,
        "token_attributions": [
            {"token": t, "score": round(s, 4)} for t, s in zip(final_tokens, final_scores)
        ]
    }



if __name__ == "__main__":

    # 1. Load model and tokenizer
    model_name = "distilbert-base-uncased"  # or any compatible transformer
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)
    model.eval()  # evaluation mode

    
    # 5. Example use
    result = get_embedding_and_attribution("Buffer overflow in libpng when parsing malformed PNG files.")
    print(result)