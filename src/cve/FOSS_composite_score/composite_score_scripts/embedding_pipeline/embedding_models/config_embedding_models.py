

from transformers import PreTrainedTokenizer, PreTrainedTokenizerFast
from sklearn.metrics.pairwise import cosine_similarity
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from captum.attr import IntegratedGradients
import numpy as np
from typing import TypedDict, Union

### Models for embedding FOSS project names
OLLAMA_NOMIC_EMBED_TEXT = 'nomic-embed-text'  # via Ollama only (not Hugging Face / Captum compatible)
DISTIL_BERT = 'distilbert-base-nli-stsb-mean-tokens'       # Available on Hugging Face, good for Captum
SBERT_MINI_LM_L6_V2 = 'sentence-transformers/all-MiniLM-L6-v2'
SBERT_MINI_LM_L12_V2 = 'sentence-transformers/all-MiniLM-L12-v2'  # ✅ Add this one


### Models for embedding FOSS project descriptions & name
BGE_LARGE = "BAAI/bge-large-en"
# Embedding from Instruction-Finetuned T5 (E5)
E5_LARGE = "intfloat/e5-large"
# SBERT with MPNet backbone (great general-purpose model)
SBERT_MPNET = "sentence-transformers/all-mpnet-base-v2"
# RoBERTa Large (usually fine-tuned for classification; limited in embedding use unless adapted)
ROBERTA_LARGE = "roberta-large"

### Control model that will be used for both FOSS project names and descriptions
GTE_LARGE = "thenlper/gte-large"



### typedict that defines the tokens and vectors that belong to a single prompt ###
class TokensAndVectors(TypedDict):
    """
    class that holds a list of tokens and a list of vectors

    Args:
        TypedDict (_type_): class from typing library in python for defining custom types
    """
    tokens: list[str]
    token_attributions: list[str]
    vectors: list[float]


def calc_token_attributions(input_text: str, model_name: str) -> None:
    """
    Calculates what tokens contributed most to the vector / had more weight.

    Args:
        input_text (str): Text to be embedded / tokenized.
        model_name (str): Name of embedding model for performing tokenization.
    """
    
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    # Tokenize the input text
  
    inputs = tokenizer(input_text, return_tensors="pt", padding=True, truncation=True)

    # Ensure model is in evaluation mode
    model.eval()

    # Define the Integrated Gradients method
    ig = IntegratedGradients(model)

    # Forward pass the input through the model
    input_ids = inputs["input_ids"]
    input_ids = input_ids.long()

    attention_mask = inputs["attention_mask"]
    outputs = model(input_ids, attention_mask=attention_mask)
    logits = outputs.logits

    # Calculate attributions using Integrated Gradients
    attributions, delta = ig.attribute(input_ids, target=logits.argmax(dim=-1), return_convergence_delta=True)

    # Convert attributions to a human-readable form
    attributions = attributions.squeeze().cpu().detach().numpy()

    # Get the tokens
    tokens = tokenizer.convert_ids_to_tokens(input_ids.squeeze().cpu().numpy())

    # Print the token and their attribution scores
    for token, attribution in zip(tokens, attributions):
        print(f"Token: {token}, Attribution: {attribution}")

def calc_cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    """
    Compute cosine similarity between two 1D vectors (lists).

    Args:
        vec1 (list[float]): first vector
        vec2 (list[float]): seconds vector

    Returns:
        float: cosine similarity
    """
    arr1 = np.array(vec1).reshape(1, -1)
    arr2 = np.array(vec2).reshape(1, -1)

    return float(cosine_similarity(arr1, arr2)[0][0])


### General Tokenizer function

def create_readable_tokens(prompt: str, tokenizer: Union[PreTrainedTokenizer,PreTrainedTokenizerFast]) -> list[str]:
    human_readable_tokens = tokenizer.tokenize(text=prompt)

    return human_readable_tokens



if __name__ == "__main__":
    pass