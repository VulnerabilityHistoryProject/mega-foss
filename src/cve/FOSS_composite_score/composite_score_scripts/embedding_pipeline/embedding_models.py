

from transformers import PreTrainedTokenizer

### Models for embedding FOSS project names
OLLAMA_NOMIC_EMBED_TEXT = 'nomic-embed-text'  # via Ollama only (not Hugging Face / Captum compatible)
DISTIL_BERT = 'distilbert-base-uncased'       # Available on Hugging Face, good for Captum
SBERT_MINI_LM_L6_V2 = 'sentence-transformers/all-MiniLM-L6-v2'
SBERT_MINI_LM_L12_V2 = 'sentence-transformers/all-MiniLM-L12-v2'  # ✅ Add this one


### Models for embedding FOSS project descriptions & name
# Beijing General Embedding (BGE)
BGE_LARGE = "BAAI/bge-large-en"
# Embedding from Instruction-Finetuned T5 (E5)
E5_LARGE = "intfloat/e5-large"
# SBERT with MPNet backbone (great general-purpose model)
SBERT_MPNET = "sentence-transformers/all-mpnet-base-v2"
# RoBERTa Large (usually fine-tuned for classification; limited in embedding use unless adapted)
ROBERTA_LARGE = "roberta-large"

### Control model that will be used for both FOSS project names and descriptions
GTE_LARGE = "thenlper/gte-large"


### General Tokenizer function

def create_readable_tokens(prompt: str, tokenizer: PreTrainedTokenizer) -> list[str]:
    human_readable_tokens = tokenizer.tokenize(text=prompt)

    return human_readable_tokens