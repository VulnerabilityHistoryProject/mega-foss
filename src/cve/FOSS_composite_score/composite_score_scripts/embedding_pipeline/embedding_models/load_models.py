# load_models.py
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModel
from ollama import Client

from embedding_models.config_embedding_models import (
    DISTIL_BERT,
    SBERT_MINI_LM_L6_V2,
    SBERT_MINI_LM_L12_V2,
    SBERT_MPNET,
    GTE_LARGE,
    BGE_LARGE,
    E5_LARGE,
    ROBERTA_LARGE,
    OLLAMA_NOMIC_EMBED_TEXT
)

model_distil_bert = SentenceTransformer(DISTIL_BERT)
model_sbert_l6 = SentenceTransformer(SBERT_MINI_LM_L6_V2)
model_sbert_l12 = SentenceTransformer(SBERT_MINI_LM_L12_V2)
model_mpnet = SentenceTransformer(SBERT_MPNET)
model_gte = SentenceTransformer(GTE_LARGE)
model_e5 = SentenceTransformer(E5_LARGE)





model_ollama_client = Client(host='http://localhost:11434')

# For models like roberta-large (not sentence-transformers ready)
tokenizer_roberta_large = AutoTokenizer.from_pretrained(ROBERTA_LARGE)
model_roberta_large = AutoModel.from_pretrained(ROBERTA_LARGE)


# Load the tokenizer and model from Hugging Face
tokenizer_bge = AutoTokenizer.from_pretrained(BGE_LARGE)
model_bge_basic = AutoModel.from_pretrained(BGE_LARGE)

# Wrap it in a SentenceTransformer
class CustomBGEModel(SentenceTransformer):
    def __init__(self, model, tokenizer):
        super().__init__()
        self.model = model
        self.tokenizer = tokenizer

model_bge = CustomBGEModel(model=model_bge_basic,tokenizer=tokenizer_bge)
