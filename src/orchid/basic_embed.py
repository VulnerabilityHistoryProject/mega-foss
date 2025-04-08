import ollama
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

MODEL = 'nomic-embed-text'

embed1 = ollama.embeddings(model=MODEL, prompt='That came out of left field.')
embed2 = ollama.embeddings(model=MODEL, prompt='He struck out.')
embed3 = ollama.embeddings(model=MODEL, prompt='It is way too cold outside.')

vec1 = np.array(embed1['embedding']).reshape(1, -1)
vec2 = np.array(embed2['embedding']).reshape(1, -1)
vec3 = np.array(embed3['embedding']).reshape(1, -1)

print(f"embed1-embed2 : ${cosine_similarity(vec1, vec2)}")
print(f"embed2-embed3 : ${cosine_similarity(vec2, vec3)}")
print(f"embed1-embed3 : ${cosine_similarity(vec1, vec3)}")
