# Configuration file for embedding model dimensions
# This helps validate that embedding outputs match expected dimensions


from typing import Callable
NAMED_VEC_DIMENSIONS = {
    # Name vectors
    "ollama_nomic_name_vec": 768,
    "distil_bert_name_vec": 768,
    "sbert_minilm_l6_v2_name_vec": 384,
    "sbert_minilm_l12_v2_name_vec": 384,
    "gte_large_name_vec": 1024,
    
    # Description vectors
    "bge_large_description_vec": 1024,
    "e5_large_description_vec": 1024,
    "gte_large_description_vec": 1024,
    "roberta_large_description_vec": 1024,
    "sbert_mpnet_base_v2_description_vec": 768
}

# Utility functions for dimension validation

def validate_embedding_dimensions(vector_embedding: list[float], embedding_func: Callable[[str],list[float]]) -> list[float]:
    """
    Validates that an embedding vector has the expected dimensions
    
    Args:
    vector_embedding (list[float]): The embedding vector to validate.
    embedding_func (Callable[[str], list[float]]): The function used to generate the embedding.

    Returns:
        The embedding vector if dimensions match
        
    Raises:
        ValueError: If dimensions don't match or target_vector_name is unknown
    """

    func_name = embedding_func.__name__
    if not func_name in EMBEDDING_FUNC_TO_NAMED_VEC:
        raise ValueError(f"Unknown embedding function being used: {embedding_func}")
    print(func_name)
    target_vector_name = EMBEDDING_FUNC_TO_NAMED_VEC[func_name]
    
    if target_vector_name not in NAMED_VEC_DIMENSIONS:
        raise ValueError(f"Unknown target vector name: {target_vector_name}")
    
    expected_dim = NAMED_VEC_DIMENSIONS[target_vector_name]
    actual_dim = len(vector_embedding)
    
    if actual_dim != expected_dim:
        raise ValueError(
            f"Dimension mismatch for {target_vector_name}: "
            f"Expected {expected_dim}, got {actual_dim}"
        )
    
    return vector_embedding

# Example mapping between embedding functions and their target vector names
EMBEDDING_FUNC_TO_NAMED_VEC = {
    "embed_prompt_with_nomic": "ollama_nomic_name_vec",
    "embed_prompt_with_distil_bert": "distil_bert_name_vec",
    "embed_prompt_with_sbert_mini_l6": "sbert_minilm_l6_v2_name_vec",
    "embed_prompt_with_sbert_mini_l12": "sbert_minilm_l12_v2_name_vec",
    "embed_prompt_with_gte_large": "gte_large_name_vec",
    "embed_prompt_with_bge_large": "bge_large_description_vec",
    "embed_prompt_with_e5_large": "e5_large_description_vec",
    "embed_prompt_with_roberta_large": "roberta_large_description_vec",
    "embed_prompt_with_sbert_mpnet": "sbert_mpnet_base_v2_description_vec"
}

# Usage example:
# nomic_vec = embed_prompt_with_nomic(prompt=TEST_PROMPT)
# validate_embedding_dimensions(nomic_vec, "ollama_nomic_name_vec")

