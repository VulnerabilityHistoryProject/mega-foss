"""
Using BGE_Large embedding model.
Vectorized prompts will be stored in a weaviate vector database for later analysis.

Author: @Trust-Worthy


"""

from transformers import AutoTokenizer, AutoModel
import torch



from embedding_models import BGE_LARGE, TokensAndVectors
from embedding_models import create_readable_tokens, calc_cosine_similarity,calc_token_attributions

def embed_prompt_with_bge_large(prompt: str) -> TokensAndVectors:
    """
    Embeds a prompt (a few sentences) using the BGE Large model and tokenizes the prompt
    is a human readable format.

    Args:
        prompt (str): Text to be embedded and tokenized.

    Returns:
        TokensAndVectors: Returns a list of tokens and a list of vectors that belong to a single prompt.
    """
    ### Load Tokenizer and Model ###
    tokenizer = AutoTokenizer.from_pretrained(BGE_LARGE)
    model = AutoModel.from_pretrained(BGE_LARGE)


    ### Creates pytorch tensors representing token IDs ###
    inputs =  tokenizer(text=prompt, return_tensors="pt", padding=True, truncation=True)


    ### Tokenize & Store tokens ###
    readable_tokens: list[str] = create_readable_tokens(prompt=prompt,tokenizer=tokenizer)
    
    ### Create token attributions ###
    token_attributions = calc_token_attributions(BGE_LARGE,model_inputs=inputs)

    ### Embed ### 
    with torch.no_grad():
        outputs = model(**inputs)

        # Use the [CLS] token embedding as sentence representation
        cls_embedding = outputs.last_hidden_state[:, 0, :]

    # Convert to list if needed
    embedding = cls_embedding.squeeze().tolist()
    
    tokens_and_vectors = {
        "tokens": readable_tokens,
        "token_attributions": token_attributions,
        "vectors": embedding
    }
    return tokens_and_vectors



if __name__ == "__main__":
    
    test_prompt_1 = "Flask is a lightweight WSGI web application framework. " \
    "It is designed to make getting started quick and easy, with the ability to scale up to complex applications. " \
    "It began as a simple wrapper around Werkzeug and Jinja, and has become one of the most popular Python web application frameworks."
    

    test_prompt_2 = "Flask offers suggestions, but doesn't enforce any dependencies or project layout. " \
    "It is up to the developer to choose the tools and libraries they want to use. " \
    "There are many extensions provided by the community that make adding new functionality easy."
    
    embedding_1 = embed_prompt_with_bge_large(prompt=test_prompt_1)
    embedding_2 = embed_prompt_with_bge_large(prompt=test_prompt_2)

    print(embedding_1["token_attributions"])
    print(embedding_2["token_attributions"])

    vector_1 = embedding_1["vectors"]
    vector_2 = embedding_2["vectors"]

    sim = calc_cosine_similarity(vec1=vector_1,vec2=vector_2)
    print("cosine similarity is: " + str(sim))

    ### to-do ###
    # if the tokens are different when using the attribution code, I have to change the tokens that are produced
    # with that to match the attribution numbers