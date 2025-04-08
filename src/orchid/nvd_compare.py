import ollama
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import os
from pydriller import Git


MODEL = 'nomic-embed-text'

# https://nvd.nist.gov/vuln/detail/CVE-2021-33815
# Actual fix commit should be 26d3c81bc5ef2f8c3f09d45eaeacfb4b1139a777
NVD_DESC = 'dwa_uncompress in libavcodec/exr.c in FFmpeg 4.4 allows an out-of-bounds array access because dc_count is not strictly checked.'
git_repo  = Git('/Users/andy/code/FFmpeg')

wrong_commits_string = """ee964145b5d229571e00bf6883a44189d02babe2
a1136ca973e3b216804d05bbf64fcc19ad0f14da
fa38573cd9ce4ab727f86f57c03b113cfd4c9d0a
b4f5da26517c101caa3a200c1cdf6553c3641f5f
a39cd8766fba7d8e4f7c177c13361058d4158ba0
2a31bf2a3507a311537721c39712fb318120595b
57b5b84e208ad61ffdd74ad849bed212deb92bc5
dd4b7badb416a5c2688da7310a7fe80fe4e4f209
3c1ecb057d7621e57968624aa15ad3e9efc819f7
30549294ef0f796d48b1ffa482bd9315d4dbb83c
a319c212bdefec27b3ee4055ad8555637a77e57a
0ae2ccff560cb23dc0a30c02234b25b9cd958975
9db5f82032b1629f5587c18d3152098507a7da35
3ea705767720033754e8d85566460390191ae27d
d1d18de6ade3ad5690f1eba9e005bab797d94ac6
12733c0cbd49077d3aac48007f674f14d1e15ccd
10173c0e58e557582dbd659f42c6aa164a8682db
42f9132218ca11a8e9a3c82a175b46bca092113e
53a3748ed23136615e488dc463b91aa57c0e9ec6
ff17d8b56ec87fe1516ddd49b0bdea81f22904af
9a3202a98b2e095b54dd784c3e01a09a676fc3fa
ac25b31ede03ef4f89175cb3c293ff6b5609e6c2
299c0b30a64a0746db2645c00a847930e01d58a4
6e127990fa9ea9776a74041080ff2a9ce8a39767
1400bd5a3921012911b80e5e209fb8a2591347e6
cdc90af00835297b8d5f3f06c47cf2c53267c3a3
34e6af9e204ca6bb18d8cf8ec68fe19b0e083e95
984e3398662d460e15904f9e4a6df9ef759070cb
20a160484f33e0d6b40ce905a89c5c6e8282704b
c6e2f0831c604c5cf7c2c17e018fb9c7cb620117
6b38101df5b2be231d67807e0f520c7d37292cea
04ee1b8da56407268ed1a49ac334d0c8965eaa7d
88896c46196e4cca2afa6df6e2bc37ecfc2c4e98
825ec16da955fd9c726d8e6c846cf9257a781a87
71db86d53b5c6872cea31bf714a1a38ec78feaba
db57a5370bd37105d389a45b04bf4970802407ec
795d2dc23b16a678d60a681e906aa87c14478597
f3c324a0fefd1a2dd4eff0be2e0d075d359d6235
8edc17b639c4ac47913c467107ffb43c67c64890
12e36a3dfdc619fcb479ae10e73679d69b19b2d7
febd022228660cb4b4d0e7b108bfec339b7dce92
79e0255956bc8fcdb143f39b2e45db77144ac017
84bf64d3598c98a748e609195358ea04b0cfd140
f4f386dd00e594dc90eb32ae872ae8e22b08d179
f26711978666cac479d77ecce9e7feb5fb8b702a
bcc07e2576cb723007bea1238afd019ae2d1b005
ab8cde6efa84e547ea07a0c47146091a0066c73c
"""
wrong_commits = wrong_commits_string.splitlines()


def commit_embedding(hash_str):
	commit = git_repo.get_commit(hash_str)
	patch_diff = ""
	for mf in commit.modified_files:
		patch_diff += mf.diff
		patch_diff += "\n"
	summary = commit.msg + patch_diff
	embed = ollama.embeddings(model=MODEL, prompt=summary)
	vec = np.array(embed['embedding']).reshape(1, -1)
	return vec

def nvd_embed():
	embed = ollama.embeddings(model=MODEL, prompt=NVD_DESC)
	vec = np.array(embed['embedding']).reshape(1, -1)
	return vec

nvd_embedding = nvd_embed()
correct_commit = '26d3c81bc5ef2f8c3f09d45eaeacfb4b1139a777'

print("Cosine similarity of correct fix")
print(cosine_similarity(commit_embedding(correct_commit), nvd_embedding))

print("Cosine similarity of WRONG fixes")
for wrong_commit in wrong_commits:
	sim = cosine_similarity(commit_embedding(wrong_commit), nvd_embedding)
	print(f"${wrong_commit}: ${sim}")
