import yaml
import glob
import json
import os
import numpy as np
import csv
# import ollama
# from sklearn.metrics.pairwise import cosine_similarity
from pydriller import Git
from sentence_transformers import SentenceTransformer,SimilarityFunction

os.environ["TOKENIZERS_PARALLELISM"] = "false"

VHP_VULNERABILITIES='/Users/andy/code/vulnerabilities'
YMLS=f"{VHP_VULNERABILITIES}/cves/ffmpeg/*.yml"
NVDCVE="/Users/andy/code/nvdcve/nvdcve"

# model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
# model = SentenceTransformer("sentence-transformers/all-mpnet-base-v2")
model = SentenceTransformer('nomic-ai/nomic-embed-text-v1.5', trust_remote_code=True)
print("Model loaded.")
repo=Git('/Users/andy/code/ffmpeg')

similarity_scores = []
num_vulns = 0

nvdcve_descs = []
fix_summaries = []

for cve_yml_filepath in glob.iglob(YMLS, recursive=True):
	yml = {}
	with open(cve_yml_filepath) as f:
		yml = yaml.safe_load(f.read())
	if len(yml) == 0:
		raise f"Malformed CVE: {cve_yml_filepath}"
	cve = yml['CVE']

	try:
		nvd_desc = None
		with open(f"{NVDCVE}/{yml['CVE']}.json") as f:
			nvdcve_json = json.load(f)
			nvd_desc = nvdcve_json['cve']['description']['description_data'][0]['value']
	except:
		print(f"{yml['CVE']} has no json")
		continue
	if not nvd_desc:
		raise f"No NVD desc for {yml['CVE']}"
	desc_embedding = model.encode(nvd_desc)
	summaries = []

	for fix in yml['fixes']:
		if len(fix['commit']) > 0:
			commit = repo.get_commit(fix['commit'])
			patch_diff = ""
			for mf in commit.modified_files:
				patch_diff += mf.diff
				patch_diff += "\n"
			summary = "classification" + commit.msg + patch_diff
			fix_summaries.append(summary)
	print('.', end='')

breakpoint()

with open('tmp/descs.csv', 'w') as f:
	csv_writer = csv.writer(f)
	csv_writer.writerows(nvdcve_descs)

with open('tmp/fix_summaries.csv', 'w') as f:
	csv_writer = csv.writer(f)
	csv_writer.writerows(fix_summaries)


print('Loaded data.')

	# fix_embeddings = model.encode(summaries)
	# similarities = model.similarity(desc_embedding, fix_embeddings)

	# for list in similarities:
	# 	for number in list:
	# 		similarity_scores.append(number.item())
	# num_vulns += 1

print(".")
print('---------------------')
print(f"num vulns: {num_vulns}")
print(f"mean:      {round(np.mean(similarity_scores), 2)}")
print(f"median:      {round(np.median(similarity_scores),2)}")
print(f"stdev:       {round(np.std(similarity_scores),2)}")
print(f"min..max     {round(np.min(similarity_scores),2)}..{round(np.max(similarity_scores),2)}")

print("Done!")
