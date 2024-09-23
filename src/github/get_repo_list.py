import requests
import configparser
import os
import json

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'github_secrets.ini'))

# Built this query in the GitHub explorer: https://docs.github.com/en/graphql/overview/explorer
url = 'https://api.github.com/graphql'

acceptable_languages = [
	# 'C',
	'Rust',
]

acceptable_repos = []

def run_query(min_stars, max_stars):

	query_str = """
	{
		search(query: "is:public stars:%d..%d", type: REPOSITORY, first: 100) {
			repositoryCount
			edges {
			node {
				... on Repository {
				nameWithOwner
				stargazers {
					totalCount
				}
				diskUsage
				primaryLanguage {
					name
				}
				languages(first: 30) {
					edges {
					node {
						name
					}
					}
				}
				}
			}
			}
		}
	}
	"""
	query = { 'query' : query_str % (min_stars, max_stars) }
	print('-' * 80)
	print("Posting query...")
	api_token = config['DEFAULT']['GITHUB_KEY']
	headers = {'Authorization': 'token %s' % api_token}

	r = requests.post(url=url, json=query, headers=headers)
	json_response = json.loads(r.text)

	if 'data' in json_response.keys():
		data = json_response['data']
	else:
		print(r.text)
		exit()

	print(f"Repository count: {data['search']['repositoryCount']}")
	if int(data['search']['repositoryCount']) >= 100:
		print('WARNING: you might be missing some repos in this query. Adjust your star count cutoff')

	print(f"{'repo':40s}     {'stars':10s} {'diskUsage':10s}    gb")
	print('-' * 80)

	total_disk_usage = 0
	for edge in data['search']['edges']:
		name = edge['node']['nameWithOwner']
		stars = edge['node']['stargazers']['totalCount']
		diskUsage = edge['node']['diskUsage']
		if len(edge['node']['languages']['edges']) > 0:
			for lang in edge['node']['languages']['edges']:
				if lang['node']['name'] in acceptable_languages:
					print(f"{name:40s} {stars:10d} {diskUsage:10d}kb    {diskUsage / 1048576.0:10f}Gb")
					total_disk_usage += diskUsage
					global acceptable_repos
					acceptable_repos.append(name)

	return total_disk_usage

# GitHub limits us to 100 results, so I'm figuring out cutoffs. These numbers probably won't last beyond July 2024, so we'll need to figure these out again later. But they were easy by experimenting with the repositoryCount query in the GH API explorer.

total_disk_usage = 0
# total_disk_usage += run_query(76090,1000000)
# total_disk_usage += run_query(56000,76090)
# total_disk_usage += run_query(45000,56000)
# total_disk_usage += run_query(38500,45000)
# total_disk_usage += run_query(34400,38500)
# total_disk_usage += run_query(30950,34400)
# total_disk_usage += run_query(30000,30950)

# total_disk_usage += run_query(76090,1000000)

# UPDATING LATER
# Make sure that each of these queries has a "repositoryCount" of < 100

star_cutoffs = [
	10_000_000,
	 1_000_000,
	    90_000,
		80_000,
		70_000,
		60_000,
		50_000,
		45_000,
		42_000,
		38_000,
		36_000,
		34_000,
		32_000,
		30_000,
]

for i in range(0, len(star_cutoffs) - 1):
	total_disk_usage += run_query(star_cutoffs[i+1],star_cutoffs[i])

print('=' * 80)
for repo in acceptable_repos:
	print(repo)
print('=' * 80)
print(f"Total estimated disk usage: {total_disk_usage / 1048576.0:.2f}gb")
print(f"Total acceptable repos: {len(acceptable_repos)}")
