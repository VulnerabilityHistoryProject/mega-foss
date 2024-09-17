import requests
import configparser
import os
import json

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'github_secrets.ini'))

# Built this query in the GitHub explorer: https://docs.github.com/en/graphql/overview/explorer
url = 'https://api.github.com/graphql'



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
			}
		}
		}
	}
	}
	"""
	query = { 'query' : query_str % (min_stars, max_stars) }

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

	# print(f"Repository count: {data['search']['repositoryCount']}")

	print(f"{'repo':50s}     {'stars':10s} {'diskUsage':10s}    gb")
	totalDiskUsage = 0
	for edge in data['search']['edges']:

		name = edge['node']['nameWithOwner']
		stars = edge['node']['stargazers']['totalCount']
		diskUsage = edge['node']['diskUsage']
		totalDiskUsage += diskUsage
		print(f"{name:50s} {stars:10d} {diskUsage:10d}kb    {diskUsage / 1048576.0:10f}Gb")
	return totalDiskUsage

# GitHub limits us to 100 results, so I'm figuring out cutoffs. These numbers probably won't last beyond July 2024, so we'll need to figure these out again later. But they were easy by experimenting with the repositoryCount query in the GH API explorer.

totalDiskUsage = 0
totalDiskUsage += run_query(76090,1000000)
totalDiskUsage += run_query(56000,76090)
totalDiskUsage += run_query(45000,56000)
totalDiskUsage += run_query(38500,45000)
totalDiskUsage += run_query(34400,38500)
totalDiskUsage += run_query(30950,34400)
totalDiskUsage += run_query(30000,30950)

print("-----")
print(f"Total estimated disk usage: {totalDiskUsage / 1048576.0:.2f}gb")
