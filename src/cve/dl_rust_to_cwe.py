"""
Downloads the Rust to CWE mapping Google Sheet as a CSV file.
"""
# Might want to change this to use the Drive API at some point if the sheet
# Is not going to be public.

import requests
import os

CWE_AND_RUST_SHEET = r"https://docs.google.com/spreadsheets/d/1JGei0TlPjIJVO8E0t_MqQcXFFn-qcEISHLBGJGBJfmQ"
output_csv = os.path.join(os.path.dirname(__file__), 'output/rust_to_cwe.csv')


def download_rust_to_cwe():
	try:
		dl_link = f"{CWE_AND_RUST_SHEET}/export?format=csv"
		res = requests.get(dl_link)
		res.raise_for_status()
		data = res.content.decode('utf-8')
		with open(output_csv, 'w') as f:
			f.write(data)
	except requests.exceptions.RequestException as e:
		print(f"Failed to download Rust to CWE mapping: {e}")
	except Exception as e:
		print(f"Failed to write Rust to CWE mapping: {e}")
	else:
		print(f"Successfully downloaded Rust to CWE mapping to {output_csv}")


def main():
	download_rust_to_cwe()


if __name__ == "__main__":
	main()
