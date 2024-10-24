import os
import psycopg2
import configparser


def pg_connect() -> psycopg2.extensions.connection:
	config = configparser.ConfigParser()
	config.read(os.path.join(os.path.dirname(__file__), 'postgres.ini'))

	return psycopg2.connect(
		dbname=config['DEFAULT']['DATABASE'],
		user=config['DEFAULT']['USER'],
		password=config['DEFAULT']['PASS'],
		host=config['DEFAULT']['HOST'],
		port=config['DEFAULT'].get('PORT', None)
	)
