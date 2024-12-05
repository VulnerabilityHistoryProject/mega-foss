import os
import psycopg2
import configparser
import pymongo


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

def mg_connect():
	config = configparser.ConfigParser()
	config.read(os.path.join(os.path.dirname(__file__), 'mongo.ini'))

	link = config['DEFAULT']['HOST'] if config['DEFAULT']['HOST'] != "localhost" else f"mongodb://localhost:{config["DEFAULT"]["PORT"]}/"

	return pymongo.MongoClient(link)[config['DEFAULT']['DATABASE']]
