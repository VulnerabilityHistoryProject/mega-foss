import os
import configparser
import pymongo
from motor.motor_asyncio import AsyncIOMotorClient

def mg_connect():
	config = configparser.ConfigParser()
	config.read(os.path.join(os.path.dirname(__file__), 'mongo.ini'))

	link = config['DEFAULT']['HOST'] if config['DEFAULT']['HOST'] != "localhost" else f"mongodb://localhost:{config['DEFAULT']['PORT']}/"

	return pymongo.MongoClient(link)[config['DEFAULT']['DATABASE']]

def async_mg_connect():
	config = configparser.ConfigParser()
	config.read(os.path.join(os.path.dirname(__file__), 'mongo.ini'))

	link = config['DEFAULT']['HOST'] if config['DEFAULT']['HOST'] != "localhost" else f"mongodb://localhost:{config['DEFAULT']['PORT']}/"

	return AsyncIOMotorClient(link)[config['DEFAULT']['DATABASE']]