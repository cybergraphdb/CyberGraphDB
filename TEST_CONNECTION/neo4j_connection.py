from neo4j import GraphDatabase
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Neo4jConnection:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        logging.info("Successfully connected to the database.")

    def close(self):
        self._driver.close()
        logging.info("Database connection closed.")

    def list_databases(self):
        with self._driver.session() as session:
            result = session.run("SHOW DATABASES")
            logging.info("Retrieved list of databases.")
            return [record["name"] for record in result]

# Configure connection details
neo4j_uri = "bolt://localhost:7688"
neo4j_user = "neo4j"
neo4j_password = ""

# Create an instance of the connection class
neo4j_conn = Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password)

# Get and print the list of databases
try:
    databases = neo4j_conn.list_databases()
    for db_name in databases:
        logging.info("Database: %s", db_name)
finally:
    # Close the connection when done
    neo4j_conn.close()
