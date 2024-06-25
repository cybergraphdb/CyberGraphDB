from neo4j import GraphDatabase


class Neo4jConnection:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self._driver.close()

    def list_databases(self):
        with self._driver.session() as session:
            result = session.run("SHOW DATABASES")
            return [record["name"] for record in result]


# Configura i dettagli di connessione
neo4j_uri = "bolt://localhost:7688"
neo4j_user = "neo4j"
neo4j_password = "scottdirT98"

# Crea un'istanza della classe di connessione
neo4j_conn = Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password)

# Ottieni e stampa l'elenco dei database
databases = neo4j_conn.list_databases()
for db_name in databases:
    print("Database:", db_name)

# Chiudi la connessione quando hai finito
neo4j_conn.close()
