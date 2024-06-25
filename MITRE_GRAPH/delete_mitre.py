from neo4j import GraphDatabase


class Neo4jConnection:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        print("\n[!] Database Connection: SUCCESSFUL")

    def close(self):
        self._driver.close()

    def delete_all_nodes_and_relationships(self):
        with self._driver.session() as session:
            session.write_transaction(self._delete_all_nodes_and_relationships)

    @staticmethod
    def _delete_all_nodes_and_relationships(tx):
        query = """
        MATCH (n)
        WHERE n:Malware OR n:Technique OR n:Mitigation OR n:Procedure OR n:Detection
        DETACH DELETE n
        """
        tx.run(query)


# Configura la connessione
uri = "bolt://localhost:7688"
user = "neo4j"
password = "scottdirT98"

# Crea una connessione al database
conn = Neo4jConnection(uri, user, password)

# Cancella tutti i nodi e le relazioni specificate
conn.delete_all_nodes_and_relationships()

# Chiudi la connessione
conn.close()
