from neo4j import GraphDatabase
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Neo4jConnection:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        logging.info("Database connection: SUCCESSFUL")

    def close(self):
        self._driver.close()

    def rename_relationships(self):
        with self._driver.session() as session:
            # Rename relationships between Technique and Mitigation
            session.write_transaction(
                self._rename_relationship,
                "Technique",
                "Mitigation",
                "HAS_TECHNIQUE",
                "HAS_MITIGATION",
            )
            # Rename relationships between Technique and Detection
            session.write_transaction(
                self._rename_relationship,
                "Technique",
                "Detection",
                "HAS_TECHNIQUE",
                "HAS_DETECTION",
            )
            # Rename relationships between Technique and Procedure
            session.write_transaction(
                self._rename_relationship,
                "Technique",
                "Procedure",
                "HAS_TECHNIQUE",
                "HAS_PROCEDURE",
            )

    @staticmethod
    def _rename_relationship(tx, start_node_label, end_node_label, old_rel, new_rel):
        query = f"""
        MATCH (start:{start_node_label})-[r:{old_rel}]->(end:{end_node_label})
        CALL apoc.refactor.rename.type(type(r), "{new_rel}") YIELD committedOperations
        RETURN committedOperations
        """
        result = tx.run(query)
        logging.info(f"Renamed relationships: {result.single()['committedOperations']}")

# Example usage
if __name__ == "__main__":
    conn = Neo4jConnection("bolt://localhost:7688", "neo4j", "")
    conn.rename_relationships()
    conn.close()
