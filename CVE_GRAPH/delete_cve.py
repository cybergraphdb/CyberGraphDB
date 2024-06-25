from py2neo import Graph

# Connessione a Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", "scottdirT98"))

# Query per cancellare tutti i nodi e le relazioni associati ai CVE
delete_cve_query = """
MATCH (c:CVE)-[r]->(n)
DETACH DELETE c, r, n
"""
#-[r]->(n)
#, r, n
delete_cve = """
MATCH (c:CVE)
DETACH DELETE c
"""
delete_product = """
MATCH (c:CVE)
DETACH DELETE c
"""
# Esegui la query
graph.run(delete_cve_query)
graph.run(delete_cve)


print("Tutti i nodi e le relazioni associati ai CVE sono stati cancellati dal database Neo4j.")
