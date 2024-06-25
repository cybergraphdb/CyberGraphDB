import os
import json
from py2neo import Graph, Node, Relationship

# Connessione a Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", "scottdirT98"))

# Funzione per creare i nodi e le relazioni a partire dal JSON
def create_cve_graph(cve_data):
    try:
        containers = cve_data["containers"]["cna"]
        cve_id = cve_data["cveMetadata"]["cveId"]

        # Creazione del nodo CVE
        cve_node = Node("CVE", id=cve_id)
        graph.merge(cve_node, "CVE", "id")

        # Creazione del nodo per ciascun prodotto interessato
        for affected in containers["affected"]:
            product_versions = [version["version"] for version in affected["versions"]]
            print(product_versions)
            product_node = Node("Product", name=affected["product"], vendor=affected["vendor"], versions=product_versions)
            graph.merge(product_node, "Product", "name")

            # Creazione della relazione tra il CVE e il prodotto
            relationship = Relationship(cve_node, "AFFECTS", product_node)
            graph.merge(relationship)

        # Descrizione della vulnerabilità
        for description in containers["descriptions"]:
            description_node = Node("CVE_Description", lang=description["lang"], text=description["value"])
            graph.merge(description_node, "CVE_Description", "text")
            description_relationship = Relationship(cve_node, "DESCRIBED_BY", description_node)
            graph.merge(description_relationship)

        # Tipi di problema
        for problem in containers["problemTypes"]:
            try:
                for problem_description in problem["descriptions"]:
                    cweId = problem_description.get("cweId")  # Default to "N/A" if cweId is missing
                    description = problem_description.get("description", "")
                    problem_node = Node("CVE_ProblemType", cweId=cweId, description=description)
                    graph.merge(problem_node, "CVE_ProblemType", "cweId")
                    problem_relationship = Relationship(cve_node, "HAS_PROBLEM_TYPE", problem_node)
                    graph.merge(problem_relationship)
            except Exception as e:
                print(f"Error in ProblemType: {e}")
                pass

        # Riferimenti
        for reference in containers["references"]:
            reference_node = Node("CVE_Reference", url=reference["url"])
            graph.merge(reference_node, "CVE_Reference", "url")
            reference_relationship = Relationship(cve_node, "HAS_REFERENCE", reference_node)
            graph.merge(reference_relationship)

    except KeyError as e:
        print(f"Errore di chiave mancante nel JSON: {e}")
    except Exception as e:
        print(f"Errore imprevisto: {e}")

# Percorso della cartella contenente i file JSON
base_path = 'C:/Users/marco/python_version/cves/cves/2023'  # Sostituisci con il percorso corretto

# Itera attraverso tutti i file JSON nelle sottocartelle
for root, dirs, files in os.walk(base_path):
    for file in files:
        if file.endswith('.json'):
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r') as f:
                    cve_data = json.load(f)
                    create_cve_graph(cve_data)
            except json.JSONDecodeError as e:
                print(f"Errore di decodifica JSON nel file {file_path}: {e}")
            except Exception as e:
                print(f"Errore imprevisto durante la lettura del file {file_path}: {e}")
