import json
import os
import logging
from py2neo import Graph, Node, Relationship

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Connect to Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", ""))

def create_cve_graph(cve_data):
    try:
        containers = cve_data["containers"]["cna"]
        cve_id = cve_data["cveMetadata"]["cveId"]

        # Create the CVE node
        cve_node = Node("CVE", id=cve_id)
        graph.merge(cve_node, "CVE", "id")

        # Create nodes for each affected product
        for affected in containers.get("affected", []):
            product_versions = [version.get("version") for version in affected.get("versions", [])]
            logging.info(f"Product versions: {product_versions}")
            product_node = Node(
                "Product",
                name=affected.get("product", ""),
                vendor=affected.get("vendor", ""),
                versions=product_versions,
            )
            graph.merge(product_node, "Product", "name")

            # Create relationship between CVE and product
            relationship = Relationship(cve_node, "AFFECTS", product_node)
            graph.merge(relationship)

        # Description of the vulnerability
        for description in containers.get("descriptions", []):
            description_node = Node(
                "CVE_Description", lang=description.get("lang", ""), text=description.get("value", "")
            )
            graph.merge(description_node, "CVE_Description", "text")
            description_relationship = Relationship(
                cve_node, "DESCRIBED_BY", description_node
            )
            graph.merge(description_relationship)

        # Problem types
        for problem in containers.get("problemTypes", []):
            for problem_description in problem.get("descriptions", []):
                cweId = problem_description.get("cweId", "N/A")
                description = problem_description.get("description", "")
                problem_node = Node(
                    "CVE_ProblemType", cweId=cweId, description=description
                )
                graph.merge(problem_node, "CVE_ProblemType", "cweId")
                problem_relationship = Relationship(
                    cve_node, "HAS_PROBLEM_TYPE", problem_node
                )
                graph.merge(problem_relationship)

        # References
        for reference in containers.get("references", []):
            reference_node = Node("CVE_Reference", url=reference.get("url", ""))
            graph.merge(reference_node, "CVE_Reference", "url")
            reference_relationship = Relationship(
                cve_node, "HAS_REFERENCE", reference_node
            )
            graph.merge(reference_relationship)

    except KeyError as e:
        logging.error(f"Missing key in JSON: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def import_cve_data(base_path):
    # Iterate through all JSON files in the subdirectories
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        cve_data = json.load(f)
                        create_cve_graph(cve_data)
                except json.JSONDecodeError as e:
                    logging.error(f"JSON decode error in file {file_path}: {e}")
                except Exception as e:
                    logging.error(f"Unexpected error while reading file {file_path}: {e}")

if __name__ == "__main__":
    # Path to the directory containing the JSON files
    base_path = "cves/cves/2023"  # Replace with the correct path
    import_cve_data(base_path)
