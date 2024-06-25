import logging
import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_detection_table(soup, neo4j_conn, technique_name):
    table_selector = "table.datasources-table tbody tr"
    table_rows = soup.select(table_selector)

    if not table_rows:
        logging.warning("Detection table not found.")
        return

    logging.info("Detection used by technique: %s", technique_name)

    prev_data_source = "N/A"
    prev_data_component = "N/A"
    prev_detects = "N/A"

    for row in table_rows:
        data_source_elements = row.select("td:nth-child(2) a")
        data_source_element = data_source_elements[0] if data_source_elements else None
        data_source = data_source_element.get_text() if data_source_element else prev_data_source

        data_component_elements = row.select("td:nth-child(3) a")
        data_component_element = data_component_elements[0] if data_component_elements else None
        data_component = data_component_element.get_text() if data_component_element else prev_data_component

        detects_elements = row.select("td:nth-child(4) p")
        detects_element = detects_elements[0] if detects_elements else None
        detects = detects_element.get_text() if detects_element else prev_detects

        logging.info("Data Source: %s", data_source)
        logging.info("Data Component: %s", data_component)
        logging.info("Detect Description: %s", detects)

        prev_data_source = data_source
        prev_data_component = data_component
        prev_detects = detects

        neo4j_conn.create_detection_node(data_source, data_component, detects)
        neo4j_conn.create_relationship_technique_detection(technique_name, data_source)

def scrape_procedure_table(soup):
    table = soup.find("table", class_="table table-bordered table-alternate mt-2")
    if not table:
        logging.warning("Procedure table not found.")
        return []

    procedures = []

    rows = table.find("tbody").find_all("tr")
    for row in rows:
        columns = row.find_all("td")
        procedure_id = columns[0].find("a").text.strip()
        procedure_name = columns[1].find("a").text.strip()
        procedure_description = columns[2].find("p").text.strip()

        procedure_data = {
            "ID": procedure_id,
            "procedure": procedure_name,
            "Description": procedure_description,
        }
        procedures.append(procedure_data)

    return procedures

def scrape_mitigation_table(soup, neo4j_conn, technique_name):
    mitigations_header = soup.find("h2", id="mitigations")
    if not mitigations_header:
        logging.warning("Mitigations header not found.")
        return []

    table = mitigations_header.find_next("table", class_="table table-bordered table-alternate mt-2")
    if not table:
        logging.warning("Mitigation table not found.")
        return []

    mitigations = []

    rows = table.find("tbody").find_all("tr")
    for row in rows:
        columns = row.find_all("td")
        mitigation_id = columns[0].find("a").text.strip()
        mitigation_name = columns[1].find("a").text.strip()
        mitigation_description = columns[2].find("p").text.strip()

        mitigation_data = {
            "ID": mitigation_id,
            "Mitigation": mitigation_name,
            "Description": mitigation_description,
        }
        mitigations.append(mitigation_data)

        logging.info("ID: %s", mitigation_id)
        logging.info("Mitigation: %s", mitigation_name)
        logging.info("Description: %s", mitigation_description)

        neo4j_conn.create_mitigation_node(mitigation_id, mitigation_name, mitigation_description)
        neo4j_conn.create_relationship_technique_mitigation(technique_name, mitigation_name)

def explore_technique_url(neo4j_conn, malware_name, technique_type, technique_name, technique_id, technique_url, technique_use, span_href):
    try:
        response = requests.get(technique_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        description_element = soup.select_one(".description-body")
        if description_element:
            technique_description = description_element.get_text().strip()
            logging.info("Technique Description: %s", technique_description)
            neo4j_conn.create_technique_node(
                technique_type, technique_name, technique_id, technique_url, span_href, technique_description
            )
            neo4j_conn.create_relationship_malware_technique(malware_name, technique_name, technique_use)
        else:
            logging.warning("Technique description not found.")

        extract_detection_table(soup, neo4j_conn, technique_name)
        procedures_data = scrape_procedure_table(soup)

        logging.info("Technique Procedures")
        for procedure in procedures_data:
            logging.info("ID: %s", procedure["ID"])
            logging.info("Procedure: %s", procedure["procedure"])
            logging.info("Description: %s", procedure["Description"])
            neo4j_conn.create_procedure_node(procedure["ID"], procedure["procedure"], procedure["Description"])
            neo4j_conn.create_relationship_technique_procedure(technique_name, procedure["procedure"])

        logging.info("Technique Mitigations")
        scrape_mitigation_table(soup, neo4j_conn, technique_name)

    except requests.exceptions.RequestException as e:
        logging.error("Could not load URL: %s", e)
