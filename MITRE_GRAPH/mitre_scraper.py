import logging
import requests
from bs4 import BeautifulSoup
from py2neo import Graph
import malware_references
import populate_database
import technique_exploration

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Connect to Neo4j
neo4j_uri = "bolt://localhost:7688"
neo4j_user = "neo4j"
neo4j_password = ""
graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))

def malware_exists(malware_name):
    try:
        query = 'MATCH (n:Malware {name: "' + malware_name + '"}) RETURN n'
        result = graph.run(query)
        return len(result.data()) > 0
    except Exception as e:
        logging.error(f"Error checking malware existence: {e}")
        return False

def scraper(url, db):
    mitre_url = "https://attack.mitre.org"

    try:
        soup = connecting_to_malware_page(url)
        malware_name = find_malware_name(soup)
        malware_description = find_malware_description(soup)

        # Find the techniques table within the HTML document
        table = soup.find("table", class_="table techniques-used background table-bordered")
        if not table:
            logging.warning("No techniques table found.")
            return

        rows = table.find("tbody").find_all("tr")
        logging.info(f"Retrieving Techniques Used by Malware: {malware_name}")

        techniques = {}
        for row in rows:
            columns = row.find_all("td")
            if len(columns) < 4:
                continue

            technique_type = columns[0].text.strip() or "Enterprise"
            technique_id_link = columns[1].find("a")
            technique_id = technique_id_link.text.strip() if technique_id_link else "N/A"
            technique_url = mitre_url + technique_id_link["href"] if technique_id_link else "N/A"

            sub_technique_id = ""
            full_technique_name = ""

            if len(columns) == 5:
                sub_technique_id_link = columns[2].find("a")
                if sub_technique_id_link:
                    sub_technique_id = sub_technique_id_link.text.strip()
                    sub_technique_name = columns[3].text.strip().replace(columns[3].find("a").text.strip(), "").strip(": ").strip()
                    full_technique_name = f"{columns[3].find('a').text.strip()}: {sub_technique_name}"
                    technique_url = mitre_url + sub_technique_id_link["href"]
                else:
                    sub_technique_id = ""
                    full_technique_name = columns[2].find("a").text.strip()
            else:
                full_technique_name = columns[2].find("a").text.strip()

            if full_technique_name and full_technique_name[-1] == ":":
                full_technique_name = full_technique_name[:-1]

            if sub_technique_id:
                sub_technique_id = sub_technique_id.replace(".", "")
                technique_id = f"{technique_id}/{sub_technique_id}"

            if "N" in technique_id:
                technique_id = technique_url.split("/")[-2] + "/" + technique_url.split("/")[-1]

            # Extract the technique use
            use_column = columns[-1]
            technique_use = use_column.text.strip()
            software_link = use_column.find("a", href=True)
            span_href_element = row.select(f"td:nth-child({len(columns)}) p span a")
            span_href = span_href_element[0]["href"] if span_href_element else "N/A"
            if "/software/" in span_href:
                technique_use = use_column.text.replace(software_link.text, "").strip()

            techniques[technique_id] = {
                "technique_type": technique_type,
                "technique_name": full_technique_name,
                "technique_url": technique_url,
                "technique_use": technique_use,
                "span_href": span_href,
                "sub_technique_id": sub_technique_id,
            }

        technique_urls = []
        for technique_id, details in techniques.items():
            logging.info(f"\nTechnique Type: {details['technique_type']}")
            logging.info(f"Technique ID: {technique_id}")
            logging.info(f"Sub-Technique ID: {details['sub_technique_id']}")
            logging.info(f"Technique Name: {details['technique_name']}")
            logging.info(f"Technique URL: {details['technique_url']}")
            logging.info(f"Technique Use: {details['technique_use']}")
            logging.info(f"Span Href: {details['span_href']}")
            logging.info("---")

            if db == "Graph":
                neo4j_conn = create_malware_node(malware_name, malware_description)
                technique_exploration.explore_technique_url(
                    neo4j_conn,
                    malware_name,
                    details["technique_type"],
                    details["technique_name"],
                    technique_id,
                    details["technique_url"],
                    details["technique_use"],
                    details["span_href"],
                )
            elif db == "Document":
                technique_urls.append(details["technique_url"])

        if db == "Document":
            malware_references.set_new_refs()
            extract_technique_references(technique_urls)
            malware_page_references = malware_references.find_malware_references(soup)
            with open("REFERENCE_LIST.txt", "a") as f:
                for url in malware_page_references:
                    f.write(url + "\n")

    except Exception as e:
        logging.error(f"Error in scraping: {e}")
        malware_page_references = malware_references.find_malware_references(soup)
        with open("REFERENCE_LIST.txt", "a") as f:
            for url in malware_page_references:
                f.write(url + "\n")

def extract_technique_references(technique_urls):
    for url in technique_urls:
        _technique_references(url)

def _technique_references(technique_url):
    response = requests.get(technique_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    malware_references._find_references(soup)

def connecting_to_malware_page(url):
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    return soup

def create_malware_node(malware_name, malware_description):
    try:
        neo4j_conn = populate_database.Neo4jConnection(neo4j_uri, neo4j_user, neo4j_password)
        neo4j_conn.create_malware_node(malware_name, malware_description)
    except Exception as e:
        logging.error(f"Error creating malware node: {e}")
    return neo4j_conn

def find_malware_description(soup):
    description_element = soup.find(class_="description-body")
    if description_element:
        malware_description = description_element.get_text().strip()
        logging.info(f"Malware Description: {malware_description}")
        return malware_description
    else:
        logging.warning("Description not found")
        return ""

def find_malware_name(soup):
    name_element = soup.find("h1")
    if name_element:
        malware_name = name_element.get_text().strip()
        logging.info(f"Malware Name: {malware_name}")
        return malware_name
    else:
        logging.warning("Name not found")
        return ""



"""
if __name__ == "__main__":
   
    url = "https://attack.mitre.org/software/S0484/"

    db = "None"
    database_type = input("[1] - Graph DB\n[2] - Document DB\n ")
    if database_type == "1":
        db = "Graph"
        print("[!!!] Building Graph Database ...\n")
    if database_type == "2":
        db = "Document"
        print("[!!!] Building Document Database ...\n")

    scraper(url, db)
"""
