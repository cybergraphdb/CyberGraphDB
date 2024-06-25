import logging
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import mitre_scraper
from py2neo import Graph

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

db = None
main_url = "https://attack.mitre.org/software/"


def extract_malware_names():
    neo4j_uri = "bolt://localhost:7688"
    neo4j_user = "neo4j"
    neo4j_password = ""

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
    query = "MATCH (m:Malware) RETURN m.name AS name"
    malware_names = [record["name"] for record in graph.run(query)]

    logging.info(f"Malware names extracted: {len(malware_names)} found.")
    for name in malware_names:
        logging.info(f"Malware {name} already in the database.")

    return malware_names


def define_db_building():
    global db
    database_type = input("[1] - Graph DB\n[2] - Document DB\n")
    if database_type == "1":
        db = "Graph"
        logging.info("Building Graph Database ...")
    elif database_type == "2":
        db = "Document"
        logging.info("Building Document Database ...")
    return db


def main():
    try:
        malware_names = extract_malware_names()
        logging.info("Malware Names Extracted.")
        response = requests.get(main_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        tbody = soup.find("tbody")
        href_elements = tbody.find_all("a", href=True)
        hrefs = [element["href"] for element in href_elements]

        with open("sidenav.txt", "w", encoding="utf-8") as s:
            s.write(soup.prettify())

        links_info = list(
            set(
                (link["href"], link.get_text(strip=True))
                for link in href_elements
                if "S0" not in link.get_text(strip=True) and "S1" not in link.get_text(strip=True)
            )
        )

        hrefs = []
        to_do = []
        for href, text in links_info:
            logging.info(f"href: {href}, text: {text}")
            if text not in malware_names and "/software/" in href:
                logging.info(f"This malware is not in the DB: {text}")
                hrefs.append(href)
                to_do.append(text)

        logging.info("+++++++++++ Start Analysis ++++++++++++")
        for malware in to_do:
            logging.info(malware)
        logging.info(f"Total amount of Malware to add: {len(to_do)}")
        assert len(to_do) == len(hrefs), "Problems ..."

        db = define_db_building()
        with open("REMAINING_MALWARES.txt", "w") as f:
            for ref in hrefs:
                logging.info(f"\nSaving {ref}")
                f.write(f"{ref}\n")

        for href in tqdm(hrefs):
            complete_url = main_url.replace("/software/", "") + href
            logging.info(f"[!] Analyzing: {complete_url}")
            mitre_scraper.scraper(complete_url, db)

    except requests.exceptions.RequestException as e:
        logging.error(f"Could not load URL {main_url}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
