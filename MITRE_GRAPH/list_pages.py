import requests
from bs4 import BeautifulSoup
import mitre_scraper
from tqdm import tqdm 
db = "None"
# URL della pagina principale da cui iniziare la ricerca
main_url = "https://attack.mitre.org/software/" #"https://attack.mitre.org/software/"

def extract_malware_names():
    from py2neo import Graph

    # Connessione al database Neo4j
    neo4j_uri = "bolt://localhost:7688"
    neo4j_user = "neo4j"
    neo4j_password = "scottdirT98"

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))

    # Query per ottenere i nomi dei nodi di tipo "Malware"
    query = "MATCH (m:Malware) RETURN m.name AS name"

    # Esegui la query e metti i risultati in una lista
    malware_names = [record["name"] for record in graph.run(query)]
    for name in malware_names:
        print(f"- Malware {name} already in the Database ...")
    
    print(f"Total Malware inside so far -> {len(malware_names)}")
    return malware_names

def define_DB_Building():
    global db
    database_type = input("[1] - Graph DB\n[2] - Document DB\n ")
    if database_type == "1":
        db = "Graph"
        print("[!!!] Building Graph Database ...\n")
    if database_type == "2":
        db = "Document"
        print("[!!!] Building Document Database ...\n")
    return db

try:
    malware_names = extract_malware_names()
    print(f"[+] Malware Names Extracted.")
    response = requests.get(main_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    # Trova tutti gli elementi "a" con attributo "href" all'interno del tag "tbody"
    tbody = soup.find("tbody")
    href_elements = tbody.find_all("a", href=True)

    # # Estrai gli href
    hrefs = [element["href"] for element in href_elements]

    print(soup.prettify())
    with open("sidenav.txt", "+a", encoding="utf-8") as s:
        s.write(soup.prettify())

    # # Trova tutti i link nel sidenav
    # sidenav_links = soup.select('.sidenav a')

    # # Debug: stampa i link trovati
    # print(f"Trovati {len(sidenav_links)} link nel sidenav")


    # Estrai gli href dai link
    #hrefs = [link['href'] for link in sidenav_links]

    # Estrai gli href e il testo dai link
    links_info = list(set(
        (link['href'], link.get_text(strip=True)) 
        for link in href_elements 
        if "S0" not in link.get_text(strip=True) and "S1" not in link.get_text(strip=True)
    ))
    print(links_info)
    # Stampa le informazioni dei link
    hrefs = []
    to_do = []
    for href, text in links_info:
        print(f"href: {href}, text: {text}")
        if text not in malware_names and "/software/" in href:
            print(f"This Malware is not in the DB: {text}")
            hrefs.append(href)
            to_do.append(text)
    print("+++++++++++ Start Analysis ++++++++++++")
    for malware in to_do:
        print(malware)
    print(f"Total amount of Malware to add: {len(to_do)}")
    #print(len(hrefs))
    assert len(to_do) == len(hrefs), "Problems ..."
    access = 1
    # Stampa gli href
    db = define_DB_Building()
    with open("REMAINING_MALWARES.txt", "+a") as f:
        for ref in hrefs:
            print(f"\nSaving {ref}")
            f.write(f'{ref}\n')
    db = "Graph"
    for href in tqdm(hrefs):
        if access == 1:
            if "/software/S" in href:
                complete_url =  main_url.replace("/software/", "") + href
                print("[!] Analyzing : ", complete_url)
                mitre_scraper.scraper(complete_url, db)
        else:
            access = 1
        
except requests.exceptions.RequestException as e:
    print(f"Could not load URL {main_url}: {e}")
