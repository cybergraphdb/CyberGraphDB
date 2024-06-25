import requests
from bs4 import BeautifulSoup


def extract_detection_table(soup, neo4j_conn, technique_name):
    # Trova le tabelle che seguono l'elemento <h2>
    table_selector = "table.datasources-table tbody tr"
    table_rows = soup.select(table_selector)

    if not table_rows:
        print("Table not found")
        return

    print("\n[!] Detection Used by Technique: \n")

    prev_data_source = "N/A"
    prev_data_component = "N/A"
    prev_detects = "N/A"

    for row in table_rows:
        data_source_elements = row.select("td:nth-child(2) a")
        data_source_element = data_source_elements[0] if data_source_elements else None
        data_source = (
            data_source_element.get_text() if data_source_element else prev_data_source
        )

        data_component_elements = row.select("td:nth-child(3) a")
        data_component_element = (
            data_component_elements[0] if data_component_elements else None
        )
        data_component = (
            data_component_element.get_text()
            if data_component_element
            else prev_data_component
        )

        detects_elements = row.select("td:nth-child(4) p")
        detects_element = detects_elements[0] if detects_elements else None
        detects = detects_element.get_text() if detects_element else prev_detects

        print("\nData Source:", data_source)
        print("Data Component:", data_component)
        print("Detect Description:\n", detects)

        # Aggiorna i valori precedenti
        prev_data_source = data_source
        prev_data_component = data_component
        prev_detects = detects

        neo4j_conn.create_detection_node(data_source, data_component, detects)
        neo4j_conn.create_relationship_technique_detection(technique_name, data_source)


def scrape_procedure_table(soup):

    # Trova la tabella
    table = soup.find("table", class_="table table-bordered table-alternate mt-2")

    # Inizializza una lista per memorizzare i dati delle procedures
    procedures = []

    # Trova tutte le righe nella tabella (tr)
    rows = table.find("tbody").find_all("tr")

    # Itera attraverso le righe della tabella
    for row in rows:
        # Estrai le colonne (td) dalla riga
        columns = row.find_all("td")

        # Estrai i dati dalla colonna "ID" (prima colonna)
        procedure_id = columns[0].find("a").text.strip()

        # Estrai i dati dalla colonna "procedure" (seconda colonna)
        procedure_name = columns[1].find("a").text.strip()

        # Estrai i dati dalla colonna "Description" (terza colonna)
        procedure_description = columns[2].find("p").text.strip()

        # Crea un dizionario con i dati estratti e aggiungilo alla lista delle procedures
        procedure_data = {
            "ID": procedure_id,
            "procedure": procedure_name,
            "Description": procedure_description,
        }
        procedures.append(procedure_data)

    return procedures


def scrape_mitigation_table(soup, neo4j_conn, technique_name):
    # Trova l'elemento <h2> con l'ID "mitigations"
    mitigations_header = soup.find("h2", id="mitigations")

    # Verifica se l'header delle mitigations è stato trovato
    if mitigations_header:
        # Trova la tabella successiva all'header
        table = mitigations_header.find_next(
            "table", class_="table table-bordered table-alternate mt-2"
        )
        if table:
            # Inizializza una lista per memorizzare i dati delle mitigations
            mitigations = []

            # Trova tutte le righe nella tabella (tr)
            rows = table.find("tbody").find_all("tr")

            # Itera attraverso le righe della tabella
            for row in rows:
                # Estrai le colonne (td) dalla riga
                columns = row.find_all("td")

                # Estrai i dati dalla colonna "ID" (prima colonna)
                mitigation_id = columns[0].find("a").text.strip()

                # Estrai i dati dalla colonna "Mitigation" (seconda colonna)
                mitigation_name = columns[1].find("a").text.strip()

                # Estrai i dati dalla colonna "Description" (terza colonna)
                mitigation_description = columns[2].find("p").text.strip()

                # Crea un dizionario con i dati estratti e aggiungilo alla lista delle mitigations
                mitigation_data = {
                    "ID": mitigation_id,
                    "Mitigation": mitigation_name,
                    "Description": mitigation_description,
                }
                mitigations.append(mitigation_data)
            for mitigation in mitigations:
                print("ID:", mitigation["ID"])
                print("Mitigation:", mitigation["Mitigation"])
                print("Description:", mitigation["Description"])
                print()
                neo4j_conn.create_mitigation_node(
                    mitigation["ID"],
                    mitigation["Mitigation"],
                    mitigation["Description"],
                )
                neo4j_conn.create_relationship_technique_mitigation(
                    technique_name, mitigation["Mitigation"]
                )

            else:
                print("No Mitigation Found")

    else:
        print("Header delle mitigations non trovato.")
        return []


# def explore_technique_url(neo4j_conn, malware_name, technique_type, technique_name, technique_id, technique_url, technique_use, span_href):
#     try:
#         response = requests.get(technique_url)
#         response.raise_for_status()
#         body = response.text

#         soup = BeautifulSoup(body, "html.parser")

#         description_element = soup.select_one(".description-body")

#         if description_element:
#             technique_description = description_element.get_text().strip()
#             print("Technique Description:\n", technique_description)
#             neo4j_conn.create_technique_node(technique_type, technique_name, technique_id, technique_url, technique_use, span_href, technique_description)
#             neo4j_conn.create_relationship_malware_technique(malware_name, technique_name)
#         else:
#             print("Description not found")

#         extract_detection_table(soup, neo4j_conn, technique_name)
#         procedures_data = scrape_procedure_table(soup)

#         print("\n[!] Technique Procedures\n")

#         for procedure in procedures_data:
#             print("ID:", procedure["ID"])
#             print("Procedure:", procedure["procedure"])
#             print("Description:", procedure["Description"])
#             print()
#             neo4j_conn.create_procedure_node(procedure["ID"], procedure["procedure"], procedure["Description"])
#             neo4j_conn.create_relationship_technique_procedure(technique_name, procedure["procedure"])

#         print("\n[!] Technique Mitigations \n")

#         scrape_mitigation_table(soup, neo4j_conn, technique_name)


#     except requests.exceptions.RequestException as e:
#         print("Could not load URL:", e)
def explore_technique_url(
    neo4j_conn,
    malware_name,
    technique_type,
    technique_name,
    technique_id,
    technique_url,
    technique_use,
    span_href,
):
    try:
        response = requests.get(technique_url)
        response.raise_for_status()
        body = response.text

        soup = BeautifulSoup(body, "html.parser")

        description_element = soup.select_one(".description-body")

        if description_element:
            technique_description = description_element.get_text().strip()
            print("Technique Description:\n", technique_description)
            neo4j_conn.create_technique_node(
                technique_type,
                technique_name,
                technique_id,
                technique_url,
                span_href,
                technique_description,
            )
            neo4j_conn.create_relationship_malware_technique(
                malware_name, technique_name, technique_use
            )
        else:
            print("Description not found")

        extract_detection_table(soup, neo4j_conn, technique_name)
        procedures_data = scrape_procedure_table(soup)

        print("\n[!] Technique Procedures\n")

        for procedure in procedures_data:
            print("ID:", procedure["ID"])
            print("Procedure:", procedure["procedure"])
            print("Description:", procedure["Description"])
            print()
            neo4j_conn.create_procedure_node(
                procedure["ID"], procedure["procedure"], procedure["Description"]
            )
            neo4j_conn.create_relationship_technique_procedure(
                technique_name, procedure["procedure"]
            )

        print("\n[!] Technique Mitigations \n")

        scrape_mitigation_table(soup, neo4j_conn, technique_name)

    except requests.exceptions.RequestException as e:
        print("Could not load URL:", e)
