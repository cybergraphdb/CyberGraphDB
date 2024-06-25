import requests
from bs4 import BeautifulSoup

import malware_references
import technique_exploration
from malware_features import Malware, Technique, ProcedureMethod, DetectionMethod, MitigationMethod
import populate_database
import build_malware_document
import streamlit as st
from py2neo import Graph
import json
import pandas as pd
from sklearn.cluster import KMeans
import plotly.express as px

# Connect to Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", "scottdirT98"))

neo4j_uri = "bolt://localhost:7688"
neo4j_user = "neo4j"
neo4j_password = "scottdirT98"

def malware_exists(malware_name):
    try:
        query = 'MATCH (n:Malware {name: "' + malware_name + '"}) RETURN n'
        result = graph.run(query)
        return len(result.data()) > 0
    except Exception as e:
        print(e)
        return False

def scraper(url, db):
    mitre_url = "https://attack.mitre.org"
    
    try:
        soup = connecting_to_malware_page(url)
        malware_name = find_malware_name(soup)
        malware_description = find_malware_description(soup)
        
        # Find the techniques table within the HTML document
        table = soup.find('table', class_='table techniques-used background table-bordered')
        if not table:
            print("No techniques table found.")
            return

        rows = table.find('tbody').find_all('tr')
        print(f"\n[!] Retrieving Techniques Used by Malware: {malware_name}\n")

        techniques = {}
        for row in rows:
            td_count = len(row.select('td'))
            columns = row.find_all('td')
            for i, column in enumerate(columns):
                print(f"\nColumn Number: {i}")
                print(column)
            if len(columns) < 4:
                continue
            
            technique_type = columns[0].text.strip()
            if not technique_type:
                technique_type = "Enterprise"
            technique_id_link = columns[1].find('a')
            technique_id = technique_id_link.text.strip() if technique_id_link else "N/A"
            technique_url = mitre_url + technique_id_link['href'] if technique_id_link else "N/A"
            
            if len(columns) == 5:
                # Sub-technique case
                sub_technique_id_link = columns[2].find('a')
                if sub_technique_id_link:
                    sub_technique_id = sub_technique_id_link.text.strip()
                    sub_technique_name = columns[3].text.strip().replace(columns[3].find('a').text.strip(), "").strip(": ").strip()
                    full_technique_name = f"{columns[3].find('a').text.strip()}: {sub_technique_name}"
                    technique_url = mitre_url + sub_technique_id_link['href']
                else:
                    sub_technique_id = ""
                    full_technique_name = columns[2].find('a')
                    if full_technique_name:
                        full_technique_name = full_technique_name.text.strip()
                        print(f"FULL TECHNIQUE NAME: {full_technique_name}")
            else:
                sub_technique_id = ""
                full_technique_name = columns[2].find('a')
                if full_technique_name:
                    full_technique_name = full_technique_name.text.strip()
                    print(f"FULL TECHNIQUE NAME: {full_technique_name}")
            
            if full_technique_name and full_technique_name[-1] == ":":
                full_technique_name = full_technique_name[:-1]


            if sub_technique_id != "":
                sub_technique_id = sub_technique_id.replace(".", "")
                technique_id = f"{technique_id}/{sub_technique_id}"
            
            if "N" in technique_id:
                technique_id = technique_url.split('/')[-2] + '/' + technique_url.split('/')[-1]
            
            # Extract the technique use
            use_column = columns[-1]
            technique_use = use_column.text.strip()
            #technique_use = f"{malware_name} {technique_use}"
            software_link = use_column.find('a', href=True)
            span_href_element = row.select(f'td:nth-child({td_count}) p span a')
            span_href = span_href_element[0]['href'] if span_href_element else "N/A"
            if '/software/' in span_href:
                technique_use = use_column.text.replace(software_link.text, "").strip()
                #technique_use = f"{malware_name} {technique_use}"

            techniques[technique_id] = {
                "technique_type": technique_type,
                "technique_name": full_technique_name,
                "technique_url": technique_url,
                "technique_use": technique_use,
                "span_href": span_href,
                "sub_technique_id": sub_technique_id
            }
        technique_urls = []
        for technique_id, details in techniques.items():
            print("\nTechnique Type:", details["technique_type"])
            print("Technique ID:", technique_id)
            print("Sub-Technique ID:", details["sub_technique_id"])
            print("Technique Name:", details["technique_name"])
            print("Technique URL:", details["technique_url"])
            print("Technique Use:", details["technique_use"])
            print("Span Href:", details["span_href"])
            print("---")

            if db == "Graph":
                    neo4j_conn = create_malware_node(malware_name, malware_description)
                    technique_exploration.explore_technique_url(neo4j_conn, malware_name, details["technique_type"], details["technique_name"], technique_id, details["technique_url"], details["technique_use"], details["span_href"])
            elif db == "Document":
                    #print(technique_urls)
                    technique_urls.append(technique_url)
                
        if db == "Document":
                malware_references.set_new_refs()
                extract_technique_references(technique_urls)
                malware_page_references = malware_references.find_malware_references(soup)
                for url in malware_page_references:
                    with open('REFERENCE_LIST.txt', 'a') as f:
                        f.write(url + '\n')
                #build_malware_document.build_document(malware_name, malware_page_references)

        # else:
        #     print("Table not found")
        
        
    except Exception as e:
        print("Error Table Techniques: " + str(e))
        malware_page_references = malware_references.find_malware_references(soup)
        for url in malware_page_references:
            with open('REFERENCE_LIST.txt', 'a') as f:
                f.write(url + '\n')
        pass

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
        print(e)
    return neo4j_conn


def find_malware_description(soup):
    description_element = soup.find(class_="description-body")
    if description_element:
        malware_description = description_element.get_text().strip()
        print("\n[!] Malware Description:\n", malware_description)
        return malware_description
    else:
        print("Description not found")

def find_malware_name(soup):
    name_element = soup.find("h1")
    if name_element:
        malware_name = name_element.get_text().strip()
        print("\n[!] MALWARE NAME:\n", malware_name)
        return malware_name
    else:
        print("Name Not found")


'''
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
'''