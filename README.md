# CyberGraphDB

CyberGraphDB is a graph database specifically designed for holistic cybersecurity threat analysis. By integrating malware data, CVE vulnerabilities, and Metasploit exploits into a unified graph structure, CyberGraphDB provides a comprehensive view of the cybersecurity landscape. This integration enhances the correlation of disparate data points and improves threat understanding and prediction.

## Access to the Database:

- **Click on this Link to access CyberGraphDB in .csv and .gml** 

https://drive.google.com/drive/folders/19oRefos2PZSp9TvX28DvRxdVOfLQz2Xm


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Data Import](#data-import)
- [Running in Docker](#running-in-docker)
- [Query Examples](#query-examples)
- [Contributing](#contributing)
- [License](#license)

## Introduction

CyberGraphDB addresses the need for advanced methods to store and analyze complex cybersecurity data. Traditional relational databases often fall short in handling such data, especially in malware analysis, CVE vulnerabilities, and exploits. Graph databases, with their natural ability to model relationships, offer a powerful alternative.

## Features

- **Holistic Threat Overview:** Combines malware information, CVE vulnerabilities, and exploits from multiple reputable sources.
- **Improved Threat Analysis:** Enables quick identification of influential nodes, measures the importance of malware entities, and detects clusters of related threats.
- **Scalability and Performance:** Efficiently processes large volumes of cybersecurity data while maintaining high query performance.
- **Modular and Updatable Design:** Easy updates and scalability with a modular approach.

## Installation

To install CyberGraphDB, clone the repository and navigate to the project directory:

```bash
git clone https://github.com/cybergraphdb/CyberGraphDB.git
cd CyberGraphDB
```
## Architecture

CyberGraphDB is composed of four interconnected graphs, each representing different aspects of cybersecurity data:

- **MITRE Graph:** Contains nodes representing malware, adversary techniques, mitigations, detections, and procedures.
- **CVE Graph:** Represents common vulnerabilities and exposures (CVEs) with attributes such as CVE ID, description, affected products, and references.
- **Malware Graph:** Includes nodes representing different malware samples with attributes like names, hash values, descriptions, and associated threats.
- **Exploit Graph:** Contains nodes representing various security exploits, especially those cataloged in the Metasploit Framework.

## Query Examples

Here are some example queries to interact with CyberGraphDB:

### Query 1: Find all malware names

```cypher
MATCH (m:Malware)
RETURN m.name
```

```cypher
MATCH (m:Malware)-[:EXPLOITS]->(c:CVE)
WHERE m.name = 'SomeMalware'
RETURN c.cve_id, c.description
```

```cypher
MATCH (c:CVE)-[:HAS_EXPLOIT]->(e:Exploit)
WHERE c.cve_id = 'CVE-2023-1234'
RETURN e.name, e.description
```
