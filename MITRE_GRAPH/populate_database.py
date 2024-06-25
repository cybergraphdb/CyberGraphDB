import json

from neo4j import GraphDatabase


class Neo4jConnection:
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        print("\n[!] Database Connection: SUCCESSFUL")

    def close(self):
        self._driver.close()

    def create_hash_node_from_report_file(self, MITRE_family):
        path = "C:\\Users\\marco\\python_version\\Retrieve_HASH\\FILTER_TARGET_HASHES\\"
        with open(path + str(MITRE_family), "r") as file:
            report_data = json.load(file)

            with self._driver.session() as session:
                session.write_transaction(
                    self._create_hash_node, str(MITRE_family), report_data
                )

    def create_malware_node(self, name, description):
        with self._driver.session() as session:
            result = session.write_transaction(
                self._create_malware_node, name, description
            )
            return result

    def create_technique_node(
        self,
        technique_type,
        technique_name,
        technique_id,
        technique_url,
        ref_url,
        technique_description,
    ):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_technique_node,
                technique_type,
                technique_name,
                technique_id,
                technique_url,
                ref_url,
                technique_description,
            )

    def create_procedure_node(self, id, procedure, description):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_procedure_node, id, procedure, description
            )

    def create_mitigation_node(self, id, mitigation, description):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_mitigation_node, id, mitigation, description
            )

    def create_detection_node(self, data_source, data_component, detect_description):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_detection_node,
                data_source,
                data_component,
                detect_description,
            )

    def create_relationship_malware_technique(
        self, malware_name, technique_name, technique_use
    ):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_relationship_malware_technique,
                malware_name,
                technique_name,
                technique_use,
            )

    def create_relationship_technique_mitigation(self, technique_name, mitigation):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_relationship_technique_mitigation,
                technique_name,
                mitigation,
            )

    def create_relationship_technique_procedure(self, technique_name, procedure):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_relationship_technique_procedure, technique_name, procedure
            )

    def create_relationship_technique_detection(self, technique_name, data_source):
        with self._driver.session() as session:
            session.write_transaction(
                self._create_relationship_technique_detection,
                technique_name,
                data_source,
            )

    @staticmethod
    def _create_mitigation_node(tx, id, mitigation, description):
        query = """
        MERGE (m:Mitigation {name: $mitigation})
        ON CREATE SET m.description = $description, m.id = $id
        RETURN m
        """
        result = tx.run(query, id=id, mitigation=mitigation, description=description)
        return result.single() is not None

    @staticmethod
    def _create_procedure_node(tx, id, procedure, description):
        query = """
        MERGE (p:Procedure {name: $procedure})
        ON CREATE SET p.description = $description, p.id = $id
        RETURN p
        """
        result = tx.run(query, id=id, procedure=procedure, description=description)
        return result.single() is not None

    @staticmethod
    def _create_detection_node(tx, data_source, data_component, detect_description):
        query = """
        MERGE (d:Detection {name: $data_source})
        ON CREATE SET d.description = $detect_description, d.data_component = $data_component
        RETURN d
        """
        result = tx.run(
            query,
            data_source=data_source,
            data_component=data_component,
            detect_description=detect_description,
        )
        return result.single() is not None

    @staticmethod
    def _create_malware_node(tx, name, description):
        query = """
        MERGE (m:Malware {name: $name})
        ON CREATE SET m.description = $description
        RETURN m
        """
        result = tx.run(query, name=name, description=description)
        return result.single() is not None

    # @staticmethod
    # def _create_technique_node(tx, technique_type, technique_name, technique_id, technique_url, technique_use, ref_url, technique_description):
    #     query = """
    #     MERGE (t:Technique {name: $technique_name})
    #     ON CREATE SET t.type = $technique_type, t.id = $technique_id, t.url = $technique_url, t.use = $technique_use, t.ref = $ref_url, t.description = $technique_description
    #     RETURN t
    #     """
    #     result = tx.run(query, technique_type=technique_type, technique_name=technique_name, technique_id=technique_id, technique_url=technique_url, technique_use=technique_use, ref_url=ref_url, technique_description=technique_description)
    #     return result.single() is not None

    @staticmethod
    def _create_technique_node(
        tx,
        technique_type,
        technique_name,
        technique_id,
        technique_url,
        span_href,
        technique_description,
    ):
        query = """
        MERGE (t:Technique {name: $technique_name})
        ON CREATE SET t.technique_type = $technique_type,
            t.technique_id = $technique_id,
            t.technique_name = $technique_name,
            t.technique_url = $technique_url,
            t.ref = $span_href,
            t.technique_description = $technique_description
        """
        tx.run(
            query,
            technique_type=technique_type,
            technique_name=technique_name,
            technique_id=technique_id,
            technique_url=technique_url,
            span_href=span_href,
            technique_description=technique_description,
        )

    # @staticmethod
    # def _create_relationship_malware_technique(tx, malware_name, technique_name):
    #     query = """
    #     MATCH (m:Malware {name: $malware_name})
    #     MATCH (t:Technique {name: $technique_name})
    #     MERGE (m)-[:HAS_TECHNIQUE]->(t)
    #     """
    #     tx.run(query, malware_name=malware_name, technique_name=technique_name)

    @staticmethod
    def _create_relationship_malware_technique(
        tx, malware_name, technique_name, technique_use
    ):
        query = """
        MATCH (m:Malware {name: $malware_name})
        MATCH (t:Technique {technique_name: $technique_name})
        MERGE (m)-[r:HAS_TECHNIQUE]->(t)
        SET r.technique_use = $technique_use
        """
        tx.run(
            query,
            malware_name=malware_name,
            technique_name=technique_name,
            technique_use=technique_use,
        )

    @staticmethod
    def _create_relationship_technique_mitigation(tx, technique_name, mitigation):
        query = """
        MATCH (m:Mitigation {name: $mitigation})
        MATCH (t:Technique {name: $technique_name})
        MERGE (t)-[:HAS_MITIGATION]->(m)
        """
        tx.run(query, technique_name=technique_name, mitigation=mitigation)

    @staticmethod
    def _create_relationship_technique_detection(tx, technique_name, data_source):
        query = """
        MATCH (d:Detection {name: $data_source})
        MATCH (t:Technique {name: $technique_name})
        MERGE (t)-[:HAS_DETECTION]->(d)
        """
        tx.run(query, technique_name=technique_name, data_source=data_source)

    @staticmethod
    def _create_relationship_technique_procedure(tx, technique_name, procedure):
        query = """
        MATCH (p:Procedure {name: $procedure})
        MATCH (t:Technique {name: $technique_name})
        MERGE (t)-[:HAS_PROCEDURE]->(p)
        """
        tx.run(query, technique_name=technique_name, procedure=procedure)

    @staticmethod
    def _create_hash_node(tx, MITRE_family, report_data):
        query = """
        MERGE (h:Hash {MITRE_family: $MITRE_family, md5: $md5, sha1: $sha1, sha256: $sha256, tlsh: $tlsh, vhash: $vhash, type_description: $type_description, type_tags: $type_tags, creation_date: $creation_date, names: $names, last_modification_date: $last_modification_date, type_tag: $type_tag, times_submitted: $times_submitted, total_votes_harmless: $total_votes_harmless, total_votes_malicious: $total_votes_malicious, size: $size, popular_threat_suggested_label: $popular_threat_suggested_label})
        RETURN h
        """
        result = tx.run(
            query,
            MITRE_family,
            md5=report_data["md5"],
            sha1=report_data["sha1"],
            sha256=report_data["sha256"],
            tlsh=report_data["tlsh"],
            vhash=report_data["vhash"],
            type_description=report_data["attributes"]["type_description"],
            type_tags=report_data["attributes"]["type_tags"],
            creation_date=report_data["attributes"]["creation_date"],
            names=report_data["attributes"]["names"],
            last_modification_date=report_data["attributes"]["last_modification_date"],
            type_tag=report_data["attributes"]["type_tag"],
            times_submitted=report_data["attributes"]["times_submitted"],
            total_votes_harmless=report_data["attributes"]["total_votes"]["harmless"],
            total_votes_malicious=report_data["attributes"]["total_votes"]["malicious"],
            size=report_data["attributes"]["size"],
            popular_threat_suggested_label=report_data["attributes"][
                "popular_threat_classification"
            ]["suggested_threat_label"],
        )
        return result.single() is not None


# # Configura la connessione
# uri = "bolt://localhost:7688"
# user = "neo4j"
# password = "scottdirT98"

# # Crea una connessione al database
# conn = Neo4jConnection(uri, user, password)

# # Esempio di utilizzo
# conn.create_relationship_malware_technique("MalwareExample", "TechniqueExample")
# conn.create_relationship_technique_mitigation("TechniqueExample", "MitigationExample")
# conn.create_relationship_technique_detection("TechniqueExample", "DetectionExample")
# conn.create_relationship_technique_procedure("TechniqueExample", "ProcedureExample")

# # Chiudi la connessione
# conn.close()
