import time

import matplotlib.pyplot as plt
import streamlit as st
from py2neo import Graph

# Connect to Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", ""))


# Function to measure the execution time of queries
def measure_query_time(query_function, *args):
    start_time = time.time()
    result = query_function(*args)
    end_time = time.time()
    execution_time = end_time - start_time
    return execution_time, result


# Define queries for different difficulty levels
def get_metasploit_script_nodes():
    query = """
    MATCH (m:MetasploitScript)
    RETURN m.name, m.type, m.target
    """
    return graph.run(query).data()


def get_metasploit_description_nodes():
    query = """
    MATCH (d:MetasploitDescription)
    RETURN d.description
    """
    return graph.run(query).data()


def get_payload_nodes():
    query = """
    MATCH (p:Payload)
    RETURN p.details
    """
    return graph.run(query).data()


def get_code_nodes():
    query = """
    MATCH (c:Code)
    RETURN c.code
    """
    return graph.run(query).data()


def get_author_nodes():
    query = """
    MATCH (a:Author)
    RETURN a.name
    """
    return graph.run(query).data()


def get_references_nodes():
    query = """
    MATCH (r:References)
    RETURN r.reference
    """
    return graph.run(query).data()


def get_descriptions_for_scripts():
    query = """
    MATCH (m:MetasploitScript)-[:HAS_DESCRIPTION]->(d:MetasploitDescription)
    RETURN m.name, d.description
    """
    return graph.run(query).data()


def get_payloads_for_scripts():
    query = """
    MATCH (m:MetasploitScript)-[:HAS_PAYLOAD]->(p:Payload)
    RETURN m.name, p.details
    """
    return graph.run(query).data()


def get_codes_for_scripts():
    query = """
    MATCH (m:MetasploitScript)-[:HAS_CODE]->(c:Code)
    RETURN m.name, c.code
    """
    return graph.run(query).data()


def get_authors_for_scripts():
    query = """
    MATCH (m:MetasploitScript)-[:CREATED]->(a:Author)
    RETURN m.name, a.name
    """
    return graph.run(query).data()


def get_all_relationships(limit=1000):
    query = """
    MATCH (a)-[r]->(b)
    RETURN a.name, type(r) AS relationship_type, b.name
    LIMIT $limit
    """
    return graph.run(query, limit=limit).data()


# Classify the queries
query_classification = {
    "easy": [
        get_metasploit_script_nodes,
        get_metasploit_description_nodes,
        get_payload_nodes,
        get_code_nodes,
        get_author_nodes,
    ],
    "medium": [
        get_descriptions_for_scripts,
        get_payloads_for_scripts,
        get_codes_for_scripts,
        get_authors_for_scripts,
        get_references_nodes,
    ],
    "hard": [get_all_relationships],
}

# Measure execution time for each query
execution_times = {"easy": [], "medium": [], "hard": []}

for difficulty, queries in query_classification.items():
    for query_function in queries:
        execution_time, _ = measure_query_time(query_function)
        execution_times[difficulty].append(execution_time)


# Calculate average execution time for each difficulty level
def calculate_average(times):
    return sum(times) / len(times) if times else 0


average_easy = calculate_average(execution_times["easy"])
average_medium = calculate_average(execution_times["medium"])
average_hard = calculate_average(execution_times["hard"])

# Streamlit UI
st.title("Exploit Graph Query Performance")

# Display the execution times in a bar chart
st.subheader("Average Execution Times by Difficulty Level")

difficulty_levels = ["Easy", "Medium", "Hard"]
average_times = [average_easy, average_medium, average_hard]

plt.figure(figsize=(10, 6))
plt.bar(difficulty_levels, average_times, color=["green", "orange", "red"])
plt.xlabel("Difficulty Level")
plt.ylabel("Average Execution Time (seconds)")
plt.title("Average Execution Time for Each Difficulty Level")
plt.show()

# Display the results
st.pyplot(plt)

# Display the average times in a table
st.subheader("Average Execution Times (seconds)")
st.write(f"Easy: {average_easy:.2f} seconds")
st.write(f"Medium: {average_medium:.2f} seconds")
st.write(f"Hard: {average_hard:.2f} seconds")

# Create LaTeX table
latex_table = f"""
\\documentclass{{article}}
\\usepackage{{booktabs}}

\\begin{{document}}

\\begin{{table}}[h!]
    \\centering
    \\begin{{tabular}}{{lccc}}
        \\toprule
        \\textbf{{Graph}} & \\textbf{{Easy (seconds)}} & \\textbf{{Medium (seconds)}} & \\textbf{{Hard (seconds)}} \\
        \\midrule
        Exploit Graph & {average_easy:.2f} & {average_medium:.2f} & {average_hard:.2f} \\
        \\bottomrule
    \\end{{tabular}}
    \\caption{{Average Execution Times by Difficulty Level for Exploit Graph}}
    \\label{{tab:execution_times}}
\\end{{table}}

\\end{{document}}
"""

st.subheader("LaTeX Table")
st.code(latex_table, language="latex")
