import streamlit as st
from py2neo import Graph
import time
import matplotlib.pyplot as plt

# Connect to Neo4j
graph = Graph("bolt://localhost:7688", auth=("neo4j", "scottdirT98"))

# Function to measure the execution time of queries
def measure_query_time(query_function, *args):
    start_time = time.time()
    result = query_function(*args)
    end_time = time.time()
    execution_time = end_time - start_time
    return execution_time, result

# Define queries for different difficulty levels
def get_malware_nodes():
    query = """
    MATCH (m:Malware)
    RETURN m.name, m.description
    """
    return graph.run(query).data()

def get_technique_nodes():
    query = """
    MATCH (t:Technique)
    RETURN t.technique_id, t.name, t.description
    """
    return graph.run(query).data()

def get_procedure_nodes():
    query = """
    MATCH (p:Procedure)
    RETURN p.id, p.name, p.description
    """
    return graph.run(query).data()

def get_mitigation_nodes():
    query = """
    MATCH (m:Mitigation)
    RETURN m.name, m.description
    """
    return graph.run(query).data()

def get_detection_nodes():
    query = """
    MATCH (d:Detection)
    RETURN d.name, d.description
    """
    return graph.run(query).data()

def get_techniques_for_malware():
    query = """
    MATCH (m:Malware)-[:HAS_TECHNIQUE]->(t:Technique)
    RETURN m.name, t.technique_id, t.name
    """
    return graph.run(query).data()

def get_procedures_for_techniques():
    query = """
    MATCH (t:Technique)-[:HAS_PROCEDURE]->(p:Procedure)
    RETURN t.technique_id, t.name, p.id, p.name
    """
    return graph.run(query).data()

def get_mitigations_for_techniques():
    query = """
    MATCH (t:Technique)-[:HAS_MITIGATION]->(m:Mitigation)
    RETURN t.technique_id, t.name, m.name
    """
    return graph.run(query).data()

def get_detections_for_techniques():
    query = """
    MATCH (t:Technique)-[:HAS_DETECTION]->(d:Detection)
    RETURN t.technique_id, t.name, d.name
    """
    return graph.run(query).data()

def get_all_relationships(limit=1000):
    query = """
    MATCH (a)-[r]->(b)
    RETURN a.name, type(r), b.name
    LIMIT $limit
    """
    return graph.run(query, limit=limit).data()

# Classify the queries
query_classification = {
    "easy": [
        get_malware_nodes,
        get_technique_nodes,
        get_procedure_nodes,
        get_mitigation_nodes,
        get_detection_nodes
    ],
    "medium": [
        get_techniques_for_malware,
        get_procedures_for_techniques,
        get_mitigations_for_techniques,
        get_detections_for_techniques
    ],
    "hard": [
        get_all_relationships
    ]
}

# Measure execution time for each query
execution_times = {
    "easy": [],
    "medium": [],
    "hard": []
}

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
st.title("MITRE Graph Query Performance")

# Display the execution times in a bar chart
st.subheader("Average Execution Times by Difficulty Level")

difficulty_levels = ["Easy", "Medium", "Hard"]
average_times = [average_easy, average_medium, average_hard]

plt.figure(figsize=(10, 6))
plt.bar(difficulty_levels, average_times, color=['green', 'orange', 'red'])
plt.xlabel('Difficulty Level')
plt.ylabel('Average Execution Time (seconds)')
plt.title('Average Execution Time for Each Difficulty Level')
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
        Malware Graph & {average_easy:.2f} & {average_medium:.2f} & {average_hard:.2f} \\
        \\bottomrule
    \\end{{tabular}}
    \\caption{{Average Execution Times by Difficulty Level for Malware Graph}}
    \\label{{tab:execution_times}}
\\end{{table}}

\\end{{document}}
"""

st.subheader("LaTeX Table")
st.code(latex_table, language='latex')