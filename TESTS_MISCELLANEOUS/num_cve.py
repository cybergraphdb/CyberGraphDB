import time

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


# Define query to get the number of nodes, edges, and properties for the CVE Graph
def get_cve_graph_info():
    query_nodes = """
    MATCH (n)
    WHERE n:CVE OR n:Product OR n:CVE_Description OR n:CVE_ProblemType OR n:CVE_Reference
    RETURN count(n) AS num_nodes
    """

    query_edges = """
    MATCH ()-[r]->()
    WHERE type(r) IN ['AFFECTS', 'DESCRIBED_BY', 'HAS_PROBLEM_TYPE', 'HAS_REFERENCE']
    RETURN count(r) AS num_edges
    """

    query_properties = """
    MATCH (n)
    WHERE n:CVE OR n:Product OR n:CVE_Description OR n:CVE_ProblemType OR n:CVE_Reference
    RETURN sum(size(keys(n))) AS num_properties
    """

    num_nodes = graph.run(query_nodes).data()[0]["num_nodes"]
    num_edges = graph.run(query_edges).data()[0]["num_edges"]
    num_properties = graph.run(query_properties).data()[0]["num_properties"]

    return num_nodes, num_edges, num_properties


# Get info for CVE Graph
num_nodes, num_edges, num_properties = get_cve_graph_info()

# Streamlit UI
st.title("CVE Graph Information")

# Display the information
st.write(f"Number of Nodes: {num_nodes}")
st.write(f"Number of Edges: {num_edges}")
st.write(f"Total Number of Properties: {num_properties}")

# Create LaTeX table
latex_table = f"""
\\documentclass{{article}}
\\usepackage{{booktabs}}

\\begin{{document}}

\\begin{{table}}[h!]
    \\centering
    \\begin{{tabular}}{{lccc}}
        \\toprule
        \\textbf{{Graph}} & \\textbf{{Number of Nodes}} & \\textbf{{Number of Edges}} & \\textbf{{Total Number of Properties}} \\
        \\midrule
        CVE Graph & {num_nodes} & {num_edges} & {num_properties} \\
        \\bottomrule
    \\end{{tabular}}
    \\caption{{CVE Graph Information}}
    \\label{{tab:graph_info}}
\\end{{table}}

\\end{{document}}
"""

st.subheader("LaTeX Table")
st.code(latex_table, language="latex")
