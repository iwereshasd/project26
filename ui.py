import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

from dia.analyzer import Analyzer

st.title("Docker Isolation Analyzer")

mode = st.radio("Mode", ["Offline Demo", "Live Docker"])

if mode == "Offline Demo":
    from dia.offline_collector import OfflineCollector as Collector
else:
    from dia.collector import Collector

collector = Collector()
analyzer = Analyzer()

containers = collector.list_containers()
name = st.selectbox("Select container", containers)

if st.button("Analyze"):
    data = collector.inspect_container(name)
    report = analyzer.analyze(data)

    st.metric("Isolation Risk", f"{report.risk_score}/100")

    df = pd.DataFrame({
        "Domain": [d.name for d in report.domains],
        "Score": [d.score for d in report.domains]
    })

    fig, ax = plt.subplots()
    ax.bar(df["Domain"], df["Score"])
    ax.set_ylim(0,10)
    st.pyplot(fig)

    for d in report.domains:
        st.write(f"**{d.name}**: {d.details}")

    for r in report.recommendations:
        st.warning(r)
