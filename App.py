import streamlit as st
import pandas as pd
import joblib


def add_background(image_file):
    st.markdown(
        f"""
        <style>
        .stApp {{
            background: url({image_file});
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

def introduction_page():
    st.markdown(
        """
        <h2 style="text-align: center; font-weight: bold;">
            Optimization of Intrusion Detection System through feature selection by Machine Learning
        </h2>
        """,
        unsafe_allow_html=True
    )
    st.subheader("Project Discription")

    st.write("""This project focuses on building an Intrusion Detection System (IDS) designed to monitor and analyze network traffic. The goal of the IDS is to classify network connections as either normal or malicious (attack) based on various input features. By leveraging machine learning techniques, particularly the Random Forest algorithm, the system is trained to detect potential threats in real-time, 
             thereby enhancing network security. The project also emphasizes the importance of thorough data preprocessing, feature selection, 
             and model evaluation to ensure high accuracy and reliability in identifying cyber threats. """)

    st.subheader("Problem Statement")

    st.write("As cyber threats grow more complex, traditional security measures often fail to detect sophisticated attacks. There is a critical need for an Intrusion Detection System (IDS) that can accurately classify network traffic as normal or malicious. The goal is to develop a machine learning-based IDS to detect threats in real-time, enhancing network security and protecting against unauthorized access.")
 
    st.subheader("Mentor:      Muhammad Usman")

    st.image("Sir.jpeg", width=300)

    st.subheader("Team Members: ")

    st.write("""
              1. Imad ud din Khattak
              2. Ahmed
              3. Nazish Javed
              4. Hawa
              5. Basit Ali
    """)

    st.subheader("Conclusion")

    st.write(""" The development of this Intrusion Detection System (IDS) demonstrates the effectiveness of machine learning in enhancing network security. By accurately classifying network traffic as normal or malicious, the IDS provides a critical layer of defense against cyber threats. The use of the Random Forest algorithm, combined with thorough data analysis and feature selection, resulted in a high-accuracy model capable of real-time threat detection. This project not only addresses the growing need for advanced security measures but also showcases the potential of data-driven approaches in protecting digital infrastructures.
 """)


def model_page():
    st.title("Network Connection Classification Model")

    model = joblib.load('Forest_model.pkl')
    scaler = joblib.load('scaler.pkl')
    feature_names = joblib.load('feature_names.pkl')

    service_counts = pd.read_csv("service_counts.csv", index_col=0)
    service_counts = service_counts.squeeze().to_dict()

    proto_counts = pd.read_csv("proto_counts.csv", index_col=0)
    proto_counts = proto_counts.squeeze().to_dict()

    state_counts = pd.read_csv("state_counts.csv", index_col=0)
    state_counts = state_counts.squeeze().to_dict()

    st.markdown(
        """
        <style>
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border-radius: 8px;
            padding: 10px 24px;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    def map_counts(value, counts_dict):
        return counts_dict.get(value, 0)  

    def get_user_input():
        input_data = {
            'dur': st.number_input("Duration (dur)", min_value=0.0, max_value=1000.0, value=0.8),
            'state': st.text_input("State", value="FIN"),
            'proto': st.text_input("Protocol (proto)", value="tcp"),
            'rate': st.number_input("Rate", min_value=0.0, max_value=10000.0, value=9.17),
            'sttl': st.number_input("Source TTL (sttl)", min_value=0, max_value=255, value=56),
            'sload': st.number_input("Source load (sload)", min_value=0.0, max_value=100000.0, value=1572.27),
            'dload': st.number_input("Destination load (dload)", min_value=0.0, max_value=100000.0, value=60929.23),
            'dloss': st.number_input("Destination loss (dloss)", min_value=0, max_value=1000, value=6),
            'sinpkt': st.number_input("Source inter-packet arrival time (sinpkt)", min_value=0.0, max_value=10000.0, value=231.88),
            'dmean': st.number_input("Mean of destination bytes (dmean)", min_value=0.0, max_value=100000.0, value=0.0),
            'ct_srv_src': st.number_input("Connection source service count (ct_srv_src)", min_value=0, max_value=100, value=8),
            'ct_state_ttl': st.number_input("Connection state TTL (ct_state_ttl)", min_value=0, max_value=100, value=2),
            'ct_srv_dst': st.number_input("Connection service destination count (ct_srv_dst)", min_value=0, max_value=100, value=6),
        }

        input_data['proto'] = map_counts(input_data['proto'], proto_counts)
        input_data['state'] = map_counts(input_data['state'], state_counts)

        return pd.DataFrame(input_data, index=[0])

    user_input = get_user_input()
    user_input = user_input.reindex(columns=feature_names, fill_value=0)
    user_input_scaled = scaler.transform(user_input)

    if st.button("Predict"):
        prediction = model.predict(user_input_scaled)
        
        st.write("### Prediction")
        if prediction[0] == 0:
            st.success("The connection is classified as **normal**.")
        else:
            st.error("The connection is classified as an **attack**.")

def main():
    add_background('Security.jpeg')  # Add your background image here
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Introduction", "Results"])

    if page == "Introduction":
        introduction_page()
    elif page == "Results":
        model_page()

if __name__ == "__main__":
    main()
