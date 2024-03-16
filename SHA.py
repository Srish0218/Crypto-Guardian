import streamlit as st
import hashlib
import plotly.graph_objects as go
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Install matplotlib using pip

st.set_page_config(
    page_title="CryptoGuardian",
    page_icon="🛡️",
    layout="wide"
)


def calculate_hash(hash_function, data):
    if hash_function == "SHA-256":
        return hashlib.sha256(data)
    elif hash_function == "SHA-384":
        return hashlib.sha384(data)
    elif hash_function == "SHA-224":
        return hashlib.sha224(data)
    elif hash_function == "SHA-512":
        return hashlib.sha512(data)
    elif hash_function == "SHA-1":
        return hashlib.sha1(data)
    elif hash_function == "MD5":
        return hashlib.md5(data)
    elif hash_function == "SHA3-256":
        return hashlib.sha3_256(data)
    elif hash_function == "SHA3-512":
        return hashlib.sha3_512(data)
    elif hash_function == "BLAKE2b":
        return hashlib.blake2b(data)
    elif hash_function == "BLAKE2s":
        return hashlib.blake2s(data)


def create_pie_chart(labels, sizes):
    fig = go.Figure(data=[go.Pie(labels=labels, values=sizes)])
    fig.update_layout(title='Algorithm Distribution')
    return fig


def visualizer(hash_functions, hash_lengths):

    st.markdown("## Visualization")
    c1, c2, c3, c4, c5, c6, c7, c8, c9, c10 = st.columns(10)

    with c1:
        with st.expander("Hash Lengths"):
            fig_lengths = go.Figure()
            fig_lengths.add_trace(
                go.Scatter(x=hash_functions, y=hash_lengths, mode='lines+markers', name='Hash Lengths'))
            fig_lengths.update_layout(xaxis_title='Hash Function', yaxis_title='Hash Length (bits)',
                                      title='Hash Algorithm Lengths')
            st.plotly_chart(fig_lengths)

    with c3:
        with st.expander("Algorithm Distribution"):
            fig_pie = go.Figure(data=[go.Pie(labels=hash_functions, values=hash_lengths)])
            fig_pie.update_layout(title='Algorithm Distribution')
            st.plotly_chart(fig_pie)

    with c5:
        with st.expander("Historical Hashing"):
            time_points = ["Time 1", "Time 2", "Time 3", "Time 4", "Time 5"]
            hash_values = np.random.rand(len(time_points), len(hash_functions)) * 1000
            fig_historical = go.Figure()
            for i, algo in enumerate(hash_functions):
                fig_historical.add_trace(
                    go.Scatter(x=time_points, y=hash_values[:, i], mode='lines+markers', name=algo))
            fig_historical.update_layout(xaxis_title='Time', yaxis_title='Hash Values',
                                         title='Historical Hashing Comparison')
            st.plotly_chart(fig_historical)

    with c7:
        with st.expander("Radar Chart"):
            attributes = ['Speed', 'Security', 'Flexibility', 'Collision Resistance']
            scores = np.random.rand(len(hash_functions), len(attributes))
            fig_radar = go.Figure()
            for i, algo in enumerate(hash_functions):
                fig_radar.add_trace(go.Scatterpolar(r=scores[i], theta=attributes, mode='lines+markers', name=algo))
            fig_radar.update_layout(title='Comparison of Hash Algorithms', polar=dict(radialaxis=dict(visible=True)),
                                    showlegend=True)
            st.plotly_chart(fig_radar)

    with c9:
        with st.expander("Hash Collisions"):
            collision_likelihood = np.random.rand(len(hash_functions), len(hash_functions))
            fig_heatmap = go.Figure(data=go.Heatmap(z=collision_likelihood, x=hash_functions, y=hash_functions))
            fig_heatmap.update_layout(title='Hash Collision Likelihood')
            st.plotly_chart(fig_heatmap)

    st.markdown(" Hash Digests")

    col1, col2 = st.columns(2)

    with col1:
        for algo in hash_functions[5:]:
            with st.expander(algo):
                simulated_distribution = np.random.randint(5, 25, size=16)
                digest_distribution_data = simulated_distribution / sum(simulated_distribution) * 100
                if len(digest_distribution_data) > 0:
                    fig_pie_digest = go.Figure(
                        data=[go.Pie(labels=[f"{i:x}" for i in range(16)], values=digest_distribution_data)])
                    fig_pie_digest.update_layout(title=f"{algo} Digest Distribution")
                    st.plotly_chart(fig_pie_digest)

    with col2:
        for algo in hash_functions[:5]:
            with st.expander(algo):
                simulated_distribution = np.random.randint(5, 25, size=16)
                digest_distribution_data = simulated_distribution / sum(simulated_distribution) * 100
                if len(digest_distribution_data) > 0:
                    fig_pie_digest = go.Figure(
                        data=[go.Pie(labels=[f"{i:x}" for i in range(16)], values=digest_distribution_data)])
                    fig_pie_digest.update_layout(title=f"{algo} Digest Distribution")
                    st.plotly_chart(fig_pie_digest)


def results_for_uploading_file(input_data, hash_functions, hash_lengths):
    with st.status("Generating...", expanded=True) as status2:
        st.write("Hashing from file...")
        time.sleep(0.5)
        st.write("Visualizing...")
        time.sleep(1)
        st.write("Hash Digest Values...")
        time.sleep(0.5)
        status2.update(label="Completed!!!", state="complete", expanded=False)
    st.markdown("#### Hash and Digest Values: ")
    # Hash function selection
    col1, col2 = st.columns(2)
    with col1:
        for algo in hash_functions[:5]:
            with st.expander(algo):
                hash_obj = calculate_hash(algo, input_data)  # Fix: use 'data' instead of 'input_data'
                hashed_value = hash_obj.hexdigest()
                st.write(f"{algo} Hex Hash:")
                st.info(hashed_value)
                try:
                    # Attempt to use the digest() method for algorithms that support it
                    hash_digest = hash_obj.digest()
                    st.write(f"{algo} Digest: ")
                    st.info(hash_digest)
                except AttributeError:
                    # For algorithms that don't support digest(), display a warning
                    st.warning(f"{algo} Digest: Not supported!!!")
    with col2:
        for algo in hash_functions[5:]:
            with st.expander(algo):
                hash_obj = calculate_hash(algo, input_data)  # Fix: use 'data' instead of 'input_data'
                hashed_value = hash_obj.hexdigest()
                st.write(f"{algo} Hex Hash:")
                st.info(hashed_value)

                try:
                    # Attempt to use the digest() method for algorithms that support it
                    hash_digest = hash_obj.digest()
                    st.write(f"{algo} Digest: ")
                    st.info(hash_digest)
                except AttributeError:
                    # For algorithms that don't support digest(), display a warning
                    st.warning(f"{algo} Digest: Not supported!!!")
    visualizer(hash_functions, hash_lengths)


def results_for_string(data, hash_functions, hash_lengths):
    with st.status("Generating data...", expanded=True) as status:
        st.write("Hashing...")
        time.sleep(0.5)
        st.write("Visualizing...")
        time.sleep(1)
        st.write("Hash Digest Values...")
        time.sleep(0.5)
        status.update(label="Completed!!!", state="complete", expanded=False)
    st.markdown("#### Hash and Digest Values: ")
    # Hash function selection
    col1, col2 = st.columns(2)
    with col1:
        for algo in hash_functions[:5]:
            with st.expander(algo):
                hash_obj = calculate_hash(algo, data.encode())  # Fix: use 'data' instead of 'input_data'
                hashed_value = hash_obj.hexdigest()
                st.write(f"{algo} Hex Hash:")
                st.info(hashed_value)
                try:
                    # Attempt to use the digest() method for algorithms that support it
                    hash_digest = hash_obj.digest()
                    st.write(f"{algo} Digest: ")
                    st.info(hash_digest)
                except AttributeError:
                    # For algorithms that don't support digest(), display a warning
                    st.warning(f"{algo} Digest: Not supported!!!")
    with col2:
        for algo in hash_functions[5:]:
            with st.expander(algo):
                hash_obj = calculate_hash(algo, data.encode())  # Fix: use 'data' instead of 'input_data'
                hashed_value = hash_obj.hexdigest()
                st.write(f"{algo} Hex Hash:")
                st.info(hashed_value)

                try:
                    # Attempt to use the digest() method for algorithms that support it
                    hash_digest = hash_obj.digest()
                    st.write(f"{algo} Digest: ")
                    st.info(hash_digest)
                except AttributeError:
                    # For algorithms that don't support digest(), display a warning
                    st.warning(f"{algo} Digest: Not supported!!!")
    visualizer(hash_functions, hash_lengths)


# Streamlit App
st.title("CryptoGuardian 🛡️️")

Feature = st.selectbox("What do you want to do:", ("Hashing Data", "Compare Hashing"))

if Feature == "Hashing Data":
    method = st.selectbox("Select method", ("I want to enter data", "I want to upload file"))
    hash_functions = ["SHA-256", "SHA-384", "SHA-224", "SHA-512", "SHA-1", "MD5", "SHA3-256", "SHA3-512", "BLAKE2b",
                      "BLAKE2s"]
    hash_lengths = [256, 384, 224, 512, 160, 128, 256, 512, 512, 256]

    if method == "I want to enter data":
        # Input string
        input_data = st.text_area("Enter Data:")
        if st.button("Generate Hash"):
            if input_data:
                results_for_string(input_data, hash_functions, hash_lengths)
            else:
                st.error("Please enter data before generating hash.")

    elif method == "I want to upload file":
        label = "Choose a file"
        uploaded_file = st.file_uploader(label)
        if uploaded_file is not None:
            data = uploaded_file.read()
            if st.button("Generate Hash"):
                results_for_uploading_file(data, hash_functions, hash_lengths)

elif Feature == "Compare Hashing":
    st.text("Enter two hash values to compare:")
    hash1 = st.text_input("Hash 1:")
    hash2 = st.text_input("Hash 2:")
    if st.button("Compare"):
        with st.status("Comparing...", expanded=True) as status3:
            st.write("Checking Integrity...")
            time.sleep(0.5)
            st.write("Visualizing...")
            time.sleep(1)
            st.write("Comparing Frequency ...")
            time.sleep(0.5)
            status3.update(label="Completed!!!", state="complete", expanded=False)
        if hash1 and hash2:
            if hash1 == hash2:
                st.success("Hashes match! Data integrity is preserved.")
            else:
                st.error("Hashes do not match! Data integrity may be compromised.")

            # Create a heatmap to visualize the similarity between the two hash values
            similarity_matrix = np.zeros((len(hash1), len(hash2)))
            for i in range(len(hash1)):
                for j in range(len(hash2)):
                    similarity_matrix[i, j] = 1 if hash1[i] == hash2[j] else 0

            fig = go.Figure(data=go.Heatmap(z=similarity_matrix, colorscale='Viridis'))
            fig.update_layout(title='Similarity between Hash Values')

            c1, c2 = st.columns(2)
            with c1:
                st.plotly_chart(fig)
            # Display the DataFrame
            with c2:
                with st.expander("Get Info!!!"):
                    st.markdown(
                        """
                    <div class="container-with-border2">



**1.     Heatmap Visualization:** The heatmap provides a graphical representation of the similarity between the 
characters of two hash values. Each cell in the heatmap represents the comparison between a character from Hash 1 and 
a character from Hash 2.

**2.   Color Gradient:** The colors in the heatmap represent the level of similarity between characters:

    - Cells with a value of 1 are colored in the darkest shade, indicating an exact match between characters.
    - Cells with a value of 0 are colored in the lightest shade, indicating no match between characters.
**3.    Axes:** The heatmap has two axes:

    - The x-axis represents the characters of Hash 2.
    - The y-axis represents the characters of Hash 1.
***Possible Outputs:***

**- Perfect Match:** If both hash values are identical, the heatmap will show a diagonal line of dark-colored 
    cells from the top-left corner to the bottom-right corner. This indicates that each character in Hash 1 matches 
    the corresponding character in Hash 2.

**- Partial Match:** If some characters match but not all, the heatmap will show dark-colored cells clustered 
    along the diagonal line, indicating matching characters. The remaining cells will be light-colored, indicating 
    non-matching characters.

**- No Match:** If none of the characters match between the two hash values, the heatmap will be entirely 
    light-colored, indicating no similarity between the hash values.

 """, unsafe_allow_html=True
                    )

            # Create a DataFrame to store the frequency of characters in hash values
            chars = sorted(set(hash1 + hash2))
            freq_hash1 = [hash1.count(char) for char in chars]
            freq_hash2 = [hash2.count(char) for char in chars]
            df = pd.DataFrame({'Character': chars, 'Hash 1 Frequency': freq_hash1, 'Hash 2 Frequency': freq_hash2})
            df = df.set_index('Character')

            # Create a heatmap to visualize the frequency of characters
            plt.figure(figsize=(10, 6))
            sns.heatmap(df, cmap='viridis', annot=True, fmt='d')
            plt.title('Character Frequency Comparison')
            plt.xlabel('Hash Value')
            plt.ylabel('Character')

            c1, c2 = st.columns(2)
            with c1:
                st.pyplot(plt)
            # Display the DataFrame
            with c2:
                st.write(df)

st.markdown("""
    <style>
        .container-with-border2 {
            width: 95%;
            margin: 20px;
            padding: 30px;
            max-height: 450px; /* Set the maximum height for the container */
            overflow-y: auto; /* Add vertical scroll if content exceeds the maximum height */
            background: rgba(255, 255, 255, 0.15);
    backdrop-filter: blur(90%);
    border-radius: 10px;
    box-shadow: 0 8px 32px 0 rgba(255, 255, 255, 0.15);
    backdrop-filter: blur( 4px );
    -webkit-backdrop-filter: blur( 4px );
    border: 1px solid rgba( 255, 255, 255, 0.18 );
        }
    </style>
""", unsafe_allow_html=True)

# Define input_data outside the "I want to enter data" block

footer = """<style>
a:link , a:visited{
color: black;
font-weight: bold;
background-color: transparent;
text-decoration: underline;
}

a:hover,  a:active {
color: red;
background-color: transparent;
text-decoration: underline;
}


.footer a {
    color: #007bff;
    text-decoration: none;
    font-weight: bold;
}
.footer {
position: fixed;
left: 0;
bottom: 0;
width: 100%;
background-color: dark grey;
color: white;
text-align: center;
}
</style>
<div class="footer">
<p>Developed with ❤ by <a style='display: block; text-align: center;' href="https://github.com/Srish0218" target="_blank">Srishti Jaitly 🌸</a></p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
