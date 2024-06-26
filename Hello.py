# Copyright (c) Streamlit Inc. (2018-2022) Snowflake Inc. (2022)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Crypto",
        page_icon="🔐",
    )

    st.write("# CRYPTOGRAPHIC APPLICATION 🔐")
    st.write("_"*20)

    st.sidebar.success("Select a cipher.")

    st.markdown(
        """
        This application uses symmetric and asymmetric cryptographic algorithms for facilitating encryption and decryption across plaintext & files.
        It also has features for generating digital fingerprints for both text and files using different hashing functions.

        ### GROUP 1
        - Ken Horlador
        - Jedele Gaspi
        - Venn Delos Santos    
    """
    )


if __name__ == "__main__":
    run()
