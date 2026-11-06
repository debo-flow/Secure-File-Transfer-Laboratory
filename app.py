"""Main Streamlit Application Dashboard for the File Transfer Laboratory."""
import streamlit as st
import os
from pathlib import Path

from core.config import CONFIG
from core.logger import get_logger
from core.exceptions import SecureFileLabError
from modules.file_analyzer import sanitize_filename, validate_file, get_file_metadata, is_safe_path
from modules.hashing import calculate_hashes

logger = get_logger("ui_dashboard")

def initialize_ui():
    """Sets up the primary dashboard layout and sidebar."""
    st.set_page_config(
        page_title=CONFIG.app_name,
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🛡️ Secure File Transfer & Data Protection Laboratory")
    st.markdown(f"**Milestone {CONFIG.milestone}:** Foundation & System Architecture")

    with st.sidebar:
        st.header("System Overview")
        st.info("This is a laboratory environment for researching secure file transfer paradigms.")
        
        st.subheader("Security Configuration")
        st.write(f"- **Max File Size:** {CONFIG.security.max_file_size_mb} MB")
        st.write(f"- **Allowed Extensions:** {', '.join(CONFIG.security.allowed_extensions)}")
        st.write("- **Active Modules:** Validation, Inspection, Hashing")
        
        st.subheader("Technology Stack")
        st.code("Python 3.10+\nStreamlit\nPytest\nHashlib", language="text")
        
        st.divider()
        st.caption("⚠️ Note: This application is a developmental foundation, not a production-secure deployment.")

def process_uploaded_file(uploaded_file):
    """Handles the secure saving, validation, and processing of an uploaded file."""
    if uploaded_file is None:
        return
        
    # 1. Sanitize & Secure Path Allocation
    safe_name = sanitize_filename(uploaded_file.name)
    temp_path = CONFIG.security.temp_storage_dir / safe_name
    
    # Path traversal safety check
    if not is_safe_path(CONFIG.security.temp_storage_dir, temp_path):
        st.error("Security Violation: Invalid file path detected.")
        logger.error(f"Path traversal attempted with filename: {uploaded_file.name}")
        return

    try:
        # 2. Safely save stream to disk (simulating local file system ingestion)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        logger.info(f"File securely temporarily staged: {safe_name}")

        # 3. Validation
        with st.spinner("Running security validations..."):
            validate_file(temp_path)
        st.success("File passed security validation checks.")

        col1, col2 = st.columns(2)

        # 4. Metadata Extraction
        with col1:
            st.subheader("📄 File Information")
            metadata = get_file_metadata(temp_path)
            for key, value in metadata.items():
                st.write(f"**{key}:** {value}")

        # 5. Cryptographic Hashing
        with col2:
            st.subheader("🔐 Cryptographic Signatures (Chunk-Based)")
            with st.spinner("Calculating hashes..."):
                hashes = calculate_hashes(temp_path)
                for algo, digest in hashes.items():
                    st.code(f"{algo}:\n{digest}", language="text")

    except SecureFileLabError as e:
        st.error(f"Validation Error: {str(e)}")
        logger.warning(f"Validation failed for {safe_name}: {str(e)}")
    except Exception as e:
        st.error("An unexpected system error occurred. Operations halted.")
        logger.error(f"Unexpected error processing {safe_name}: {str(e)}")
    finally:
        # 6. Secure Cleanup
        if temp_path.exists():
            try:
                temp_path.unlink()
                logger.info(f"Temporary file destroyed: {safe_name}")
            except Exception as cleanup_error:
                logger.error(f"Failed to destroy temporary file {safe_name}: {str(cleanup_error)}")

def main():
    initialize_ui()
    
    st.markdown("### Secure File Ingestion Engine")
    st.write("Upload a file to test the validation, metadata extraction, and chunk-based hashing engines.")
    
    uploaded_file = st.file_uploader(
        "Select a file for analysis", 
        help="Files are inspected and hashed, never executed."
    )
    
    if uploaded_file:
        process_uploaded_file(uploaded_file)

if __name__ == "__main__":
    main()
