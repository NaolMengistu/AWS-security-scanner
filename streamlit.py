import streamlit as st
import pandas as pd
from fpdf import FPDF
from datetime import datetime
import streamlit.components.v1 as components
import textwrap

# --- Recommended Actions Mapping ---
recommended_actions = {
    "Public access is allowed due to misconfigured Public Access Block settings.":
        "Update the Public Access Block settings to enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
    "No Public Access Block configuration found.":
        "Implement Public Access Block settings for this bucket, enabling all four block options (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) to prevent unintended public access.",
    "Bucket policy allows public access.":
        "Review and revise the S3 bucket policy to remove or restrict statements that grant public access ('Principal': '*' or 'Principal': {'AWS': '*'}). Apply the principle of least privilege.",
    "Bucket encryption is not enabled.":
        "Enable server-side encryption (e.g., AES-256 or AWS KMS) for the S3 bucket to protect data at rest.",
    "Bucket logging is not enabled.":
        "Enable bucket logging to track access and modifications for audit purposes.",
    # The following key is used for a partial string match
    "Error checking bucket logging: ":
        "An error occurred while checking bucket logging status. Investigate the specific error and ensure server access logging is configured correctly for audit and monitoring.",
    "SSH (port 22) publicly accessible":
        "Restrict SSH (port 22) access to only known, trusted IP addresses or ranges. Consider using a VPN or bastion host for more secure access.",
    "RDP (port 3389) publicly accessible":
        "Restrict RDP (port 3389) access to only known, trusted IP addresses or ranges. Consider using a VPN or bastion host for secure remote desktop access.",
    "HTTP (port 80) publicly accessible":
        "If this EC2 instance hosts a web application, ensure it is protected by a Web Application Firewall (WAF) and consider using HTTPS (port 443) with a load balancer. If direct HTTP access is not required, restrict it to specific source IPs or remove the rule.",
    "ICMP (Ping) publicly accessible":
        "Restrict ICMP (Ping) access to specific IP ranges needed for diagnostics. If not essential for monitoring, consider removing public ICMP access to reduce network reconnaissance possibilities.",
    "Wide-open rule (0.0.0.0/0) detected.":
        "Review and tighten security group rules to only allow necessary traffic from specific, trusted sources.",
    # The following key is used for a partial string match
    "grants wildcard permissions.":
        "Review the identified IAM policy. Replace wildcard ('*') permissions for actions or resources with specific, granular permissions following the principle of least privilege.",
    # The following key is used for a partial string match
    "Review attached policy '":
        "Carefully review the attached managed IAM policy for any overly permissive statements, especially those using wildcards. If necessary, detach the policy and create a custom policy with least-privilege permissions.",
    "User does not have MFA enabled.":
        "Enable Multi-Factor Authentication (MFA) on the user account for enhanced security.",
    "User account appears to be inactive (no console or API usage).":
        "Review the account's usage and consider deactivating or removing unused accounts to reduce the attack surface.",
    "Default route to an Internet Gateway detected; verify if intended for public subnets.":
        "Ensure that default routes to an Internet Gateway are only associated with public subnets. For private subnets requiring outbound internet access, use a NAT Gateway or NAT Instance.",
    "Overly permissive rule allowing all traffic from 0.0.0.0/0 detected.":
        "Tighten Network ACL rules to restrict inbound and outbound traffic to only necessary protocols, ports, and specific source/destination IP ranges, following the principle of least privilege.",
    "Subnet is configured to automatically assign public IPs, which may indicate unintended public exposure.":
        "Review subnets with 'auto-assign public IP' enabled. Disable this feature for private subnets to prevent unintended direct exposure to the internet. Ensure resources in these subnets that require public IPs are intentionally configured as such.",
    "VPC Flow Logs are not enabled, which may hinder network traffic monitoring.":
        "Enable VPC Flow Logs for the VPC to capture IP traffic information. This is crucial for network monitoring, security analysis, and troubleshooting."
}

# --- Text wrapping function for DataFrame cells ---
def wrap_text_for_df(text, width=50):
    if not isinstance(text, str):
        text = str(text)
    return textwrap.fill(text, width=width, break_long_words=True, replace_whitespace=False)


# --- Executes the compliance checks from checker.py ---
def run_compliance_checks():
    try:
        # checker.py should be in the same directory
        import checker
        results = {
            "S3_Compliance_Issues": checker.check_s3_compliance(),
            "EC2_SG_Issues": checker.check_ec2_security_groups(),
            "IAM_Issues": checker.check_iam_policies(),
            "VPC_Issues": checker.check_vpc_configurations()
        }
    except ImportError:
        st.warning("checker.py not found. Using dummy data for demonstration.")
        # Fallback to dummy data if the main checker script is missing
        results = {
            "S3_Compliance_Issues": [
                {"Bucket": "my-sample-bucket-1", "Issues": [
                    {"Issue": "Public access is allowed due to misconfigured Public Access Block settings.", "DORA_Mapping": "DORA_S3_1.1"},
                    {"Issue": "Bucket encryption is not enabled.", "DORA_Mapping": "DORA_S3_2.1"}
                ]},
                {"Bucket": "my-sample-bucket-2", "Issues": [
                    {"Issue": "Error checking bucket logging: Access Denied", "DORA_Mapping": "DORA_S3_3.1"}
                ]}
            ],
            "EC2_SG_Issues": [
                {"SecurityGroup": "sg-12345abc", "Issues": [
                    {"Issue": "SSH (port 22) publicly accessible", "DORA_Mapping": "DORA_EC2_1.1"},
                    {"Issue": "Wide-open rule (0.0.0.0/0) detected.", "DORA_Mapping": "DORA_EC2_1.2"}
                ]}
            ],
            "IAM_Issues": [
                 {"User": "test-user", "Issues": [
                    {"Issue": "User does not have MFA enabled.", "DORA_Mapping": "DORA_IAM_MFA_1.0"}
                ]},
                {"Role": "admin-role", "Issues": [
                    {"Issue": "Policy 'AdministratorAccess' grants wildcard permissions.", "DORA_Mapping": "DORA_IAM_WILDCARD_1.0"},
                    {"Issue": "Review attached policy 'arn:aws:iam::aws:policy/PowerUserAccess' for wildcard permissions.", "DORA_Mapping": "DORA_IAM_REVIEW_POLICY_1.0"}
                ]}
            ],
            "VPC_Issues": []
        }
    return results

# --- Generates the PDF report from scan results ---
def generate_pdf_report(results):
    pdf = FPDF(orientation='L') # Landscape mode for wider tables
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "AWS Compliance Scan Report", ln=True, align="C")
    pdf.ln(5)

    # A4 landscape is 297mm wide. With 10mm margins, effective width is 277mm.
    effective_page_width = 297 - 20
    
    headers = ["Resource", "Issue", "DORA Mapping", "Recommendation"]
    col_widths_percent = [0.15, 0.30, 0.20, 0.35] 
    col_widths = [effective_page_width * w for w in col_widths_percent]
    line_height = 5 # mm
    header_height = 7 # mm

    for category, items in results.items():
        pdf.set_font("Arial", "B", 14)
        
        # Add a new page if the category title and table header won't fit
        if pdf.get_y() + 10 + header_height + 5 > pdf.page_break_trigger:
            pdf.add_page()
        pdf.cell(0, 10, category.replace("_", " "), ln=True)

        if items:
            # Draw table header
            pdf.set_font("Arial", "B", 9)
            pdf.set_fill_color(200, 220, 255) # Light blue fill
            current_x = pdf.l_margin
            for i, header_text in enumerate(headers):
                pdf.set_xy(current_x, pdf.get_y())
                pdf.multi_cell(col_widths[i], header_height, header_text, border=1, align='C', fill=True)
                current_x += col_widths[i]
            pdf.ln(header_height)

            pdf.set_font("Arial", "", 8)

            for item_data in items:
                resource_name = (
                    item_data.get("Bucket") or
                    item_data.get("SecurityGroup") or
                    item_data.get("Role") or
                    item_data.get("User") or
                    item_data.get("RouteTable") or
                    item_data.get("NetworkACL") or
                    item_data.get("Subnet") or
                    item_data.get("VPC") or
                    "Unknown Resource"
                )

                for issue_obj in item_data.get("Issues", []):
                    issue_text = issue_obj.get("Issue", "Unknown Issue")
                    mapping = issue_obj.get("DORA_Mapping", "N/A")
                    recommendation_text = "No recommendation available."

                    # Find the appropriate recommendation, checking for partial key matches
                    if issue_text in recommended_actions:
                        recommendation_text = recommended_actions[issue_text]
                    elif "Error checking bucket logging: " in issue_text:
                        base_rec = recommended_actions.get("Error checking bucket logging: ", "Investigate logging error.")
                        specific_error_detail = issue_text.split("Error checking bucket logging: ", 1)[-1]
                        recommendation_text = f"{base_rec} Specific detail: {specific_error_detail}"
                    elif "grants wildcard permissions." in issue_text:
                        recommendation_text = recommended_actions.get("grants wildcard permissions.", "Review wildcard permissions.")
                    elif "Review attached policy '" in issue_text and "for wildcard permissions." in issue_text:
                        recommendation_text = recommended_actions.get("Review attached policy '", "Review attached policy for wildcards.")
                    
                    row_contents = [resource_name, issue_text, mapping, recommendation_text]

                    # Calculate max number of lines needed for the current row to ensure all content fits
                    max_lines_in_row = 0
                    for i, cell_text in enumerate(row_contents):
                        lines = pdf.multi_cell(col_widths[i], line_height, str(cell_text), border=0, align='L', split_only=True)
                        if len(lines) > max_lines_in_row:
                            max_lines_in_row = len(lines)
                    
                    actual_row_height = (max_lines_in_row if max_lines_in_row > 0 else 1) * line_height

                    # Check for page break before drawing the row
                    if pdf.get_y() + actual_row_height > pdf.page_break_trigger:
                        pdf.add_page()
                        # Redraw category title and table header on new page
                        pdf.set_font("Arial", "B", 14)
                        pdf.cell(0, 10, category.replace("_", " "), ln=True)
                        pdf.set_font("Arial", "B", 9)
                        pdf.set_fill_color(200, 220, 255)
                        current_x_newpage = pdf.l_margin
                        for i, header_text_newpage in enumerate(headers):
                            pdf.set_xy(current_x_newpage, pdf.get_y())
                            pdf.multi_cell(col_widths[i], header_height, header_text_newpage, border=1, align='C', fill=True)
                            current_x_newpage += col_widths[i]
                        pdf.ln(header_height)
                        pdf.set_font("Arial", "", 8)

                    # Draw the actual row cells
                    y_before_row = pdf.get_y()
                    current_x = pdf.l_margin
                    # Tracks the lowest Y coordinate reached by any cell in this row, ensuring the next row starts below it
                    max_y_after_cell_in_row = y_before_row

                    for i, cell_text in enumerate(row_contents):
                        # Align all cells to the same starting Y for this row
                        pdf.set_xy(current_x, y_before_row)
                        pdf.multi_cell(col_widths[i], line_height, str(cell_text), border=1, align='L')
                        # Check if this cell made the row taller
                        if pdf.get_y() > max_y_after_cell_in_row:
                             max_y_after_cell_in_row = pdf.get_y()
                        current_x += col_widths[i]
                    
                    # Set the Y position to the bottom of the tallest cell in the row just drawn
                    pdf.set_y(max_y_after_cell_in_row)

            pdf.ln(5) # Add a small space after each table
        else:
            pdf.set_font("Arial", "I", 10)
            if pdf.get_y() + 10 > pdf.page_break_trigger:
                pdf.add_page()
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, category.replace("_", " "), ln=True)
                pdf.set_font("Arial", "I", 10)
            pdf.cell(0, 10, "No issues detected for this category.", ln=True)
            pdf.ln(5)

    pdf_output = pdf.output(dest="S").encode("latin1")
    return pdf_output

# --- Custom CSS for enhanced table styling ---
enhanced_custom_css = """
<style>
    .table-container {
        display: flex;
        justify-content: center;
        width: 100%;
        margin-bottom: 25px; /* Space below each table */
        margin-top: 10px;      /* Space above each table */
    }

    .custom-html-table {
        width: 95% !important;
        table-layout: fixed;
        border-collapse: collapse;
        margin-left: auto;
        margin-right: auto;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1); /* Light mode shadow */
        border-radius: 8px;
        overflow: hidden;
        font-size: 0.9rem;
    }

    .custom-html-table th {
        background-color: #2c3e50; /* Dark blue header */
        color: white;
        font-weight: 600;
        text-align: left;
        padding: 12px 10px;
        border: 1px solid #34495e; /* Slightly darker border for header */
        white-space: pre-wrap !important;
        word-wrap: break-word;
        overflow-wrap: break-word;
        vertical-align: top;
    }

    .custom-html-table td {
        text-align: left;
        padding: 10px 10px;
        border: 1px solid #ddd; /* Light mode border */
        white-space: pre-wrap !important;
        word-wrap: break-word;
        overflow-wrap: break-word;
        vertical-align: top;
        color: #333; /* Default light mode text color for cells */
    }

    .custom-html-table tbody tr:nth-child(even) {
        background-color: #f8f9fa; /* Light mode even row */
    }
    .custom-html-table tbody tr:nth-child(odd) {
        background-color: #ffffff; /* Light mode odd row */
    }

    .custom-html-table tbody tr:hover {
        background-color: #e9ecef; /* Light mode hover */
    }

    /* Column width proportions */
    .custom-html-table th:nth-child(1), .custom-html-table td:nth-child(1) { width: 15% !important; }
    .custom-html-table th:nth-child(2), .custom-html-table td:nth-child(2) { width: 30% !important; }
    .custom-html-table th:nth-child(3), .custom-html-table td:nth-child(3) { width: 20% !important; }
    .custom-html-table th:nth-child(4), .custom-html-table td:nth-child(4) { width: 35% !important; }

    .stDownloadButton > button {
        background-color: #4CAF50; /* Green for download buttons */
        color: white;
        border-radius: 5px;
        padding: 8px 12px;
        font-weight: bold;
        border: none;
        margin-top: 5px;
        margin-bottom: 10px;
    }
    .stDownloadButton > button:hover {
        background-color: #45a049;
    }

    /* DARK MODE SPECIFIC STYLES */
    @media (prefers-color-scheme: dark) {
        .custom-html-table {
            box-shadow: 0 4px 8px rgba(0,0,0,0.3); /* Darker shadow for dark mode */
        }

        .custom-html-table td {
            border: 1px solid #444; /* Darker border for dark mode cells */
            color: #e0e0e0; /* Light text color for dark mode cells */
        }

        .custom-html-table tbody tr:nth-child(even) {
            background-color: #2a2a2e; /* Dark mode even row */
        }
        .custom-html-table tbody tr:nth-child(odd) {
            background-color: #333333; /* Dark mode odd row */
        }

        .custom-html-table tbody tr:hover {
            background-color: #4a4a4e; /* Dark mode hover */
        }
        
        .custom-html-table th {
            border: 1px solid #555; /* Adjust header border for dark mode */
        }
    }
</style>
"""

# --- Main Streamlit Dashboard Logic ---
def main():
    st.set_page_config(layout="wide")
    st.title("AWS Cloud Security Compliance Checker")
    st.markdown("""
    This dashboard displays the results of compliance checks on AWS resources,
    mapping detected misconfigurations to specific DORA compliance requirements alongside recommendations.
    """)

    st.markdown(enhanced_custom_css, unsafe_allow_html=True)

    timestamp_placeholder = st.empty()

    if "results" not in st.session_state:
        with st.spinner("Scanning..."):
            st.session_state.results = run_compliance_checks()
            st.session_state.last_run = datetime.now()
        st.success("✅scan complete!")

    if st.button("Re-Run Scan"):
        with st.spinner("Collecting data from AWS..."):
            st.session_state.results = run_compliance_checks()
            st.session_state.last_run = datetime.now()
        st.success("✅ Check completed!")

    timestamp_placeholder.markdown(f"**Last checked:** {st.session_state.last_run.strftime('%Y-%m-%d %H:%M:%S')}")

    results = st.session_state.results

    WRAP_WIDTH = 100 # Base wrap width for the 'Issue' column

    for category, items in results.items():
        st.subheader(category.replace("_", " "))
        table_data = []
        if items:
            for item in items:
                resource = (
                    item.get("Bucket") or
                    item.get("SecurityGroup") or
                    item.get("Role") or
                    item.get("User") or
                    item.get("RouteTable") or
                    item.get("NetworkACL") or
                    item.get("Subnet") or
                    item.get("VPC") or
                    "Unknown Resource"
                )
                for issue_obj in item.get("Issues", []):
                    issue_text = issue_obj.get("Issue", "Unknown Issue")
                    dora_mapping_text = issue_obj.get("DORA_Mapping", "N/A")
                    recommendation = "No recommendation available."

                    if issue_text in recommended_actions:
                        recommendation = recommended_actions[issue_text]
                    elif "Error checking bucket logging: " in issue_text:
                        base_rec = recommended_actions.get("Error checking bucket logging: ", "Investigate logging error.")
                        specific_error_detail = issue_text.split("Error checking bucket logging: ", 1)[-1] if "Error checking bucket logging: " in issue_text else issue_text
                        recommendation = f"{base_rec} Specific detail: {specific_error_detail}"
                    elif "grants wildcard permissions." in issue_text:
                        recommendation = recommended_actions.get("grants wildcard permissions.", "Review and restrict wildcard permissions.")
                    elif "Review attached policy '" in issue_text and "for wildcard permissions." in issue_text:
                        recommendation = recommended_actions.get("Review attached policy '", "Review the attached policy for overly permissive wildcard statements.")

                    table_data.append({
                        "Resource": wrap_text_for_df(resource, width=int(WRAP_WIDTH * 0.7)),
                        "Issue": wrap_text_for_df(issue_text, width=WRAP_WIDTH),
                        "DORA Mapping": wrap_text_for_df(dora_mapping_text, width=int(WRAP_WIDTH*0.8)),
                        "Recommendation": wrap_text_for_df(recommendation, width=WRAP_WIDTH + 15)
                    })

        if table_data:
            df = pd.DataFrame(table_data)
            
            df_display = df.copy()
            for col in df_display.columns:
                 df_display[col] = df_display[col].apply(lambda x: x.replace('\n', '<br>') if isinstance(x, str) else x)

            html_table = df_display.to_html(escape=False, index=False, classes="custom-html-table")
            centered_html_table = f"<div class='table-container'>{html_table}</div>"
            st.markdown(centered_html_table, unsafe_allow_html=True)
        else:
            st.info("No issues detected for this category.")

    # --- PDF Download Button in Sidebar ---
    st.sidebar.header("Download Full Report")
    if st.sidebar.button("Generate PDF Report", key="generate_pdf_main"):
        with st.spinner("Generating PDF report..."):
            pdf_data = generate_pdf_report(results)
            st.sidebar.download_button(
                label="Download PDF Report",
                data=pdf_data,
                file_name=f"Full_AWS_Compliance_Report_{st.session_state.last_run.strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
                key="pdf_download_main"
            )
        st.sidebar.success("PDF report ready for download!")

if __name__ == '__main__':
    main()