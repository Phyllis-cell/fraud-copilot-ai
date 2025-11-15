
# Fraud Copilot – Analyst Console (Streamlit)

Run locally (no AWS needed) or connect to AWS Bedrock + DynamoDB if configured.

## Quickstart (local demo)
```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```
This uses `sample_cases.csv` and generates rationales locally (fallback).

## Use with AWS
Set environment variables:
```
export AWS_REGION=us-east-1
export DDB_TABLE=FraudCases
export BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20240620-v1:0
```
Then launch Streamlit and toggle "Use AWS DynamoDB" in the sidebar. The app will:
- Scan DynamoDB table `FraudCases` for cases
- Call Amazon Bedrock to regenerate multilingual rationales

```bash
streamlit run streamlit_app.py
```
