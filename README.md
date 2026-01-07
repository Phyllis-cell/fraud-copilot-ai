# Fraud Copilot – Analyst Console (Streamlit)

**Author:** Phyllis Barikisu Snyper  
**Project Type:** Personal, non-work community project

## What You’ll Learn
This project demonstrates how to design a GenAI-powered analyst console using AWS services. Builders will learn:
- How to integrate Amazon Bedrock into an application workflow
- How to design AI-generated decision rationales for fraud analysis
- How to switch between local inference and AWS-backed services
- How to structure an AI assistant for real-world decision support

## Architecture Overview
Fraud Copilot is built as a lightweight analyst console using Streamlit.

In AWS mode:
- Amazon DynamoDB stores fraud case records
- Amazon Bedrock generates multilingual AI rationales
- The application toggles between local and AWS-backed execution

This design allows builders to experiment locally while understanding how to scale to AWS services.


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

---
This is a personal project created outside of my employment to help other builders learn how to design AI-powered applications on AWS.
