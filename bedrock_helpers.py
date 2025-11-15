
import os, json

def generate_rationale(features, fraud_prob, anomaly_score, language="English", model_id=None):
    model_id = model_id or os.getenv("BEDROCK_MODEL_ID","anthropic.claude-3-5-sonnet-20240620-v1:0")
    try:
        import boto3
        bedrock = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION","us-east-1"))
        prompt = f"""You are a fraud analyst assistant.
Language: {language}
Fraud probability: {fraud_prob:.2f}
Anomaly score: {anomaly_score:.2f}
Transaction features (JSON): {json.dumps(features)}

Task:
1) In 2 short sentences, explain the top risk factors in the requested language.
2) Output one recommended action (Approve / Review / Block).
Respond in JSON with keys: rationale, action.
"""
        body = {
            "anthropic_version":"bedrock-2023-05-31",
            "max_tokens": 256,
            "messages":[{"role":"user","content":[{"type":"text","text":prompt}]}]
        }
        resp = bedrock.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body)
        )
        out = json.loads(resp["body"].read().decode("utf-8"))
        text = out["content"][0]["text"]
        if "action" in text and "rationale" in text:
            try:
                data = json.loads(text)
                return data.get("rationale",""), data.get("action","Review")
            except Exception:
                pass
        return text.strip(), "Review"
    except Exception:
        rationale = f"Likely risky due to amount/device/geo patterns. Scores: fraud={fraud_prob:.2f}, anomaly={anomaly_score:.2f}."
        return rationale, "Review"
