# app.py — Fraud Copilot AI
# (Auth hardening + Session timeout + Role guards + Signals + Enrichment + Decision Webhooks)
# (NEW: Top bar with 3-dot menu, Contact + Logout moved to menu, Slim sidebar; CSV selector now drives table)
# (UPDATE: Full i18n wiring + French pack + Polly voice per language + localized table browser + localized assistant)

import os, json, time, math, hashlib
from datetime import datetime, timedelta
from decimal import Decimal

import pandas as pd
import streamlit as st
import io
import numpy as np

import textwrap

import textwrap

# ==================== CloudWatch Metrics Emitter ====================
import boto3, time

def emit_metrics_to_cloudwatch(latency_ms: float, tokens_used: int, drift_z: float = 0.0):
    """Send live KPIs to AWS CloudWatch."""
    try:
        region = os.getenv("AWS_REGION") or "us-east-1"
        cw = boto3.client("cloudwatch", region_name=region)
        cw.put_metric_data(
            Namespace="FraudCopilotAI",
            MetricData=[
                {"MetricName": "Requests", "Value": 1, "Unit": "Count"},
                {"MetricName": "FraudScoreLatencyMs", "Value": latency_ms, "Unit": "Milliseconds"},
                {"MetricName": "BedrockTokenUsage", "Value": tokens_used, "Unit": "Count"},
                {"MetricName": "ModelDriftZ", "Value": drift_z, "Unit": "None"},
            ],
        )
    except Exception as e:
        st.warning(f"CloudWatch metric emit error: {e}")
# ====================================================================

st.set_page_config(page_title="Fraud Copilot 🔍 Analyst Console", layout="wide")



# ======================================================
# Local dataset selector (cross-platform safe)
# ======================================================
def resolve_first_existing(paths):
    """Return the first path that exists from a list."""
    for p in paths:
        if os.path.exists(p):
            return p
    return None

DATASETS = {
    "Registration Fraud (20K full)": resolve_first_existing([
        "registration_data_20K_full.csv",
        "./data/registration_data_20K_full.csv",
        r"C:\Users\amaba\Downloads\registration_data_20K_full.csv",
        "registration_data_20K_minimum.csv",
        "./data/registration_data_20K_minimum.csv",
        r"C:\Users\amaba\Downloads\registration_data_20K_minimum.csv",
    ]),
    "Payment Fraud (100K full)": resolve_first_existing([
        "transaction_data_100K_full.csv",
        "./data/transaction_data_100K_full.csv",
        r"C:\Users\amaba\Downloads\transaction_data_100K_full.csv",
    ]),
}

# ---- Dataset selector (drives preview AND the main table when AWS is OFF)
st.sidebar.markdown("### 📁 Data")
fraud_type = st.sidebar.selectbox(
    "Select Fraud Dataset",
    list(DATASETS.keys()),
    index=0,
    key="dataset_select_main"
)
dataset_path = DATASETS[fraud_type]
st.session_state["active_dataset_path"] = dataset_path  # <-- used by load_cases_local()

if dataset_path and os.path.exists(dataset_path):
    df_csv = pd.read_csv(dataset_path)
    st.sidebar.success(f"✅ Loaded: {os.path.basename(dataset_path)}")
else:
    st.sidebar.error("❌ Dataset not found. Check your path settings.")
    df_csv = pd.DataFrame()

with st.expander("Dataset Preview (first 20 rows)", expanded=False):
    st.dataframe(df_csv.head(20), use_container_width=True)

# --------- dotenv is OPTIONAL now ----------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ====================== AWS / Bedrock / Polly scaffolding ======================
try:
    import boto3
    from botocore.exceptions import BotoCoreError, NoCredentialsError, ClientError
except Exception:
    boto3 = None
    class BotoCoreError(Exception): ...
    class NoCredentialsError(Exception): ...
    class ClientError(Exception): ...

# ------------------ Polly Voice Functions ------------------
def _get_polly_client():
    """
    Build a Polly client using either explicit env vars or default AWS config/metadata.
    Falls back to us-east-1 (Joanna supported).
    """
    if boto3 is None:
        raise RuntimeError("boto3 not installed. pip install boto3 botocore")

    region = os.getenv("AWS_REGION_POLLY") or os.getenv("AWS_REGION") or "us-east-1"
    ak = os.getenv("AWS_ACCESS_KEY_ID")
    sk = os.getenv("AWS_SECRET_ACCESS_KEY")
    tk = os.getenv("AWS_SESSION_TOKEN")

    if ak and sk:
        session = boto3.session.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=tk,
            region_name=region,
        )
    else:
        session = boto3.session.Session(region_name=region)

    return session.client("polly")

def polly_speak(text: str, voice: str = None) -> bytes:
    """Return MP3 bytes for given text using Amazon Polly."""
    if not text or not text.strip():
        return b""
    voice = voice or os.getenv("POLLY_VOICE", "Joanna")

    # Split long text into safe chunks (< 3000 chars; use 2500 to be safe)
    chunks, remaining, max_len = [], text.strip(), 2500
    while remaining:
        chunk = remaining[:max_len]
        cut = max(chunk.rfind(". "), chunk.rfind("! "), chunk.rfind("? "))
        if cut > 0 and len(remaining) > max_len:
            chunk = chunk[:cut+1]
        chunks.append(chunk)
        remaining = remaining[len(chunk):].lstrip()

    out = io.BytesIO()
    try:
        polly = _get_polly_client()
        for c in chunks:
            resp = polly.synthesize_speech(Text=c, VoiceId=voice, OutputFormat="mp3")
            stream = resp.get("AudioStream")
            if stream:
                out.write(stream.read())
        return out.getvalue()
    except (NoCredentialsError, ClientError, BotoCoreError) as e:
        try:
            st.warning(f"Polly error: {e}")
        except Exception:
            pass
        return b""

# Map UI language to the best Polly voice available
def pick_polly_voice(lang_code: str) -> str:
    return {
        "fr": "Lea",       # French
        "es": "Lucia",     # Spanish
        "de": "Vicki",     # German
        "it": "Carla",     # Italian
        "pt": "Vitoria",   # Portuguese (BR)
        "tr": "Filiz",     # Turkish
        "ru": "Tatyana",   # Russian
        "zh": "Zhiyu",     # Mandarin
        "ja": "Mizuki",    # Japanese
        "ko": "Seoyeon",   # Korean
        "hi": "Aditi",     # Hindi (en/hi)
        "ar": "Zeina",     # Arabic
        # fall back to env or Joanna
    }.get(lang_code, os.getenv("POLLY_VOICE", "Joanna"))

# ============================ Theming & page ============================
ACCENT = "#FF9900"
INK = "#0B0D17"
CHIP1 = "#FDE68A"
CHIP2 = "#A7F3D0"
CHIP3 = "#BFDBFE"
CARD = "#0F172A"
BORDER = "#1F2937"

st.markdown(f"""
<style>
  .banner {{background:linear-gradient(90deg,#0b0d17 0%,#1b2838 50%,#0b0d17 100%);border:1px solid {BORDER};border-radius:18px;padding:18px 20px;margin-bottom:10px;box-shadow:0 10px 30px rgba(0,0,0,.25);}}
  .title {{ color:{ACCENT};font-weight:800;letter-spacing:.3px;font-size:28px;margin:0 0 6px 0; }}
  .subtitle {{ color:#e5e7eb;font-size:14px;margin:0; }}
  .chip {{ display:inline-block;padding:8px 12px;border-radius:999px;margin-right:6px;font-weight:700;border:1px solid {BORDER}; }}
  .chip1 {{ background:{CHIP1};color:{INK}; }} .chip2 {{ background:{CHIP2};color:{INK}; }} .chip3 {{ background:{CHIP3};color:{INK}; }}
  .kcard {{ background:{CARD};border:1px solid {BORDER};border-radius:16px;padding:14px 16px;color:#fff;box-shadow:0 12px 30px rgba(0,0,0,.2); }}
  .klabel {{ font-size:12px;color:#9ca3af;margin:0; }} .kvalue {{ font-size:26px;font-weight:800;margin:2px 0 0 0;color:#fff; }}
  .badge {{ display:inline-block;padding:6px 10px;border-radius:999px;margin-right:6px;font-size:12px;font-weight:700; }}
  .bad {{ background:#3b0d0d;color:#fca5a5;border:1px solid #7f1d1d; }} .ok {{ background:#0b2a1b;color:#86efac;border:1px solid #166534; }}
  .mid {{ background:#1f2937;color:#f8fafc;border:1px solid #475569; }}
  .ribbon {{ background:#7f1d1d; color:#fecaca; border:1px solid #991b1b; padding:10px 12px; border-radius:12px; margin-bottom:10px; font-weight:700; }}
</style>
""", unsafe_allow_html=True)

# ======================= Bedrock fallback helper =======================
try:
    from bedrock_helpers import generate_rationale
except Exception:
    def generate_rationale(features, fraud_prob, anomaly_score, language, model_id):
        msg = {
            "English": (f"Likely risky due to amount/device/geo patterns. "
                        f"Scores: fraud={fraud_prob:.2f}, anomaly={anomaly_score:.2f}."),
            "French":  (f"Risque probable en raison de motifs montant/appareil/géo. "
                        f"Scores : fraude={fraud_prob:.2f}, anomalie={anomaly_score:.2f}."),
            "Spanish": (f"Riesgo probable por patrones de monto/dispositivo/geo. "
                        f"Puntajes: fraude={fraud_prob:.2f}, anomalía={anomaly_score:.2f}."),
        }
        action = "decline" if fraud_prob > 0.85 else "manual_review" if fraud_prob > 0.65 else "approve"
        return msg.get(language, msg["English"]), action

# ============================ Security config ===========================
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "60"))
MAX_BAD_LOGINS = int(os.getenv("MAX_BAD_LOGINS", "3"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "120"))

# ============================ Auth helpers ==============================
def _fallback_users():
    demo_hash = hashlib.sha256("demo123".encode()).hexdigest()
    return [
        {"username": "analyst",  "password_sha256": demo_hash, "roles": ["Analyst"]},
        {"username": "reviewer", "password_sha256": demo_hash, "roles": ["Reviewer"]},
        {"username": "auditor",  "password_sha256": demo_hash, "roles": ["Auditor"]},
        {"username": "lead",     "password_sha256": demo_hash, "roles": ["Analyst", "Reviewer", "Auditor"]},
    ]

def load_users_from_env():
    raw = os.getenv("AUTH_USERS_JSON", "").strip()
    if not raw:
        return _fallback_users()
    try:
        data = json.loads(raw)
        out = []
        for u in data:
            if {"username", "password_sha256", "roles"} <= set(u):
                out.append({
                    "username": str(u["username"]),
                    "password_sha256": str(u["password_sha256"]),
                    "roles": [str(r) for r in u.get("roles", [])]
                })
        return out or _fallback_users()
    except Exception:
        return _fallback_users()

def check_password(user, plain_password):
    return hashlib.sha256(plain_password.encode()).hexdigest() == user["password_sha256"]

def _now_ts():
    return int(time.time())

def _is_locked():
    lock_until = st.session_state.get("__lock_until", 0)
    return _now_ts() < lock_until

def _login_fail():
    n = st.session_state.get("__bad_logins", 0) + 1
    st.session_state["__bad_logins"] = n
    if n >= MAX_BAD_LOGINS:
        st.session_state["__lock_until"] = _now_ts() + LOCKOUT_SECONDS

def _login_success(user):
    st.session_state.clear()
    st.session_state.auth = True
    st.session_state.user = {"username": user["username"], "roles": user.get("roles", ["Analyst"]) }
    st.session_state.current_role = st.session_state.user["roles"][0]
    st.session_state.session_started = _now_ts()
    st.session_state.last_active = _now_ts()
    st.session_state.run_count = 0
    st.session_state.interactions = 0

def login_view():
    st.markdown(
        """
        <style>
        .login-card {max-width: 540px; margin: 8vh auto; padding: 28px 28px 22px;
            background: #0f172a; border: 1px solid #1f2937; border-radius: 16px;
            box-shadow: 0 16px 40px rgba(0,0,0,.25); color:#e5e7eb;}
        .login-title {font-size: 26px; color:#FF9900; font-weight: 800; margin-bottom:6px;}
        .login-sub {color:#9ca3af; margin-bottom: 10px;}
        </style>
        """,
        unsafe_allow_html=True
    )
    st.markdown(
        """
        <div class="login-card">
          <div class="login-title">Fraud Copilot – Sign In</div>
          <div class="login-sub">Use your credentials to continue. Need access? Ask your admin.</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    users = load_users_from_env()
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
        if submitted:
            if _is_locked():
                wait = st.session_state["__lock_until"] - _now_ts()
                st.error(f"Too many failed attempts. Try again in {wait}s.")
                return
            user = next((u for u in users if u["username"].lower() == (username or "").lower()), None)
            if not user or not check_password(user, password or ""):
                _login_fail()
                st.error("Invalid username or password.")
            else:
                _login_success(user)
                st.success("Signed in ✅")
                st.rerun()

def _session_expired():
    last = st.session_state.get("last_active", _now_ts())
    return (_now_ts() - last) > (SESSION_TIMEOUT_MINUTES * 60)

def _touch_session():
    st.session_state["last_active"] = _now_ts()
    st.session_state["run_count"] = st.session_state.get("run_count", 0) + 1

def logout():
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()

def require_login():
    if not st.session_state.get("auth"):
        login_view()
        st.stop()
    if _session_expired():
        st.warning("Session timed out for inactivity. You’ve been signed out.")
        logout()
    _touch_session()

def has_role(*roles):
    user_roles = set(st.session_state.get("user", {}).get("roles", []))
    return any(r in user_roles for r in roles)

def require_roles(*roles):
    if not has_role(*roles):
        st.error("Insufficient permissions for this section.")
        st.stop()

# ========================== Localization ===============================
LANG_OPTIONS = {
    "en": "English", "fr": "Français", "es": "Español", "pt": "Português", "ar": "العربية", "de": "Deutsch",
    "it": "Italiano", "sw": "Kiswahili", "yo": "Yorùbá", "tr": "Türkçe", "ru": "Русский", "zh": "中文",
    "ja": "日本語", "ko": "한국어", "hi": "हिन्दी",
}
UI_TEXT = {
    "en": {
        "app_title": "Fraud Copilot – Analyst Console",
        "app_caption": "Real-time fraud decisions with explainable, auditable AI (AWS Bedrock)",
        "filters": "Filters & Settings", "app_language": "App language",
        "role": "Role", "role_analyst": "Analyst", "role_reviewer": "Reviewer", "role_auditor": "Auditor",
        "risk_min": "Min risk score", "show_all": "Show all (ignore risk filter)",
        "auto_refresh": "Auto-refresh every 10s", "use_aws": "Use AWS DynamoDB (if configured)",
        "bedrock_model": "Bedrock model", "dynamodb_region": "DynamoDB region",
        "btn_test": "Test", "btn_seed": "Seed", "btn_refresh": "Refresh", "btn_peek": "Peek",
        "seeded_ok": "Seeded! ✅", "flagged_cases": "Flagged Cases", "search": "Search cases",
        "sort_by": "Sort by", "ascending": "Ascending", "page_size": "Rows per page", "page": "Page",
        "case_detail": "Case Detail & AI Rationale", "select_case": "Select a case",
        "regenerate_btn": "Regenerate AI Rationale", "bedrock_calling": "Generating explanation with Bedrock…",
        "ai_rationale": "AI Rationale", "recommended_action": "Recommended Action",
        "kpi_summary": "KPI Summary", "total_flagged": "Total Flagged", "avg_risk": "Avg Risk (shown)",
        "max_risk": "Max Risk", "ai_risk_score": "AI Risk Score (composite)", "fp_estimate": "Est. false-positive rate",
        "add_new_case": "Add New Fraud Case", "field_case_id": "Case ID", "field_created_at": "Created At (epoch seconds)",
        "field_user_id": "User ID", "field_transaction_id": "Transaction ID", "field_amount": "Amount ($)",
        "field_currency": "Currency", "field_risk": "Risk Score", "field_action": "Action", "field_notes": "Notes",
        "save_case": "Save Case", "connected": "Connected", "describe_failed": "DescribeTable failed",
        "seed_failed": "Seed failed", "peek_failed": "Peek failed", "must_enable_aws": "Enable 'Use AWS DynamoDB' to save to the database.",
        "not_set": "DYNAMO_TABLE is not set.", "both_required": "Both case_id (PK) and created_at (SK) are required.",
        "case_added": "✅ Case {case_id} added successfully!", "user": "User", "risk": "Risk", "fraud": "fraud", "anomaly": "anomaly",
        "governance": "Governance checks", "bad_high_drift": "⚠️ Drift detected", "ok_low_drift": "✅ No significant drift",
        "bad_mismatch": "⚠️ Shadow mismatch", "ok_match": "✅ Shadow agrees", "good_quality": "✅ Good explanation",
        "weak_quality": "⚠️ Weak explanation", "audit_packet": "Audit packet (regulator-ready)",
        "download_json": "Download JSON", "audit_hash": "Immutable audit hash", "prev_hash": "Previous hash (chain)",
        "what_if": "What-if? Counterfactual", "try_amount": "Try a different amount", "try_country": "Country (ISO / name)",
        "ask_helena": "Ask Helena about this scenario", "timeline": "Case timeline", "add_note": "Add analyst note",
        "save_note": "Save note", "helena_chat": "Helena mini chat", "hint_chat": "Ask a follow-up (e.g., 'Why review vs decline?')",
        "run_agent": "Run Helena Agent", "reviewer_block": "Reviewer Decision",
        "reviewer_help": "Select a new decision for this case and save. Rationale is unchanged.",
        "save_reviewer": "Save reviewer decision", "ro_title": "Read-only mode",
        "ro_caption": "Auditor view: you can browse data, open the Audit packet and download JSON, but you cannot change anything.",
        "assistant_placeholder": "Type a question…",
        "speak_rationale": "🔊 Speak rationale",
        "regen_in_lang": "Regenerate rationale in app language before speaking",
        "dispatch_approve": "Dispatch: APPROVE",
        "dispatch_hold": "Dispatch: HOLD",
        "dispatch_review": "Dispatch: REVIEW",
        "dispatch_decline": "Dispatch: DECLINE",
        "labels_heading": "Analyst Label, Retrain & Dispatch",
        "final_label": "Final ground-truth label",
        "label_conf": "Label confidence",
        "save_label": "Save label",
        "trigger_retrain": "Trigger retrain job",
        "monitoring": "📊 Monitoring (CloudWatch)",
        "requests_decisions": "Requests / Decisions (last 3h)",
        "bedrock_tokens": "Bedrock Token Usage (last 3h)",
        "latency": "Latency ms (p95) (last 3h)",
        "driftz": "Model Drift Z (last 3h)",
    },
    "fr": {
        "app_title": "Fraud Copilot – Console Analyste",
        "app_caption": "Décisions anti-fraude en temps réel avec IA explicable et auditables (AWS Bedrock)",
        "filters": "Filtres & paramètres", "app_language": "Langue de l’application",
        "role": "Rôle", "role_analyst": "Analyste", "role_reviewer": "Relecteur", "role_auditor": "Auditeur",
        "risk_min": "Score de risque minimal", "show_all": "Tout afficher (ignorer le filtre)",
        "auto_refresh": "Rafraîchir toutes les 10 s", "use_aws": "Utiliser AWS DynamoDB (si configuré)",
        "bedrock_model": "Modèle Bedrock", "dynamodb_region": "Région DynamoDB",
        "btn_test": "Tester", "btn_seed": "Initialiser", "btn_refresh": "Rafraîchir", "btn_peek": "Aperçu",
        "seeded_ok": "Initialisé ! ✅", "flagged_cases": "Cas signalés", "search": "Rechercher des cas",
        "sort_by": "Trier par", "ascending": "Croissant", "page_size": "Lignes par page", "page": "Page",
        "case_detail": "Détail du cas & raisonnement IA", "select_case": "Sélectionner un cas",
        "regenerate_btn": "Régénérer le raisonnement IA", "bedrock_calling": "Génération de l’explication via Bedrock…",
        "ai_rationale": "Raisonnement IA", "recommended_action": "Action recommandée",
        "kpi_summary": "Synthèse KPI", "total_flagged": "Total signalés", "avg_risk": "Risque moyen (affiché)",
        "max_risk": "Risque max", "ai_risk_score": "Score de risque IA (composite)", "fp_estimate": "Tx. faux positifs estimé",
        "add_new_case": "Ajouter un nouveau cas de fraude", "field_case_id": "ID du cas", "field_created_at": "Créé le (secondes epoch)",
        "field_user_id": "ID utilisateur", "field_transaction_id": "ID transaction", "field_amount": "Montant ($)",
        "field_currency": "Devise", "field_risk": "Score de risque", "field_action": "Action", "field_notes": "Notes",
        "save_case": "Enregistrer le cas", "connected": "Connecté", "describe_failed": "DescribeTable a échoué",
        "seed_failed": "Initialisation échouée", "peek_failed": "Aperçu indisponible",
        "must_enable_aws": "Activez « Utiliser AWS DynamoDB » pour enregistrer dans la base.",
        "not_set": "DYNAMO_TABLE n’est pas défini.", "both_required": "case_id (PK) et created_at (SK) sont requis.",
        "case_added": "✅ Cas {case_id} ajouté avec succès !", "user": "Utilisateur", "risk": "Risque", "fraud": "fraude", "anomaly": "anomalie",
        "governance": "Contrôles de gouvernance", "bad_high_drift": "⚠️ Dérive détectée", "ok_low_drift": "✅ Pas de dérive significative",
        "bad_mismatch": "⚠️ Désaccord du modèle fantôme", "ok_match": "✅ Accord du modèle fantôme",
        "good_quality": "✅ Explication de bonne qualité", "weak_quality": "⚠️ Explication faible",
        "audit_packet": "Dossier d’audit (prêt régulateur)",
        "download_json": "Télécharger le JSON", "audit_hash": "Empreinte d’audit immuable", "prev_hash": "Empreinte précédente (chaîne)",
        "what_if": "Et si ? Contrefactuel", "try_amount": "Essayer un autre montant", "try_country": "Pays (ISO / nom)",
        "ask_helena": "Demander ce scénario à Helena", "timeline": "Chronologie du cas", "add_note": "Ajouter une note d’analyste",
        "save_note": "Enregistrer la note", "helena_chat": "Mini-chat Helena", "hint_chat": "Posez une question (ex. « Pourquoi revue et pas refus ? »)",
        "run_agent": "Lancer l’agent Helena", "reviewer_block": "Décision du relecteur",
        "reviewer_help": "Choisissez une nouvelle décision pour ce cas et enregistrez. Le raisonnement reste inchangé.",
        "save_reviewer": "Enregistrer la décision du relecteur", "ro_title": "Mode lecture seule",
        "ro_caption": "Vue auditeur : vous pouvez parcourir, ouvrir le dossier d’audit et télécharger le JSON, sans modification.",
        "assistant_placeholder": "Saisissez une question…",
        "speak_rationale": "🔊 Lire le raisonnement",
        "regen_in_lang": "Régénérer le raisonnement dans la langue de l’app avant lecture",
        "dispatch_approve": "Dispatcher : APPROUVER",
        "dispatch_hold": "Dispatcher : METTRE EN ATTENTE",
        "dispatch_review": "Dispatcher : REVOIR",
        "dispatch_decline": "Dispatcher : REFUSER",
        "labels_heading": "Étiquetage analyste, ré-apprentissage & dispatch",
        "final_label": "Libellé vérité terrain",
        "label_conf": "Confiance du libellé",
        "save_label": "Enregistrer le libellé",
        "trigger_retrain": "Déclencher l’entraînement",
        "monitoring": "📊 Supervision (CloudWatch)",
        "requests_decisions": "Requêtes / Décisions (3 h)",
        "bedrock_tokens": "Jetons Bedrock (3 h)",
        "latency": "Latence ms (p95) (3 h)",
        "driftz": "Dérive du modèle Z (3 h)",
    },
}
COL_LABELS = {
    "en": {"case_id": "Case ID","user_id": "User ID","risk": "risk","fraud_prob": "fraud_prob","anomaly_score": "anomaly_score","action": "action"},
    "fr": {"case_id": "ID cas","user_id": "ID utilisateur","risk": "risque","fraud_prob": "proba_fraude","anomaly_score": "score_anomalie","action": "action"},
}

def t(key: str, lang: str) -> str:
    return UI_TEXT.get(lang, UI_TEXT["en"]).get(key, UI_TEXT["en"].get(key, key))

def col_label(col: str, lang: str) -> str:
    return COL_LABELS.get(lang, COL_LABELS["en"]).get(col, col)

def bedrock_lang_name(lang_code: str) -> str:
    # Return a friendly language name for prompts
    return {
        "en": "English", "fr": "French", "es": "Spanish", "pt": "Portuguese", "ar": "Arabic",
        "de": "German", "it": "Italian", "tr": "Turkish", "ru": "Russian", "zh": "Chinese",
        "ja": "Japanese", "ko": "Korean", "hi": "Hindi", "sw": "Swahili", "yo": "Yoruba",
    }.get(lang_code, "English")

# ============================ Require login ============================
require_login()

# ===================== Session / signals (NEW) =========================
def _client_fingerprint() -> str:
    try:
        ctx = getattr(getattr(st, "runtime", None), "scriptrunner", None)
        ua = getattr(getattr(ctx, "get_script_run_ctx", lambda: None)(), "headers", {}).get("User-Agent", "ua")
    except Exception:
        ua = "ua"
    raw = f"{st.session_state.user['username']}|{st.session_state.get('session_started', 0)}|{ua}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def collect_session_signals() -> dict:
    duration_s = _now_ts() - st.session_state.get("session_started", _now_ts())
    inter = st.session_state.get("interactions", 0)
    fp = _client_fingerprint()
    return {"session_seconds": duration_s, "interaction_count": inter, "client_fp": fp}

def bump_interactions(n: int = 1):
    st.session_state["interactions"] = st.session_state.get("interactions", 0) + n

# ======================================================================
#               🆕 TOP NAV + LIGHT SIDEBAR RESTRUCTURE
# ======================================================================
user_obj = st.session_state.user
allowed_roles = user_obj.get("roles", ["Analyst"])
current_role = st.session_state.get("current_role", allowed_roles[0])

st.markdown("""
<style>
.topbar { display:flex; align-items:center; justify-content:space-between;
    background: rgba(11,13,23,.25); border:1px solid rgba(31,41,55,.4);
    border-radius:16px; padding:10px 14px; margin-bottom:14px; backdrop-filter: blur(10px); }
.top-left { display:flex; flex-direction:column; gap:2px; }
.top-title { font-weight:700; font-size:17px; color:#fff; }
.top-sub { font-size:12px; color:#94a3b8; }
.top-chips { display:flex; gap:6px; margin-top:4px; flex-wrap:wrap; }
.tchip { background:rgba(15,23,42,.4); border:1px solid rgba(148,163,184,.2);
    border-radius:999px; padding:4px 10px; font-size:12px; color:#e2e8f0; }
</style>
""", unsafe_allow_html=True)

if "show_top_menu" not in st.session_state:
    st.session_state.show_top_menu = False

nav1, nav2 = st.columns([5, 1])
with nav1:
    st.markdown(f"""
    <div class="topbar">
       <div class="top-left">
          <div class="top-title">{t("app_title", "en")}</div>
          <div class="top-sub">Real-time fraud decisions • Explainable • AWS-ready</div>
          <div class="top-chips">
             <span class="tchip">AWS Bedrock</span>
             <span class="tchip">DynamoDB</span>
             <span class="tchip">User: {user_obj.get("username","?")}</span>
             <span class="tchip">Role: {current_role}</span>
          </div>
       </div>
    </div>
    """, unsafe_allow_html=True)

with nav2:
    if st.button("⋮", key="top_menu_btn"):
        st.session_state.show_top_menu = not st.session_state.show_top_menu

    if st.session_state.show_top_menu:
        with st.popover("Session / Actions", use_container_width=True):
            st.markdown(f"**👤 {user_obj.get('username','?')}**")
            if len(allowed_roles) > 1:
                new_role = st.selectbox("Switch role", allowed_roles,
                                        index=allowed_roles.index(current_role))
                if new_role != current_role:
                    st.session_state.current_role = new_role
                    st.rerun()
            st.markdown("---")
            with st.expander("📮 Contact support", expanded=False):
                with st.form("contact_form_top"):
                    nm = st.text_input("Name", value=user_obj.get("username", ""))
                    em = st.text_input("Email", value=os.getenv("SUPPORT_EMAIL_DEFAULT", ""))
                    cat = st.selectbox("Category", ["Bug", "Feature request", "Access issue", "Other"])
                    msg = st.text_area("Message")
                    sent = st.form_submit_button("Send")
                    if sent:
                        payload = {
                            "name": nm.strip(),
                            "email": em.strip(),
                            "category": cat,
                            "message": msg.strip(),
                            "ts": int(time.time()),
                            "diagnostics": {
                                "session_started": st.session_state.get("session_started", 0),
                                "role": st.session_state.get("current_role", "?")
                            }
                        }
                        try:
                            with open("contact_inbox.jsonl", "a", encoding="utf-8") as f:
                                f.write(json.dumps(payload) + "\n")
                            st.success("Message recorded ✅")
                        except Exception as e:
                            st.error(f"Could not record message: {e}")

            st.markdown("---")
            if st.button("🚪 Log out"):
                logout()

# =============================== SIDEBAR ===============================
UI_LANG_CODE = st.sidebar.selectbox(
    t("app_language", "en"),
    options=list(LANG_OPTIONS.keys()),
    format_func=lambda k: LANG_OPTIONS[k],
    index=list(LANG_OPTIONS.keys()).index("en"),
)

st.sidebar.header(t("filters", UI_LANG_CODE))
risk_min = st.sidebar.slider(t("risk_min", UI_LANG_CODE), 0.0, 1.0, 0.75, 0.01)
show_all = st.sidebar.checkbox(t("show_all", UI_LANG_CODE), value=False)
auto_refresh = st.sidebar.checkbox(t("auto_refresh", UI_LANG_CODE), value=False)
use_aws = st.sidebar.checkbox(t("use_aws", UI_LANG_CODE), value=True)

MODEL_CHOICES = [
    ("Anthropic Claude 3.5 Sonnet", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
    ("Anthropic Claude 3 Haiku", "anthropic.claude-3-haiku-20240307-v1:0"),
    ("Amazon Titan Text Premier", "amazon.titan-text-premier-v1:0"),
    ("Mistral Large", "mistral.mistral-large-2407-v1:0"),
    ("Cohere Command-R+", "cohere.command-r-plus-v1:0"),
    ("Custom…", "__custom__")
]
choice = st.sidebar.selectbox(t("bedrock_model", UI_LANG_CODE), [lbl for lbl, _ in MODEL_CHOICES], index=0)
if dict(MODEL_CHOICES)[choice] == "__custom__":
    bedrock_model = st.sidebar.text_input(
        "Custom Bedrock model ID",
        value=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
    )
else:
    bedrock_model = dict(MODEL_CHOICES)[choice]

DDB_REGION = os.getenv("AWS_REGION_DDB") or os.getenv("AWS_REGION") or "us-east-2"
TABLE_NAME = os.getenv("DYNAMO_TABLE")
if DDB_REGION:
    st.sidebar.caption(f"{t('dynamodb_region', UI_LANG_CODE)}: **{DDB_REGION}**")
if not TABLE_NAME:
    st.sidebar.error(t("not_set", UI_LANG_CODE))

# Quick Polly test — use UI language
if st.sidebar.button("🔊 Test Polly"):
    sample = {
        "en": "Hello from Amazon Polly. Your audio is working.",
        "fr": "Bonjour d’Amazon Polly. L’audio fonctionne.",
        "es": "Hola desde Amazon Polly. El audio funciona.",
    }.get(UI_LANG_CODE, "Hello from Amazon Polly. Your audio is working.")
    audio = polly_speak(sample, voice=pick_polly_voice(UI_LANG_CODE))
    if audio:
        st.sidebar.audio(audio, format="audio/mp3")
    else:
        st.sidebar.error("Polly test failed. Check credentials, region, or permissions.")

# =========================== AWS helpers ===============================
def _get_ddb():
    if boto3 is None:
        raise RuntimeError("boto3 not available")
    region = os.getenv("AWS_REGION_DDB") or os.getenv("AWS_REGION") or "us-east-2"
    ak = os.getenv("AWS_ACCESS_KEY_ID")
    sk = os.getenv("AWS_SECRET_ACCESS_KEY")
    tk = os.getenv("AWS_SESSION_TOKEN")
    kwargs = dict(region_name=region)
    if ak and sk:
        kwargs.update(aws_access_key_id=ak, aws_secret_access_key=sk)
        if tk:
            kwargs.update(aws_session_token=tk)
    return boto3.resource("dynamodb", **kwargs)

def _get_cw():
    if boto3 is None:
        raise RuntimeError("boto3 not available")
    region = os.getenv("AWS_REGION_CW") or os.getenv("AWS_REGION") or "us-east-2"
    ak = os.getenv("AWS_ACCESS_KEY_ID")
    sk = os.getenv("AWS_SECRET_ACCESS_KEY")
    tk = os.getenv("AWS_SESSION_TOKEN")
    kwargs = dict(region_name=region)
    if ak and sk:
        kwargs.update(aws_access_key_id=ak, aws_secret_access_key=sk)
        if tk:
            kwargs.update(aws_session_token=tk)
    return boto3.client("cloudwatch", **kwargs)
def emit_metrics_to_cloudwatch(latency_ms: float, tokens_used: int, model_drift_z: float):
    """
    Pushes one sample for each metric used by the Monitoring (CloudWatch) panel:
      - FraudScoreLatencyMs (Average)
      - BedrockTokens (Sum)
      - Requests / Decisions (Sum) are handled elsewhere
      - ModelDriftZ (Average)
    """
    try:
        cw = _get_cw()
        ns = os.getenv("CLOUDWATCH_NAMESPACE", "FraudCopilot")

        metric_data = [
            # p95 latency is computed server-side; we send individual samples, CloudWatch aggregates
            {
                "MetricName": "FraudScoreLatencyMs",
                "Dimensions": [{"Name": "Service", "Value": "console"}],
                "Value": float(latency_ms),
                "Unit": "Milliseconds",
                "StorageResolution": 60,  # 1-minute high-res
            },
            {
                "MetricName": "BedrockTokens",
                "Dimensions": [{"Name": "Model", "Value": "all"}],
                "Value": float(tokens_used),
                "Unit": "Count",
                "StorageResolution": 60,
            },
            {
                "MetricName": "ModelDriftZ",
                "Dimensions": [{"Name": "Country", "Value": "all"}],
                "Value": float(model_drift_z),
                "Unit": "None",
                "StorageResolution": 60,
            },
            # Note: Requests/Decisions are emitted from the decision/agent paths (see step 4)
        ]
        cw.put_metric_data(Namespace=ns, MetricData=metric_data)
    except Exception as e:
        # non-fatal: just surface a soft warning inside Streamlit
        try:
            st.warning(f"CloudWatch emit error: {e}")
        except Exception:
            pass

def cw_metric_df(namespace: str, metric: str, dim_name: str, dim_value: str = "all",
                 stat: str = "Sum", period: int = 300, minutes: int = 180):
    try:
        cw = _get_cw()
        end = datetime.utcnow()
        start = end - timedelta(minutes=minutes)
        dims = [] if dim_name is None else [{"Name": dim_name, "Value": dim_value}]
        resp = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=period, Statistics=[stat]
        )
        pts = sorted(resp.get("Datapoints", []), key=lambda d: d["Timestamp"])
        if not pts:
            return pd.DataFrame(columns=["ts", "value"])
        return pd.DataFrame({
            "ts": [p["Timestamp"] for p in pts],
            "value": [float(p.get(stat, 0.0)) for p in pts]
        })
    except Exception as e:
        st.warning(f"CloudWatch error for {metric}: {e}")
        return pd.DataFrame(columns=["ts", "value"])

@st.cache_data(ttl=10, show_spinner=False)
def scan_table_all_items(table_name: str):
    try:
        ddb = _get_ddb()
        table = ddb.Table(table_name)
        items, kwargs = [], {}
        while True:
            resp = table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        def norm(v):
            if isinstance(v, Decimal):
                return float(v) if (v % 1) else int(v)
            return v
        return [{k: norm(v) for k, v in it.items()} for it in items]
    except (NoCredentialsError, BotoCoreError, ClientError) as e:
        st.error(f"DynamoDB error: {e}")
        return []
    except Exception as e:
        st.error(f"Unexpected DynamoDB error: {e}")
        return []

def _describe_table(table_name: str):
    ddb = _get_ddb()
    return ddb.meta.client.describe_table(TableName=table_name)

LABELS_TABLE = os.getenv("LABELS_TABLE", "").strip()
RETRAIN_LAMBDA = os.getenv("RETRAIN_LAMBDA", "").strip()
RETRAIN_QUEUE_URL = os.getenv("RETRAIN_QUEUE_URL", "").strip()

DECISION_QUEUE_URL = os.getenv("DECISION_QUEUE_URL", "").strip()
DECISION_SNS_ARN = os.getenv("DECISION_SNS_ARN", "").strip()
DECISION_WEBHOOK_URL = os.getenv("DECISION_WEBHOOK_URL", "").strip()

def _emit_decision_event(case_id: str, created_at: str, action: str, payload: dict):
    event = {
        "type": "fraudcopilot.decision.v1",
        "ts": int(time.time()),
        "case_id": case_id,
        "created_at": created_at,
        "action": action,
        "payload": payload,
    }
    try:
        if boto3 and DECISION_QUEUE_URL:
            sqs = boto3.client("sqs", region_name=DDB_REGION)
            sqs.send_message(QueueUrl=DECISION_QUEUE_URL, MessageBody=json.dumps(event))
        if boto3 and DECISION_SNS_ARN:
            sns = boto3.client("sns", region_name=DDB_REGION)
            sns.publish(TopicArn=DECISION_SNS_ARN, Message=json.dumps(event))
        if DECISION_WEBHOOK_URL:
            import urllib.request
            req = urllib.request.Request(
                DECISION_WEBHOOK_URL,
                data=json.dumps(event).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
        return True, None
    except Exception as e:
        return False, str(e)

# ========================= Seed/Peek/Test UI ===========================
colA, colB, colC, colD = st.sidebar.columns(4, gap="small")
if colA.button("🔍 " + t("btn_test", UI_LANG_CODE)):
    if not TABLE_NAME:
        st.sidebar.error(t("not_set", UI_LANG_CODE))
    else:
        try:
            info = _describe_table(TABLE_NAME)
            st.sidebar.success(t("connected", UI_LANG_CODE) + " ✅")
            st.sidebar.json({
                "TableName": info["Table"]["TableName"],
                "TableStatus": info["Table"]["TableStatus"],
                "ItemCount": info["Table"].get("ItemCount", 0),
                "RegionUsed": DDB_REGION
            })
        except Exception as e:
            st.sidebar.error(f"{t('describe_failed', UI_LANG_CODE)}: {e}")

if colB.button("🌱 " + t("btn_seed", UI_LANG_CODE)):
    if not use_aws:
        st.sidebar.error(t("must_enable_aws", UI_LANG_CODE))
    elif not TABLE_NAME:
        st.sidebar.error(t("not_set", UI_LANG_CODE))
    else:
        try:
            ddb = _get_ddb()
            tdb = ddb.Table(TABLE_NAME)
            now = int(time.time())
            sample = [
                {"case_id": f"T{now}-001", "created_at": str(now), "user_id": "U100", "transaction_id": "txn_001",
                 "amount": Decimal("245.70"), "currency": "USD", "risk": Decimal("0.91"),
                 "fraud_prob": Decimal("0.88"), "anomaly_score": Decimal("0.73"),
                 "action": "manual_review", "rationale": "",
                 "features": json.dumps({"amount": 245.7, "country": "US", "device": "web"}), "ts": now},
                {"case_id": f"T{now}-002", "created_at": str(now + 1), "user_id": "U200", "transaction_id": "txn_002",
                 "amount": Decimal("45.70"), "currency": "USD", "risk": Decimal("0.25"),
                 "fraud_prob": Decimal("0.18"), "anomaly_score": Decimal("0.20"),
                 "action": "approve", "rationale": "",
                 "features": json.dumps({"amount": 45.7, "country": "FR", "device": "ios"}), "ts": now + 1},
            ]
            with tdb.batch_writer() as bw:
                for it in sample:
                    bw.put_item(Item=it)
            st.sidebar.success(t("seeded_ok", UI_LANG_CODE))
            st.cache_data.clear()
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"{t('seed_failed', UI_LANG_CODE)}: {e}")

if colC.button("🔄 " + t("btn_refresh", UI_LANG_CODE)):
    bump_interactions()
    st.cache_data.clear()
    st.rerun()

if colD.button("👀 " + t("btn_peek", UI_LANG_CODE)):
    try:
        rows = scan_table_all_items(TABLE_NAME or "")
        st.sidebar.json(rows[:5] if rows else [])
    except Exception as e:
        st.sidebar.error(f"{t('peek_failed', UI_LANG_CODE)}: {e}")

# ============================ Data sources =============================
def load_cases_local():
    """
    Return a DataFrame in the unified "cases" schema:
    ['case_id','created_at','user_id','risk','fraud_prob','anomaly_score','action','rationale','features','ts']
    If a dataset CSV is selected, derive rows from it. Otherwise fall back to sample_cases.csv.
    """
    sel = st.session_state.get("active_dataset_path")
    if sel and os.path.exists(sel):
        try:
            src = pd.read_csv(sel)

            now = int(time.time())

            def _get_col(*names, default=None):
                for n in names:
                    if n in src.columns:
                        return src[n]
                return default

            # best-effort identifiers
            uid_series = _get_col("user_id", "email_address", "email",
                                  default=pd.Series([f"U{1000+i}" for i in range(len(src))]))
            case_ids = pd.Series([f"T{now+i:010d}-{(i%999)+1:03d}" for i in range(len(src))])

            # basic risk heuristic using amount if available, otherwise a small random-like spread
            if "amount" in src.columns:
                amt = src["amount"].astype("float64").fillna(0.0)
                scale = float(amt.quantile(0.95) or 1.0)
                risk = (amt / (scale + 1e-9)).clip(0, 1)
            else:
                # no amount column — create a mild gradient
                risk = pd.Series([(i % 10)/10 for i in range(len(src))], dtype="float64")

            fraud_prob = (risk * 0.95).clip(0, 1)
            anom = (risk * 0.80).clip(0, 1)

            # Features column: keep a few useful raw columns if present
            keep_cols = [c for c in ["amount","country","billing_state","ip_address","user_agent","email_address"] if c in src.columns]
            feat = src[keep_cols].fillna("").to_dict(orient="records") if keep_cols else [{} for _ in range(len(src))]

            df_cases = pd.DataFrame({
                "case_id": case_ids.astype(str),
                "created_at": str(now),
                "user_id": uid_series.astype(str),
                "risk": risk.astype(float),
                "fraud_prob": fraud_prob.astype(float),
                "anomaly_score": anom.astype(float),
                "action": "manual_review",
                "rationale": "",
                "features": [json.dumps(f) for f in feat],
                "ts": now
            })
            return df_cases
        except Exception as e:
            st.warning(f"Could not parse selected dataset; falling back to sample_cases.csv. Error: {e}")

    # Fallback demo file
    path = "sample_cases.csv"
    if not os.path.exists(path):
        now = int(time.time())
        df0 = pd.DataFrame([
            {"case_id": "T00001-1730", "created_at": str(now), "user_id": "U0007",
             "risk": 0.91, "fraud_prob": 0.88, "anomaly_score": 0.73, "action": "manual_review", "rationale": "",
             "features": json.dumps({"amount": 245.7, "country": "NG", "device": "web"}), "ts": now},
            {"case_id": "T00002-1731", "created_at": str(now + 1), "user_id": "U0021",
             "risk": 0.83, "fraud_prob": 0.72, "anomaly_score": 0.80, "action": "manual_review", "rationale": "",
             "features": json.dumps({"amount": 189.2, "country": "DE", "device": "ios"}), "ts": now + 1},
        ])
        df0.to_csv(path, index=False)
    return pd.read_csv(path)

def save_case_local_update(case_id: str, created_at: str, upd: dict):
    path = "sample_cases.csv"
    df_local = load_cases_local()
    m = (df_local["case_id"] == case_id) & (df_local["created_at"].astype(str) == str(created_at))
    for k, v in upd.items():
        df_local.loc[m, k] = v
    df_local.to_csv(path, index=False)

def load_cases_dynamodb():
    if not TABLE_NAME:
        st.warning(t("not_set", UI_LANG_CODE))
        return load_cases_local()
    rows = scan_table_all_items(TABLE_NAME)
    if not rows:
        return pd.DataFrame(columns=["case_id", "created_at", "user_id", "risk",
                                     "fraud_prob", "anomaly_score", "action", "rationale", "features", "ts"])
    return pd.DataFrame(rows)

# IMPORTANT: this df is your CASES table (not the CSV preview).
df = load_cases_dynamodb() if use_aws else load_cases_local()
for colname, default in [("risk", 0.0), ("fraud_prob", 0.0), ("anomaly_score", 0.0),
                         ("action", "manual_review"), ("rationale", ""), ("features", "{}"),
                         ("ts", 0), ("created_at", "")]:
    if colname not in df.columns:
        df[colname] = default
if not show_all:
    df = df[df["risk"] >= risk_min].copy()
df.sort_values("risk", ascending=False, inplace=True)

# ======================= Session & helpers =============================
if "timeline" not in st.session_state:
    st.session_state.timeline = {}
if "chat" not in st.session_state:
    st.session_state.chat = []
if "analyst_id" not in st.session_state:
    st.session_state.analyst_id = st.session_state.user["username"]
if "audit_chain" not in st.session_state:
    st.session_state.audit_chain = {}
if "country_stats" not in st.session_state:
    st.session_state.country_stats = {}

def explanation_quality_score(text: str) -> float:
    if not text:
        return 0.25
    base = min(len(text) / 220.0, 1.0)
    keywords = ["because", "due to", "pattern", "amount", "location", "device", "reason", "threshold"]
    bump = sum(1 for k in keywords if k in (text or "").lower()) / len(keywords)
    return max(0.1, min(1.0, 0.55 * base + 0.45 * bump))

def ai_risk_composite(risk: float, fraud: float, anom: float, q: float) -> float:
    return max(0.0, min(1.0, 0.50 * risk + 0.25 * fraud + 0.15 * anom + 0.10 * q))

def fp_estimate_from_threshold(scores: pd.Series, threshold: float = 0.80) -> float:
    if scores is None or getattr(scores, "empty", True):
        return 0.0
    return float((scores >= threshold).mean())

def drift_signal(amount: float, country: str):
    if not country:
        country = "UNK"
    stats = st.session_state.country_stats.setdefault(country, {"count": 0, "mean": 0.0, "m2": 0.0})
    count, mean, m2 = stats["count"], stats["mean"], stats["m2"]
    if count >= 2:
        var = m2 / (count - 1)
        sd = (var ** 0.5) if var > 1e-9 else 0.0
        z = ((amount - mean) / sd) if sd > 1e-9 else 0.0
    else:
        z = 0.0
    return z, stats

def commit_baseline(amount: float, country: str):
    stats = st.session_state.country_stats.setdefault(country, {"count": 0, "mean": 0.0, "m2": 0.0})
    count, mean, m2 = stats["count"], stats["mean"], stats["m2"]
    count += 1
    delta = amount - mean
    mean += delta / count
    delta2 = amount - mean
    m2 += delta * delta2
    stats.update({"count": count, "mean": mean, "m2": m2})

def shadow_agrees(primary_action: str, features: dict, fraud_prob: float, anomaly_score: float, lang: str):
    SHADOW_MODEL_ID = os.getenv("SHADOW_MODEL_ID", "").strip()
    if not SHADOW_MODEL_ID:
        return None, True
    try:
        _, action2 = generate_rationale(features, fraud_prob, anomaly_score, lang, SHADOW_MODEL_ID)
        return action2, (str(action2) == str(primary_action))
    except Exception:
        return None, True

def make_audit_hash(payload: dict, prev_hash: str = "") -> str:
    s = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "|" + prev_hash
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def risk_level(r: float) -> str:
    if r >= 0.85:
        return "🔴 High"
    if r >= 0.60:
        return "🟠 Med"
    return "🟢 Low"

def enrich_features(features: dict) -> dict:
    f = dict(features or {})
    email = f.get("email")
    phone = f.get("phone")
    ip = f.get("ip")
    if email:
        f["email_domain_age_days"] = 365
        f["email_disposable"] = False
    if phone:
        f["phone_country_guess"] = "US"
        f["phone_line_type"] = "mobile"
    if ip:
        f["ip_asn_risk"] = 0.12
        f["ip_is_hosting"] = False
    f.update({f"session_{k}": v for k, v in collect_session_signals().items()})
    return f

# ===================== Table browser (SAFE PAGING) ======================
def table_browser(df_all: pd.DataFrame, lang: str):
    st.subheader(t("flagged_cases", lang))
    q = st.text_input(t("search", lang), "")
    sort_col = st.selectbox(t("sort_by", lang),
                            [c for c in ["risk", "fraud_prob", "anomaly_score", "case_id", "user_id", "action"] if c in df_all.columns],
                            index=0)
    asc = st.checkbox(t("ascending", lang), value=False)
    page_size = st.selectbox(t("page_size", lang), [10, 20, 50, 100], index=0)
    dff = df_all.copy()
    if q.strip():
        ql = q.strip().lower()
        mask = dff.astype(str).apply(lambda s: s.str.lower().str.contains(ql, na=False)).any(axis=1)
        dff = dff[mask]
    if sort_col in dff.columns:
        dff = dff.sort_values(sort_col, ascending=asc)
    if "risk" in dff.columns:
        dff["RiskLevel"] = dff["risk"].apply(risk_level)
    total_rows = int(len(dff))
    page_size = max(1, int(page_size))
    pages = max(1, math.ceil(total_rows / page_size))
    page = 1 if pages == 1 else st.slider(t("page", lang), min_value=1, max_value=pages, value=1)
    start = (page - 1) * page_size
    end = start + page_size
    shown_cols = [c for c in ["case_id", "user_id", "RiskLevel", "risk", "fraud_prob", "anomaly_score", "action"] if c in dff.columns]
    # Localize column headers if desired (display only)
    display = dff.iloc[start:end][shown_cols].rename(columns=lambda c: col_label(c, lang))
    st.dataframe(display, use_container_width=True, height=360)
    bump_interactions()
    return dff

# ============================== Layout =================================
ROLE = st.session_state.get("current_role", "Analyst")
is_analyst = ROLE == "Analyst"
is_reviewer = ROLE == "Reviewer"
is_auditor = ROLE == "Auditor"
SHADOW_MODEL_ID = os.getenv("SHADOW_MODEL_ID", "").strip()

if is_auditor:
    st.markdown(f"<div class='ribbon'>🔒 {t('ro_title', UI_LANG_CODE)}</div>", unsafe_allow_html=True)

st.markdown(f"""
<div class="banner">
  <div class="title">{t("app_title", UI_LANG_CODE)}</div>
  <p class="subtitle">{t("app_caption", UI_LANG_CODE)}</p>
  <div style="margin-top:10px;">
    <span class="chip chip1">AWS Bedrock</span>
    <span class="chip chip2">DynamoDB</span>
    <span class="chip chip3">Explainable & Auditable</span>
  </div>
</div>
""", unsafe_allow_html=True)

k1, k2, k3, k4, k5 = st.columns([1, 1, 1, 1, 1])
with k1:
    st.markdown(f"""<div class="kcard"><p class="klabel">{t('total_flagged', UI_LANG_CODE)}</p>
<p class="kvalue">{len(df)}</p></div>""", unsafe_allow_html=True)
with k2:
    st.markdown(f"""<div class="kcard"><p class="klabel">{t('avg_risk', UI_LANG_CODE)}</p>
<p class="kvalue">{(df['risk'].mean() if len(df) else 0):.2f}</p></div>""", unsafe_allow_html=True)
with k3:
    st.markdown(f"""<div class="kcard"><p class="klabel">{t('max_risk', UI_LANG_CODE)}</p>
<p class="kvalue">{(df['risk'].max() if len(df) else 0):.2f}</p></div>""", unsafe_allow_html=True)
with k4:
    st.markdown(f"""<div class="kcard"><p class="klabel">{t('ai_risk_score', UI_LANG_CODE)}</p>
<p class="kvalue">—</p></div>""", unsafe_allow_html=True)
with k5:
    fp = fp_estimate_from_threshold(df["risk"] if "risk" in df else pd.Series([], dtype=float), 0.80)
    st.markdown(f"""<div class="kcard"><p class="klabel">{t('fp_estimate', UI_LANG_CODE)}</p>
<p class="kvalue">{fp:.2f}</p></div>""", unsafe_allow_html=True)

st.write("")
col1, col2 = st.columns([2, 1], gap="large")

with col1:
    df_filtered = table_browser(df, UI_LANG_CODE)
    st.markdown(f"### {t('case_detail', UI_LANG_CODE)}")
    sel = st.selectbox(t("select_case", UI_LANG_CODE), df_filtered["case_id"].tolist() if len(df_filtered) else [], index=0 if len(df_filtered) else None)

    if sel:
        row = df_filtered[df_filtered["case_id"] == sel].iloc[0]
        row_index = df.index[df["case_id"] == sel]
        row_index = row_index[0] if len(row_index) else None

        base_features = row["features"]
        try:
            features_dict = json.loads(base_features) if isinstance(base_features, str) else base_features
        except Exception:
            features_dict = {"raw": str(base_features)}
        features_dict = enrich_features(features_dict)
        amount = float(features_dict.get("amount", 0.0))
        country = str(features_dict.get("country", "UNK"))

        if is_analyst:
            if st.button(t("regenerate_btn", UI_LANG_CODE), disabled=is_auditor):
                with st.spinner(t("bedrock_calling", UI_LANG_CODE)):
                    rationale, action = generate_rationale(
                        features_dict,
                        float(row.get("fraud_prob", 0.0)),
                        float(row.get("anomaly_score", 0.0)),
                        bedrock_lang_name(UI_LANG_CODE),
                        bedrock_model
                    )
                try:
                    if use_aws and TABLE_NAME:
                        ddb = _get_ddb()
                        tdb = ddb.Table(TABLE_NAME)
                        tdb.update_item(
                            Key={"case_id": row["case_id"], "created_at": str(row.get("created_at", ""))},
                            UpdateExpression="SET rationale=:r, #act=:a, features=:f",
                            ExpressionAttributeNames={"#act": "action"},
                            ExpressionAttributeValues={":r": rationale, ":a": action, ":f": json.dumps(features_dict)}
                        )
                    else:
                        save_case_local_update(
                            row["case_id"], str(row.get("created_at", "")),
                            {"rationale": rationale, "action": action, "features": json.dumps(features_dict)}
                        )
                    if row_index is not None:
                        df.loc[row_index, ["rationale", "action", "features"]] = [rationale, action, json.dumps(features_dict)]
                    st.toast("Helena updated the rationale and saved it ✅")
                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to save rationale: {e}")

        rationale_text = (row.get("rationale", "") or "").strip()
        qscore = explanation_quality_score(rationale_text)
        composite = ai_risk_composite(
            float(row.get("risk", 0.0)),
            float(row.get("fraud_prob", 0.0)),
            float(row.get("anomaly_score", 0.0)),
            qscore
        )

        shadow_action, agree = shadow_agrees(
            row.get("action", "manual_review"),
            features_dict,
            float(row.get("fraud_prob", 0.0)),
            float(row.get("anomaly_score", 0.0)),
            bedrock_lang_name(UI_LANG_CODE)
        )
        z, _stats = drift_signal(amount, country)
        drift_bad = abs(z) >= 2.0

        st.write(
            f"**{t('user', UI_LANG_CODE)}:** {row.get('user_id', '?')} · **{t('risk', UI_LANG_CODE)}:** {row.get('risk', 0.0):.2f} "
            f"({t('fraud', UI_LANG_CODE)}={row.get('fraud_prob', 0.0):.2f}, {t('anomaly', UI_LANG_CODE)}={row.get('anomaly_score', 0.0):.2f})"
        )
        st.json(features_dict)

        drift_badge = (
            f"<span class='badge bad'>{t('bad_high_drift', UI_LANG_CODE)}</span>"
            if drift_bad else f"<span class='badge ok'>{t('ok_low_drift', UI_LANG_CODE)}</span>"
        )
        shadow_badge = (
            f"<span class='badge bad'>{t('bad_mismatch', UI_LANG_CODE)}</span>"
            if (agree is False) else f"<span class='badge ok'>{t('ok_match', UI_LANG_CODE)}</span>"
        )
        q_badge = (
            f"<span class='badge ok'>{t('good_quality', UI_LANG_CODE)}</span>"
            if qscore >= 0.6 else f"<span class='badge mid'>{t('weak_quality', UI_LANG_CODE)}</span>"
        )
        st.markdown(f"<div class='badge mid'>{t('governance', UI_LANG_CODE)}</div> {drift_badge} {shadow_badge} {q_badge}", unsafe_allow_html=True)

        st.markdown(f"**{t('ai_rationale', UI_LANG_CODE)}**")
        st.info(rationale_text or "(no rationale)")
        st.markdown(f"**{t('recommended_action', UI_LANG_CODE)}:** `{row.get('action', 'manual_review')}`")

        # 🔊 Speak rationale with Polly (localized voice + optional regeneration in UI language)
        if st.checkbox(t("regen_in_lang", UI_LANG_CODE), value=False) and is_analyst:
            with st.spinner(t("bedrock_calling", UI_LANG_CODE)):
                rationale_text, _ = generate_rationale(
                    features_dict,
                    float(row.get("fraud_prob", 0.0)),
                    float(row.get("anomaly_score", 0.0)),
                    bedrock_lang_name(UI_LANG_CODE),
                    bedrock_model
                )
            try:
                if use_aws and TABLE_NAME:
                    _get_ddb().Table(TABLE_NAME).update_item(
                        Key={"case_id": row["case_id"], "created_at": str(row.get("created_at",""))},
                        UpdateExpression="SET rationale=:r",
                        ExpressionAttributeValues={":r": rationale_text}
                    )
                else:
                    save_case_local_update(row["case_id"], str(row.get("created_at","")), {"rationale": rationale_text})
                if row_index is not None:
                    df.loc[row_index, "rationale"] = rationale_text
            except Exception as e:
                st.warning(f"Could not persist regenerated rationale: {e}")

        if st.button(t("speak_rationale", UI_LANG_CODE)):
            voice = pick_polly_voice(UI_LANG_CODE)
            audio = polly_speak(rationale_text or t("ai_rationale", UI_LANG_CODE), voice=voice)
            if audio:
                st.audio(audio, format="audio/mp3")
            else:
                st.warning("Could not synthesize speech (check AWS creds/region/Polly access).")

        st.session_state["__last_composite"] = composite
        st.markdown(
            f"""<script>
              const els = window.parent.document.querySelectorAll('.kvalue');
              if (els && els.length>=4) {{ els[3].innerText = "{composite:.2f}"; }}
            </script>""",
            unsafe_allow_html=True
        )

        with st.expander(f"🔒 {t('audit_packet', UI_LANG_CODE)}", expanded=False):
            prev_hash = st.session_state.audit_chain.get(row["case_id"], "")
            audit_pkt = {
                "version": 1,
                "case_id": row["case_id"],
                "event_ts": int(time.time()),
                "event_iso": datetime.utcnow().isoformat() + "Z",
                "model": bedrock_model,
                "shadow_model": SHADOW_MODEL_ID or None,
                "inputs": features_dict,
                "scores": {
                    "risk": float(row.get("risk", 0.0)),
                    "fraud": float(row.get("fraud_prob", 0.0)),
                    "anomaly": float(row.get("anomaly_score", 0.0)),
                    "explanation_quality": round(qscore, 3),
                    "composite": round(composite, 3)
                },
                "rationale": rationale_text,
                "recommendation": row.get("action", "manual_review"),
                "governance": {
                    "drift_z": round(float(z), 3),
                    "drift_flag": bool(drift_bad),
                    "shadow_action": shadow_action,
                    "shadow_agree": True if (agree is None or agree) else False
                },
                "analyst": st.session_state.analyst_id,
                "prev_hash": prev_hash or ""
            }
            ahash = make_audit_hash(audit_pkt, prev_hash)
            st.session_state.audit_chain[row["case_id"]] = ahash
            st.markdown(f"**{t('audit_hash', UI_LANG_CODE)}:** `{ahash}`")
            if prev_hash:
                st.markdown(f"**{t('prev_hash', UI_LANG_CODE)}:** `{prev_hash}`")
            st.json(audit_pkt)
            if not is_auditor:
                commit_baseline(amount, country)

        if is_analyst:
            with st.expander(f"🧪 {t('what_if', UI_LANG_CODE)}", expanded=False):
                cf_amount = st.number_input(t("try_amount", UI_LANG_CODE), value=float(features_dict.get("amount", 100.0)))
                cf_country = st.text_input(t("try_country", UI_LANG_CODE), value=str(features_dict.get("country", "US")))
                if st.button(t("ask_helena", UI_LANG_CODE)):
                    rationale_cf, _ = generate_rationale(
                        {"amount": cf_amount, "country": cf_country},
                        float(row.get("fraud_prob", 0.0)),
                        float(row.get("anomaly_score", 0.0)),
                        bedrock_lang_name(UI_LANG_CODE),
                        bedrock_model
                    )
                    st.info(rationale_cf)

       # ---- Helena Agent (runs only for Analysts) ----
# ---- Helena Agent (runs only for Analysts) ----
if is_analyst:
    if st.button(f"🤖 {t('run_agent', UI_LANG_CODE)}", type="primary"):
        simf = dict(features_dict)
        simf["simulated_velocity"] = 0.42

        # Measure latency around the model call
        t0 = time.time()
        new_rat, new_act = generate_rationale(
            simf,
            float(row.get("fraud_prob", 0.0)),
            float(row.get("anomaly_score", 0.0)),
            bedrock_lang_name(UI_LANG_CODE),
            bedrock_model
        )
        latency_ms = (time.time() - t0) * 1000
        tokens_used = len(str(new_rat))  # simple placeholder
        model_drift_z = 0.0              # placeholder drift metric
        emit_metrics_to_cloudwatch(latency_ms, tokens_used, model_drift_z)

        tl = st.session_state.timeline.setdefault(row["case_id"], [])
        tl.append(f"{st.session_state.analyst_id}: Agent updated recommendation to '{new_act}'")
        st.toast("Agent run complete (demo).")

        # update the existing placeholder instead of adding a second box
        rat_holder.info(new_rat)
# ------------------------------------------------

# -----------------------------------------------




        with st.expander(f"🧭 {t('timeline', UI_LANG_CODE)}", expanded=False):
            tl = st.session_state.timeline.setdefault(row["case_id"], [])
            if not tl:
                tl.extend(["AI flagged high risk", "Analyst viewed rationale"])
            st.markdown("\n".join([f"- {e}" for e in tl]))
            if is_analyst:
                new_note = st.text_input(t("add_note", UI_LANG_CODE), key=f"note_{row['case_id']}")
                if st.button(t("save_note", UI_LANG_CODE), key=f"save_{row['case_id']}"):
                    if new_note.strip():
                        tl.append(f"{st.session_state.analyst_id}: {new_note.strip()}")
                        st.toast("Note saved")

        with st.expander(f"💬 {t('helena_chat', UI_LANG_CODE)}", expanded=False):
            for role, content in st.session_state.chat:
                with st.chat_message(role):
                    st.markdown(content)
            prompt = st.chat_input(t("hint_chat", UI_LANG_CODE))
            if prompt:
                st.session_state.chat.append(("user", prompt))
                with st.chat_message("user"):
                    st.markdown(prompt)
                reply, _ = generate_rationale(
                    features_dict,
                    float(row.get("fraud_prob", 0.0)),
                    float(row.get("anomaly_score", 0.0)),
                    bedrock_lang_name(UI_LANG_CODE),
                    bedrock_model
                )
                st.session_state.chat.append(("assistant", reply))
                with st.chat_message("assistant"):
                    st.markdown(reply)

        if is_analyst:
            st.markdown("---")
            st.markdown(f"### {t('labels_heading', UI_LANG_CODE)}")
            label_val = st.radio(t("final_label", UI_LANG_CODE), ["fraud", "legit", "unsure"], horizontal=True, index=2)
            conf = st.slider(t("label_conf", UI_LANG_CODE), 0.0, 1.0, 0.8, 0.05)
            if st.button(t("save_label", UI_LANG_CODE)):
                label_item = {
                    "case_id": row["case_id"],
                    "created_at": str(row.get("created_at", "")),
                    "label": label_val,
                    "confidence": Decimal(str(conf)),
                    "risk": Decimal(str(row.get("risk", 0.0))),
                    "fraud_prob": Decimal(str(row.get("fraud_prob", 0.0))),
                    "anomaly_score": Decimal(str(row.get("anomaly_score", 0.0))),
                    "ts": int(time.time())
                }
                try:
                    if LABELS_TABLE and use_aws and boto3:
                        ddb = _get_ddb()
                        ddb.Table(LABELS_TABLE).put_item(Item=label_item)
                        st.success("Label saved to DynamoDB ✅")
                    else:
                        with open("labels_local.jsonl", "a", encoding="utf-8") as f:
                            f.write(json.dumps(label_item) + "\n")
                        st.info("Label saved locally (labels_local.jsonl).")
                except Exception as e:
                    st.error(f"Could not save label: {e}")

            cA, cB, cC, cD = st.columns(4)
            with cA:
                if st.button(t("dispatch_approve", UI_LANG_CODE)):
                    ok, err = _emit_decision_event(
                        row["case_id"], str(row.get("created_at", "")), "approve",
                        {"user": row.get("user_id"), "features": features_dict}
                    )
                    st.success("Approve dispatched ✅") if ok else st.error(f"Dispatch failed: {err}")
            with cB:
                if st.button(t("dispatch_hold", UI_LANG_CODE)):
                    ok, err = _emit_decision_event(
                        row["case_id"], str(row.get("created_at", "")), "hold",
                        {"user": row.get("user_id"), "features": features_dict}
                    )
                    st.success("Hold dispatched ✅") if ok else st.error(f"Dispatch failed: {err}")
            with cC:
                if st.button(t("dispatch_review", UI_LANG_CODE)):
                    ok, err = _emit_decision_event(
                        row["case_id"], str(row.get("created_at", "")), "manual_review",
                        {"user": row.get("user_id"), "features": features_dict}
                    )
                    st.success("Review dispatched ✅") if ok else st.error(f"Dispatch failed: {err}")
            with cD:
                if st.button(t("dispatch_decline", UI_LANG_CODE)):
                    ok, err = _emit_decision_event(
                        row["case_id"], str(row.get("created_at", "")), "decline",
                        {"user": row.get("user_id"), "features": features_dict}
                    )
                    st.success("Decline dispatched ✅") if ok else st.error(f"Dispatch failed: {err}")

            if st.button(t("trigger_retrain", UI_LANG_CODE)):
                try:
                    if RETRAIN_LAMBDA and use_aws and boto3:
                        lam = boto3.client("lambda", region_name=DDB_REGION)
                        lam.invoke(
                            FunctionName=RETRAIN_LAMBDA,
                            InvocationType="Event",
                            Payload=json.dumps({"reason": "analyst_feedback", "project": "FraudCopilot"}).encode("utf-8")
                        )
                        st.success("Retrain trigger sent to Lambda ✅")
                    elif RETRAIN_QUEUE_URL and use_aws and boto3:
                        sqs = boto3.client("sqs", region_name=DDB_REGION)
                        sqs.send_message(
                            QueueUrl=RETRAIN_QUEUE_URL,
                            MessageBody=json.dumps({"reason": "analyst_feedback"})
                        )
                        st.success("Retrain trigger sent to SQS ✅")
                    else:
                        st.info("Set RETRAIN_LAMBDA or RETRAIN_QUEUE_URL to enable remote retraining.")
                except Exception as e:
                    st.error(f"Failed to trigger retrain: {e}")

        if is_reviewer:
            st.markdown("---")
            st.markdown(f"### {t('reviewer_block', UI_LANG_CODE)}")
            st.caption(t("reviewer_help", UI_LANG_CODE))
            options = ["approve", "manual_review", "hold", "decline"]
            current = str(row.get("action", "manual_review"))
            new_dec = st.selectbox("Decision", options, index=options.index(current) if current in options else 1)
            if st.button(t("save_reviewer", UI_LANG_CODE)):
                try:
                    if use_aws and TABLE_NAME:
                        ddb = _get_ddb()
                        tdb = ddb.Table(TABLE_NAME)
                        tdb.update_item(
                            Key={"case_id": row["case_id"], "created_at": str(row.get("created_at", ""))},
                            UpdateExpression="SET #act=:a",
                            ExpressionAttributeNames={"#act": "action"},
                            ExpressionAttributeValues={":a": new_dec}
                        )
                    else:
                        save_case_local_update(row["case_id"], str(row.get("created_at", "")), {"action": new_dec})
                    if row_index is not None:
                        df.loc[row_index, "action"] = new_dec
                    ok, err = _emit_decision_event(
                        row["case_id"], str(row.get("created_at", "")), new_dec,
                        {"user": row.get("user_id"), "features": features_dict}
                    )
                    msg = "Reviewer decision saved ✅"
                    st.success(msg if ok else f"{msg} (webhook failed: {err})")
                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to save decision: {e}")

with col2:
    st.subheader(t("kpi_summary", UI_LANG_CODE))
    st.caption(t("show_all", UI_LANG_CODE))

    with st.expander(t("monitoring", UI_LANG_CODE), expanded=False):
        ns = os.getenv("CLOUDWATCH_NAMESPACE", "FraudCopilot")
        colm1, colm2 = st.columns(2)
        with colm1:
            st.caption(t("requests_decisions", UI_LANG_CODE))
            d_requests = cw_metric_df(ns, "Requests", "Service", "console", stat="Sum")
            d_decisions = cw_metric_df(ns, "Decisions", "Service", "console", stat="Sum")
            if not d_requests.empty:
                st.line_chart(d_requests.set_index("ts")["value"])
            if not d_decisions.empty:
                st.line_chart(d_decisions.set_index("ts")["value"])

            st.caption(t("bedrock_tokens", UI_LANG_CODE))
            d_tokens = cw_metric_df(ns, "BedrockTokens", "Model", "all", stat="Sum")
            if not d_tokens.empty:
                st.line_chart(d_tokens.set_index("ts")["value"])
        with colm2:
            st.caption(t("latency", UI_LANG_CODE))
            d_lat = cw_metric_df(ns, "FraudScoreLatencyMs", "Service", "console", stat="Average")
            if not d_lat.empty:
                st.line_chart(d_lat.set_index("ts")["value"])

            st.caption(t("driftz", UI_LANG_CODE))
            d_drift = cw_metric_df(ns, "ModelDriftZ", "Country", "all", stat="Average")
            if not d_drift.empty:
                st.line_chart(d_drift.set_index("ts")["value"])

    st.caption("Tip: emit these metrics from your scoring path via CloudWatch PutMetricData.")

# ========================= Add New Fraud Case ==========================
if is_analyst:
    st.write(f"### {t('add_new_case', UI_LANG_CODE)}")
    with st.form("new_case_form"):
        default_case_id = f"T{int(time.time())}"
        case_id = st.text_input(t("field_case_id", UI_LANG_CODE), value=default_case_id)
        created_at = st.text_input(t("field_created_at", UI_LANG_CODE), value=str(int(time.time())))
        user_id = st.text_input(t("field_user_id", UI_LANG_CODE))
        transaction_id = st.text_input(t("field_transaction_id", UI_LANG_CODE))
        amount = st.number_input(t("field_amount", UI_LANG_CODE), min_value=0.0, step=0.01)
        currency = st.text_input(t("field_currency", UI_LANG_CODE), value="USD")
        risk_val = st.slider(t("field_risk", UI_LANG_CODE), 0.0, 1.0, 0.5)
        action_choice = st.selectbox(t("field_action", UI_LANG_CODE), ["approve", "manual_review", "hold", "decline"])
        notes = st.text_area(t("field_notes", UI_LANG_CODE))

        submitted = st.form_submit_button(t("save_case", UI_LANG_CODE))
        if submitted:
            if not use_aws:
                st.error(t("must_enable_aws", UI_LANG_CODE))
            elif not TABLE_NAME:
                st.error(t("not_set", UI_LANG_CODE))
            elif not case_id or not created_at:
                st.error(t("both_required", UI_LANG_CODE))
            else:
                try:
                    ddb = _get_ddb()
                    tdb = ddb.Table(TABLE_NAME)
                    existing = tdb.get_item(Key={"case_id": case_id, "created_at": str(created_at)}).get("Item")
                    if existing:
                        st.error("Duplicate case_id + created_at. Change either value.")
                    else:
                        raw_features = {"amount": float(amount), "country": "US", "currency": currency}
                        ef = enrich_features(raw_features)
                        rationale_text, maybe_action = generate_rationale(
                            features=ef, fraud_prob=0.0, anomaly_score=0.0,
                            language=bedrock_lang_name(UI_LANG_CODE), model_id=bedrock_model
                        )
                        final_action = maybe_action or action_choice
                        item = {
                            "case_id": case_id, "created_at": str(created_at),
                            "user_id": user_id, "transaction_id": transaction_id,
                            "amount": Decimal(str(amount)), "currency": currency,
                            "risk": Decimal(str(risk_val)), "fraud_prob": Decimal("0"), "anomaly_score": Decimal("0"),
                            "action": final_action, "rationale": (notes.strip() or rationale_text),
                            "features": json.dumps(ef), "ts": int(time.time())
                        }
                        tdb.put_item(Item=item)
                        st.success(t("case_added", UI_LANG_CODE).format(case_id=case_id))
                        st.cache_data.clear()
                        st.rerun()
                except Exception as e:
                    st.error(f"Error saving case: {e}")

# -------------------- Auto-refresh (optional) --------------------------
if auto_refresh:
    time.sleep(10)
    st.rerun()

# ------------------- Floating Assistant (bottom-right) -----------------
st.markdown("""
<style>
#fc-fab { position: fixed; bottom: 22px; right: 22px; width: 52px; height: 52px; border-radius: 50%;
  background: #111827; border: 1px solid #374151; color: #fff; font-weight: 800; cursor: pointer;
  box-shadow: 0 10px 28px rgba(0,0,0,.3); z-index: 99998; }
#fc-panel { position: fixed; bottom: 86px; right: 22px; width: 380px; max-height: 62vh; overflow: hidden;
  background: #0f172a; border: 1px solid #1f2937; border-radius: 14px; box-shadow: 0 20px 48px rgba(0,0,0,.45);
  z-index: 99999; }
.fc-head { display:flex; align-items:center; justify-content:space-between; padding: 10px 12px; background: #111827;
  border-bottom: 1px solid #1f2937; color: #e5e7eb; font-weight: 700; font-size: 13px; }
.fc-body { padding: 10px 12px; overflow-y: auto; max-height: 44vh; }
.fc-input { display:flex; gap: 6px; padding: 10px 12px; border-top: 1px solid #1f2937; background: #0b1220; }
.fc-badge { background:#0b2a1b; color:#86efac; border:1px solid #166534; padding:2px 8px; border-radius: 999px; font-size: 11px; margin-left:6px; }
.fc-bubble-user { background:#1f2937; color:#e5e7eb; border:1px solid #374151; padding:8px 10px; border-radius:10px;
  margin:6px 0 6px auto; max-width: 88%; }
.fc-bubble-assistant { background:#0b1220; color:#e5e7eb; border:1px solid #1f2937; padding:8px 10px; border-radius:10px;
  margin:6px auto 6px 0; max-width: 88%; }
.fc-small { font-size: 11px; color:#9ca3af; }
</style>
""", unsafe_allow_html=True)

if "fc_open" not in st.session_state:
    st.session_state.fc_open = False
if "fc_chat" not in st.session_state:
    st.session_state.fc_chat = []
if "fc_input_buf" not in st.session_state:
    st.session_state.fc_input_buf = ""
if "last_tts" not in st.session_state:
    st.session_state.last_tts = b""

def _fc_render_messages():
    if not st.session_state.fc_chat:
        st.markdown('<div class="fc-small">Ask about cases, rationale, thresholds, playbooks…</div>', unsafe_allow_html=True)
        return
    for m in st.session_state.fc_chat:
        cls = "fc-bubble-user" if m["role"] == "user" else "fc-bubble-assistant"
        st.markdown(f'<div class="{cls}">{m["text"]}</div>', unsafe_allow_html=True)

from streamlit.components.v1 import html as _html
_html("""<button id="fc-fab" onclick="parent.postMessage({type:'fc_toggle'}, '*')">🤖</button>
<script> window.addEventListener('message', (e)=>{}); </script>""", height=60)

toggle_col = st.empty()
if toggle_col.button("fc__internal_toggle_button", key="fc_toggle_btn", help="", type="secondary", disabled=True):
    st.session_state.fc_open = not st.session_state.fc_open

st.markdown("""
<script>
  window.addEventListener('message', (ev) => {
    if (ev && ev.data && ev.data.type === 'fc_toggle') {
      const root = window.parent.document;
      const btns = Array.from(root.querySelectorAll('button'));
      const target = btns.find(b => b.innerText.trim() === 'fc__internal_toggle_button');
      if (target) target.click();
    }
  });
</script>
""", unsafe_allow_html=True)

if st.session_state.fc_open:
    st.markdown('<div id="fc-panel">', unsafe_allow_html=True)

    st.markdown(
        f"""
        <div class="fc-head">
          <div>Assistant <span class="fc-badge">online</span></div>
          <div class="fc-small">{bedrock_lang_name(UI_LANG_CODE)} • {st.session_state.get('current_role','Analyst')}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    body_holder = st.container()
    with body_holder:
        st.markdown('<div class="fc-body">', unsafe_allow_html=True)
        _fc_render_messages()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="fc-input">', unsafe_allow_html=True)
    c_in, c_send, c_tts = st.columns([6, 1, 1])
    with c_in:
        st.session_state.fc_input_buf = st.text_input(
            t("assistant_placeholder", UI_LANG_CODE),
            key="fc_text_in",
            label_visibility="collapsed",
            value=st.session_state.fc_input_buf
        )
    send_clicked = c_send.button("➤", key="fc_send")
    speak_clicked = c_tts.button("🔊", key="fc_tts")
    st.markdown('</div>', unsafe_allow_html=True)

    if send_clicked and st.session_state.fc_input_buf.strip():
        user_q = st.session_state.fc_input_buf.strip()
        st.session_state.fc_chat.append({"role": "user", "text": user_q})

        def _df_preview_for_llm(dff, n=15):
            if dff is None or getattr(dff, "empty", True):
                return "No rows."
            cols = [c for c in ["case_id","user_id","risk","fraud_prob","anomaly_score","action"] if c in dff.columns]
            lines = []
            for _, r in dff.head(n).iterrows():
                lines.append(", ".join(f"{c}={r.get(c)}" for c in cols))
            return "\\n".join(lines)

        page_context = textwrap.dedent(f"""
        App context:
        - Role: {st.session_state.get('current_role')}
        - Language: {UI_LANG_CODE} ({bedrock_lang_name(UI_LANG_CODE)})
        - Risk filter: min={risk_min:.2f} | show_all={show_all}
        - DynamoDB enabled: {use_aws}
        - Table: {TABLE_NAME or 'not set'}
        - Totals: flagged={len(df)}, avg_risk={float(df['risk'].mean() if len(df) else 0):.3f}, max_risk={float(df['risk'].max() if len(df) else 0):.3f}

        Recent rows (top 15):
        {_df_preview_for_llm(df, 15)}
        """).strip()

        SYSTEM_PROMPT = """You are Helena, an expert fraud-ops copilot embedded in a Streamlit console.
Answer with clear, concise guidance. When asked about data, use only the provided context.
If the user asks for actions, explain steps; if they ask for code, provide minimal working snippets.
If a question is unrelated to fraud or this console, politely redirect."""

        try:
            from bedrock_helpers import bedrock_chat
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"{page_context}\n\nUser question: {user_q}"}
            ]
            with st.spinner("Thinking…"):
                answer = bedrock_chat(messages, model_id=bedrock_model, max_tokens=1200, temperature=0.4)
        except Exception as e:
            answer = f"Bedrock call failed: {e}"

        st.session_state.fc_chat.append({"role": "assistant", "text": answer})
        st.session_state.fc_input_buf = ""
        st.rerun()

    if speak_clicked:
        last_assistant = next((m["text"] for m in reversed(st.session_state.fc_chat) if m["role"]=="assistant"), "")
        if last_assistant:
            try:
                mp3 = polly_speak(last_assistant, voice=pick_polly_voice(UI_LANG_CODE))
                st.session_state.last_tts = mp3
            except Exception as e:
                st.warning(f"Polly error: {e}")

    if st.session_state.get("last_tts"):
        st.audio(st.session_state["last_tts"], format="audio/mp3")

    st.markdown('</div>', unsafe_allow_html=True)
# ------------------- end floating assistant -------------------
