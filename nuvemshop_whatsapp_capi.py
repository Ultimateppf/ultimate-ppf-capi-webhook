#!/usr/bin/env python3
"""
nuvemshop_whatsapp_capi.py
==========================
Webhook server que recebe eventos de pedido da Nuvemshop (order/created, order/paid),
detecta pedidos originados via WhatsApp (utm_source=whatsapp OU ctwa_clid presente)
e dispara um evento Purchase no Meta Conversions API com atribuição correta.

NÚMEROS MAPEADOS:
- utm_content=numero_0324 → +55 67 9692-0324 (Nuvem Chat / IA)
- utm_content=numero_6052 → +55 67 9646-6052 (vendas manual)
- utm_content=numero_6900 → +55 67 9674-6900 (vendas manual)

DEPENDÊNCIAS:
pip install flask requests

USO:
python nuvemshop_whatsapp_capi.py

Variáveis de ambiente (obrigatórias):
META_PIXEL_ID       → ID do Pixel Meta (ex: 123456789)
META_ACCESS_TOKEN   → Token de acesso do Conversions API
NUVEMSHOP_SECRET    → Secret do webhook da Nuvemshop (para validação HMAC)
PORT                → Porta do servidor (padrão: 5001)
"""

import os
import hmac
import hashlib
import json
import sqlite3
import time
import uuid
import hashlib as hl
import requests
from flask import Flask, request, jsonify
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIGURAÇÃO
# ──────────────────────────────────────────────

PIXEL_ID = os.getenv("META_PIXEL_ID", "SEU_PIXEL_ID_AQUI")
ACCESS_TOKEN = os.getenv("META_ACCESS_TOKEN", "SEU_ACCESS_TOKEN_AQUI")
NUVEMSHOP_SECRET = os.getenv("NUVEMSHOP_SECRET", "SEU_SECRET_AQUI")
PORT = int(os.getenv("PORT", 5001))
DB_PATH = os.getenv("DB_PATH", "nuvemshop_events.db")
TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

# Banco do whatsapp_ctwa_receiver.py — usado para lookup de ctwa_clid
# Deve ser o mesmo arquivo ctwa_store.db usado pelo receiver
CTWA_DB_PATH = os.getenv("CTWA_DB_PATH", "ctwa_store.db")

CAPI_URL = f"https://graph.facebook.com/v19.0/{PIXEL_ID}/events"

# Mapeamento utm_content → número WhatsApp (formato E.164 sem +, 12 dígitos: 55+DDD+número)
UTM_CONTENT_TO_PHONE = {
    "numero_0324": "556796920324",  # +55 67 9692-0324 — Nuvem Chat / IA
    "numero_6052": "556796466052",  # +55 67 9646-6052 — Vendas manual
    "numero_6900": "556796746900",  # +55 67 9674-6900 — Vendas manual
}

# Mapeamento utm_content → nome legível do canal
UTM_CONTENT_TO_CHANNEL = {
    "numero_0324": "Nuvem Chat (IA) — 9692-0324",
    "numero_6052": "Vendas Manual — 9646-6052",
    "numero_6900": "Vendas Manual — 9674-6900",
}

app = Flask(__name__)

# ──────────────────────────────────────────────
# BANCO DE DADOS (deduplicação)
# ──────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS processed_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            event_id TEXT NOT NULL UNIQUE,
            utm_content TEXT,
            phone_channel TEXT,
            value REAL,
            currency TEXT,
            sent_at TEXT,
            capi_response TEXT
        )
    """)
    conn.commit()
    conn.close()

def is_duplicate(event_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

def save_event(order_id, event_id, utm_content, phone_channel, value, currency, capi_response):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT OR IGNORE INTO processed_events
            (order_id, event_id, utm_content, phone_channel, value, currency, sent_at, capi_response)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(order_id), event_id, utm_content, phone_channel,
        value, currency, datetime.utcnow().isoformat(),
        json.dumps(capi_response, ensure_ascii=False)
    ))
    conn.commit()
    conn.close()

# ──────────────────────────────────────────────
# VALIDAÇÃO HMAC (Nuvemshop)
# ──────────────────────────────────────────────

def validate_nuvemshop_signature(payload_bytes: bytes, signature_header: str) -> bool:
    """Valida o X-Linkedstore-Token ou HMAC SHA256 enviado pela Nuvemshop."""
    if not NUVEMSHOP_SECRET or NUVEMSHOP_SECRET == "SEU_SECRET_AQUI":
        app.logger.warning("NUVEMSHOP_SECRET não configurado — pulando validação HMAC")
        return True  # Em desenvolvimento, aceitar sem validar
    expected = hmac.new(
        NUVEMSHOP_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header or "")

# ──────────────────────────────────────────────
# NUVEMSHOP API — buscar pedido completo
# ──────────────────────────────────────────────

def fetch_nuvemshop_order(store_id, order_id):
    """
    Busca pedido completo na API Nuvemshop.
    O webhook só envia payload mínimo {store_id, event, id} — sem total, produtos ou cliente.
    Esta função busca o pedido completo usando o NUVEMSHOP_TOKEN configurado no Railway.
    """
    token = os.getenv("NUVEMSHOP_TOKEN", "")
    if not token or not store_id or not order_id:
        app.logger.warning(
            f"fetch_nuvemshop_order: token={'SET' if token else 'MISSING'} "
            f"store_id={store_id} order_id={order_id}"
        )
        return None
    try:
        resp = requests.get(
            f"https://api.tiendanube.com/v1/{store_id}/orders/{order_id}",
            headers={
                "Authentication": f"bearer {token}",
                "User-Agent": "UltimatePPF-CAPI/1.0",
            },
            timeout=15,
        )
        if resp.ok:
            order_full = resp.json()
            app.logger.info(
                f"[API Nuvemshop] Pedido #{order_id} buscado — "
                f"total={order_full.get('total')} currency={order_full.get('currency')}"
            )
            return order_full
        app.logger.warning(
            f"[API Nuvemshop] HTTP {resp.status_code} ao buscar pedido #{order_id}: {resp.text[:200]}"
        )
        return None
    except Exception as e:
        app.logger.warning(f"[API Nuvemshop] Erro ao buscar pedido #{order_id}: {e}")
        return None

# ──────────────────────────────────────────────
# CTWA ATTRIBUTION — lookup ctwa_clid → fbc
# ──────────────────────────────────────────────

def lookup_ctwa_clid(customer_phone: str) -> str:
    """
    Busca o ctwa_clid mais recente para o telefone do cliente no banco do
    whatsapp_ctwa_receiver.py (ctwa_store.db).

    O ctwa_clid é gerado quando o cliente clica num anúncio CTWA (Click-to-WhatsApp)
    e enviado ao Meta CAPI como campo `fbc` — isso fecha o loop de atribuição,
    ligando a compra ao anúncio exato que gerou o lead.

    Retorna o ctwa_clid (string) ou "" se não encontrado.
    """
    if not customer_phone:
        return ""
    try:
        conn = sqlite3.connect(CTWA_DB_PATH, timeout=5)
        row = conn.execute("""
            SELECT ctwa_clid FROM ctwa_clicks
            WHERE phone = ?
              AND ctwa_clid IS NOT NULL
              AND ctwa_clid != ''
              AND ctwa_clid NOT LIKE 'MSG:%'
            ORDER BY received_at DESC
            LIMIT 1
        """, (customer_phone,)).fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception as e:
        # Banco pode não existir ainda (receiver não iniciado)
        if app:
            app.logger.debug(f"ctwa lookup ({customer_phone}): {e}")
    return ""

# ──────────────────────────────────────────────
# HASHING PII (Meta CAPI exige SHA256)
# ──────────────────────────────────────────────

def sha256(value: str) -> str:
    if not value:
        return ""
    return hl.sha256(value.strip().lower().encode("utf-8")).hexdigest()

def format_phone(phone: str) -> str:
    """Remove tudo que não for dígito e garante formato E.164 sem +"""
    digits = "".join(filter(str.isdigit, phone or ""))
    if digits.startswith("0"):
        digits = digits[1:]
    if not digits.startswith("55") and len(digits) <= 11:
        digits = "55" + digits
    return digits

# ──────────────────────────────────────────────
# EXTRAÇÃO DE UTM DO PEDIDO NUVEMSHOP
# ──────────────────────────────────────────────

def extract_utm(order: dict) -> dict:
    """
    Extrai parâmetros UTM do pedido Nuvemshop.
    Localização possível:
    - order["landing_url"]    — URL de origem
    - order["utm_parameters"] — objeto UTM (nem sempre presente)
    - order["referring_url"]
    """
    utm = {
        "utm_source":   "",
        "utm_medium":   "",
        "utm_campaign": "",
        "utm_content":  "",
        "utm_term":     "",
    }

    # 1. Tentar objeto utm_parameters direto
    utm_obj = order.get("utm_parameters") or {}
    if isinstance(utm_obj, dict):
        for k in utm:
            if k in utm_obj:
                utm[k] = str(utm_obj[k] or "")

    # 2. Tentar landing_url como fallback
    landing = order.get("landing_url") or order.get("referring_url") or ""
    if landing and not utm["utm_source"]:
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(landing)
            params = parse_qs(parsed.query)
            for k in utm:
                if k in params:
                    utm[k] = params[k][0]
        except Exception:
            pass

    return utm

# ──────────────────────────────────────────────
# DISPARO META CAPI
# ──────────────────────────────────────────────

def send_capi_purchase(order: dict, utm: dict, phone_number: str) -> dict:
    """Dispara evento Purchase para o Meta Conversions API."""

    order_id = str(order.get("id") or order.get("number") or uuid.uuid4())
    # event_id = order_id puro, IGUAL ao que o CAPI nativo da Nuvemshop usa.
    # O Meta deduplica eventos com event_id IDÊNTICO: se o mesmo pedido também
    # gerar um Purchase nativo (site/CAPI Nuvemshop), o Meta conta UMA venda só
    # — sem dupla marcação. A atribuição CTWA é preservada pelo fbc no user_data.
    event_id = order_id

    # Valor e moeda
    total = float(order.get("total") or order.get("total_price") or 0)
    currency = str(order.get("currency") or "BRL").upper()

    # PII do cliente
    customer = order.get("customer") or {}
    billing  = order.get("billing_address") or customer.get("default_address") or {}

    email_raw = (customer.get("email") or billing.get("email") or "").strip().lower()

    # Telefone do cliente (separado para uso no lookup ctwa_clid)
    customer_phone_raw = format_phone(customer.get("phone") or billing.get("phone") or "")
    # Para o campo ph: usar telefone do cliente ou, como fallback, o número do canal
    phone_raw = customer_phone_raw or format_phone(phone_number)

    # FIX: safe split — evita IndexError quando nome está vazio
    _fn_parts  = (billing.get("first_name") or customer.get("name") or "").split()
    first_name = _fn_parts[0].lower() if _fn_parts else ""
    last_name_parts = (billing.get("last_name")  or customer.get("name") or "").split()
    last_name       = last_name_parts[-1].lower() if last_name_parts else ""
    city            = (billing.get("city") or "").lower()
    state           = (billing.get("province_code") or billing.get("state") or "").lower()
    zip_code        = "".join(filter(str.isdigit, billing.get("zipcode") or billing.get("zip") or ""))
    country         = (billing.get("country") or "BR").upper()

    # Timestamp do pedido
    created_at = order.get("created_at") or ""
    try:
        from dateutil import parser as dparser
        event_time = int(dparser.parse(created_at).timestamp())
    except Exception:
        event_time = int(time.time())

    # ── CTWA Attribution: buscar ctwa_clid do cliente ──────────────────────────
    ctwa_clid = lookup_ctwa_clid(customer_phone_raw)
    fbc_value = f"fb.1.{int(time.time() * 1000)}.{ctwa_clid}" if ctwa_clid else ""
    # ───────────────────────────────────────────────────────────────────────────

    # user_data
    user_data = {
        "external_id":        [sha256(str(order.get("customer_id") or email_raw or order_id))],
        "client_ip_address":  order.get("client_ip") or "",
        "client_user_agent":  "",
    }
    if fbc_value:
        user_data["fbc"] = fbc_value  # ← atribuição CTWA — campo crítico para ROAS
    if email_raw:
        user_data["em"]  = [sha256(email_raw)]
    if phone_raw:
        user_data["ph"]  = [sha256(phone_raw)]
    if first_name:
        user_data["fn"]  = [sha256(first_name)]
    if last_name:
        user_data["ln"]  = [sha256(last_name)]
    if city:
        user_data["ct"]  = [sha256(city)]
    if state:
        user_data["st"]  = [sha256(state)]
    if zip_code:
        user_data["zp"]  = [sha256(zip_code)]
    if country:
        user_data["country"] = [sha256(country)]

    # custom_data
    contents = []
    for item in (order.get("products") or order.get("line_items") or []):
        contents.append({
            "id":        str(item.get("product_id") or item.get("id") or ""),
            "quantity":  int(item.get("quantity") or 1),
            "item_price": float(item.get("price") or 0),
        })

    custom_data = {
        "value":        total,
        "currency":     currency,
        "order_id":     order_id,
        "content_type": "product",
    }
    if contents:
        custom_data["contents"] = contents

    # Informações do canal WhatsApp
    custom_data["whatsapp_channel"] = UTM_CONTENT_TO_CHANNEL.get(utm["utm_content"], utm["utm_content"])
    custom_data["utm_medium"]       = utm["utm_medium"]
    custom_data["utm_campaign"]     = utm["utm_campaign"]

    event = {
        "event_name":       "Purchase",
        "event_time":       event_time,
        "event_id":         event_id,
        "event_source_url": order.get("landing_url") or f"https://loja.ultimateppf.com.br/",
        "action_source":    "other",   # "other" para WhatsApp
        "user_data":        user_data,
        "custom_data":      custom_data,
    }

    payload = {
        "data": [event],
        "test_event_code": os.getenv("META_TEST_EVENT_CODE", "") or None,
    }
    # Remover test_event_code se vazio
    if not payload.get("test_event_code"):
        del payload["test_event_code"]

    params = {"access_token": ACCESS_TOKEN}

    if TEST_MODE:
        app.logger.info(f"[TEST MODE] Payload CAPI:\n{json.dumps(payload, indent=2, ensure_ascii=False)}")
        return {"test_mode": True, "payload": payload, "event_id": event_id, "_ctwa_clid": ctwa_clid}

    resp   = requests.post(CAPI_URL, params=params, json=payload, timeout=10)
    result = resp.json()
    result["event_id"]    = event_id
    result["http_status"] = resp.status_code
    result["_ctwa_clid"]  = ctwa_clid  # para log interno (não vai para a API)
    return result

# ──────────────────────────────────────────────
# ROTAS
# ──────────────────────────────────────────────

@app.route("/webhook/nuvemshop", methods=["POST"])
def nuvemshop_webhook():
    """Recebe eventos da Nuvemshop e processa pedidos WhatsApp."""

    payload_bytes = request.get_data()

    # Validar assinatura HMAC
    sig_header = (
        request.headers.get("X-Linkedstore-Token") or
        request.headers.get("X-Nuvemshop-Token")  or
        request.headers.get("X-HMAC-SHA256")       or ""
    )
    if not validate_nuvemshop_signature(payload_bytes, sig_header):
        app.logger.warning("Assinatura HMAC inválida — rejeitando webhook")
        return jsonify({"error": "invalid_signature"}), 401

    try:
        data = request.get_json(force=True) or {}
    except Exception as e:
        return jsonify({"error": f"JSON inválido: {e}"}), 400

    topic = data.get("topic") or data.get("event") or ""
    order = data.get("order") or data  # às vezes o payload é o pedido direto

    # FIX: O webhook Nuvemshop envia apenas payload mínimo {store_id, event, id}.
    # Buscar pedido completo na API para obter total, produtos e dados do cliente.
    store_id_from_payload  = data.get("store_id")
    order_id_from_payload  = data.get("id")
    if (not order.get("total") and not order.get("total_price")
            and store_id_from_payload and order_id_from_payload):
        full_order = fetch_nuvemshop_order(store_id_from_payload, order_id_from_payload)
        if full_order:
            order = full_order
        else:
            app.logger.warning(
                f"Não foi possível buscar pedido #{order_id_from_payload} — "
                f"processando com payload mínimo (total=0)"
            )


    order_id = str(order.get("id") or order.get("number") or "")

    # Só processar pedidos criados ou pagos
    if topic and "order" not in topic.lower():
        return jsonify({"status": "ignored", "reason": f"topic={topic}"}), 200

    # Extrair UTMs
    utm = extract_utm(order)

    app.logger.info(
        f"Pedido #{order_id} | topic={topic} | utm_source={utm['utm_source']} | utm_content={utm['utm_content']}"
    )

    # ── PRE-CHECK ctwa_clid (antes de filtrar por UTM) ─────────────────────────
    # O ctwa_clid prova que o cliente clicou num anúncio Meta CTWA.
    # Verificamos ANTES do filtro por utm_source para não perder compras reais
    # onde o cliente chegou via CTWA mas sem UTM no link de produto.
    customer_data = order.get("customer") or {}
    billing_data  = order.get("billing_address") or customer_data.get("default_address") or {}
    pre_check_phone = format_phone(
        customer_data.get("phone") or billing_data.get("phone") or ""
    )
    pre_check_ctwa = lookup_ctwa_clid(pre_check_phone)
    # ─────────────────────────────────────────────────────────────────────────

    # Verificar atribuição Meta: utm_source=whatsapp OU ctwa_clid presente.
    # Qualquer um dos dois é prova suficiente de origem em anúncio Meta/WhatsApp.
    is_whatsapp_utm = utm["utm_source"].lower() == "whatsapp"

    # ── FIX 3: Disparar CAPI para TODOS os pedidos pagos (não só WhatsApp) ──────
    # Pedidos WhatsApp (utm_source=whatsapp ou ctwa_clid): atribuição completa + fbc
    # Pedidos site (sem UTM/ctwa): email/phone hasheados → aumenta match rate no Meta
    # event_id = order_id garante deduplicação com o CAPI nativo da Nuvemshop.

    if not is_whatsapp_utm and not pre_check_ctwa:
        # FIX 4: Log explícito de diagnóstico (antes era retorno silencioso)
        _total_log = float(order.get("total") or order.get("total_price") or 0)
        app.logger.info(
            f"[CAPI SITE] Pedido #{order_id} | R$ {_total_log:.2f} | "
            f"phone={pre_check_phone or '—'} | utm_source={utm['utm_source'] or '—'} | "
            f"sem atribuição WhatsApp → disparando CAPI via email/phone hash"
        )
        phone_number = pre_check_phone  # phone do cliente para matching hash
        channel_name = "Site (sem atribuição WhatsApp)"
    else:
        # Identificar canal pelo utm_content (ou usar phone do cliente se só ctwa)
        phone_number = UTM_CONTENT_TO_PHONE.get(utm["utm_content"])
        channel_name = UTM_CONTENT_TO_CHANNEL.get(utm["utm_content"], "WhatsApp (CTWA)")

        if not phone_number:
            if pre_check_ctwa:
                # Sem mapeamento utm_content mas temos ctwa_clid — usar phone do cliente
                phone_number = pre_check_phone
                channel_name = "WhatsApp (CTWA — canal não identificado)"
            else:
                # FIX 4: Log em vez de retorno silencioso
                app.logger.info(
                    f"[CAPI WA] Pedido #{order_id} | utm_content não mapeado: "
                    f"'{utm['utm_content']}' → disparando com phone do cliente"
                )
                phone_number = pre_check_phone
                channel_name = f"WhatsApp (utm_content={utm['utm_content']})"

    # Deduplicação interna (mesmo event_id usado em send_capi_purchase)
    event_id = order_id
    if is_duplicate(event_id):
        app.logger.info(f"Pedido #{order_id} já processado (event_id={event_id}) — ignorando")
        return jsonify({"status": "duplicate", "event_id": event_id}), 200

    # Disparar evento CAPI
    try:
        capi_result = send_capi_purchase(order, utm, phone_number)
    except Exception as e:
        app.logger.error(f"Erro ao enviar CAPI: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

    # Salvar no banco
    value    = float(order.get("total") or order.get("total_price") or 0)
    currency = str(order.get("currency") or "BRL").upper()
    save_event(order_id, event_id, utm["utm_content"], channel_name, value, currency, capi_result)

    app.logger.info(
        f"✅ CAPI enviado | pedido #{order_id} | canal={channel_name} | "
        f"valor={currency} {value:.2f} | event_id={event_id} | "
        f"ctwa={'✅ ' + capi_result.get('_ctwa_clid', '')[:16] + '...' if capi_result.get('_ctwa_clid') else '⚠️ sem ctwa_clid'}"
    )

    return jsonify({
        "status":   "ok",
        "order_id": order_id,
        "event_id": event_id,
        "channel":  channel_name,
        "value":    value,
        "currency": currency,
        "capi":     capi_result,
    }), 200

@app.route("/webhook/nuvemshop/test", methods=["GET"])
def test_endpoint():
    """Endpoint de teste — verifica configuração sem precisar de webhook real."""
    return jsonify({
        "status":    "online",
        "pixel_id":  PIXEL_ID,
        "test_mode": TEST_MODE,
        "db_path":   DB_PATH,
        "channels":  UTM_CONTENT_TO_CHANNEL,
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.route("/webhook/nuvemshop/events", methods=["GET"])
def list_events():
    """Lista os últimos 50 eventos processados."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT order_id, event_id, utm_content, phone_channel, value, currency, sent_at
        FROM processed_events
        ORDER BY id DESC LIMIT 50
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"total": len(rows), "events": rows})

# ──────────────────────────────────────────────
# OAUTH CALLBACK — troca code por access_token e registra webhooks
# ──────────────────────────────────────────────

NUVEMSHOP_CLIENT_ID     = os.getenv("NUVEMSHOP_CLIENT_ID", "")
NUVEMSHOP_CLIENT_SECRET = os.getenv("NUVEMSHOP_CLIENT_SECRET", "")
NUVEMSHOP_TOKEN         = os.getenv("NUVEMSHOP_TOKEN", "")
NUVEMSHOP_USER_ID       = os.getenv("NUVEMSHOP_USER_ID", "7647937")
WEBHOOK_BASE_URL        = os.getenv("WEBHOOK_BASE_URL", "https://web-production-f9e966.up.railway.app")

# ──────────────────────────────────────────────
# WHATSAPP WEBHOOK — captura ctwa_clid de anúncios WZAP
# ──────────────────────────────────────────────

WA_VERIFY_TOKEN = os.getenv("WA_VERIFY_TOKEN", "ultimate_ppf_webhook_2026")
WA_APP_SECRET   = os.getenv("WA_APP_SECRET", "")

def init_ctwa_db():
    """Inicializa o banco SQLite para ctwa_clicks."""
    conn = sqlite3.connect(CTWA_DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ctwa_clicks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            phone        TEXT NOT NULL,
            ctwa_clid    TEXT,
            mensagem_codigo TEXT,
            ad_id        TEXT,
            source_type  TEXT,
            headline     TEXT,
            received_at  TEXT NOT NULL,
            raw_referral TEXT,
            UNIQUE(phone, ctwa_clid)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_phone ON ctwa_clicks(phone)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctwa  ON ctwa_clicks(ctwa_clid)")
    conn.commit()
    return conn

def extrair_codigo_mensagem(texto):
    """Extrai código de rastreamento de mensagens pré-preenchidas (ex: WZAP-PPF-MAI26-A)."""
    import re
    padrao = r'\b([A-Z]{2,}-[A-Z0-9]{2,}(?:-[A-Z0-9]+)*)\b'
    match  = re.search(padrao, (texto or "").upper())
    return match.group(1) if match else ""

def salvar_ctwa_click(phone, referral, mensagem_texto=""):
    """Salva ctwa_clid ou código de mensagem no banco."""
    ctwa_clid   = (referral or {}).get("ctwa_clid", "")
    ad_id       = (referral or {}).get("source_id", "")
    source_type = (referral or {}).get("source_type", "")
    headline    = (referral or {}).get("headline", "")
    codigo      = extrair_codigo_mensagem(mensagem_texto)

    if not ctwa_clid and not codigo:
        return False

    ctwa_key = ctwa_clid or f"MSG:{codigo}:{phone[-4:]}"
    now      = datetime.utcnow().isoformat()

    try:
        conn = sqlite3.connect(CTWA_DB_PATH, timeout=5)
        conn.execute("""
            INSERT OR IGNORE INTO ctwa_clicks
                (phone, ctwa_clid, mensagem_codigo, ad_id, source_type, headline,
                 received_at, raw_referral)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (phone, ctwa_key, codigo, ad_id, source_type, headline,
              now, json.dumps(referral) if referral else "{}"))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        app.logger.error(f"[CTWA DB] Erro ao salvar: {e}")
        return False

def processar_wa_payload(payload):
    """Processa payload do WhatsApp Business API e salva ctwa_clids."""
    salvos = 0
    if payload.get("object") != "whatsapp_business_account":
        return 0
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            if change.get("field") != "messages":
                continue
            value = change.get("value", {})
            for msg in value.get("messages", []):
                phone = msg.get("from", "")
                if not phone:
                    contacts = value.get("contacts", [])
                    phone    = contacts[0].get("wa_id", "") if contacts else ""
                if not phone:
                    continue
                referral   = msg.get("referral")
                texto      = msg.get("text", {}).get("body", "") if msg.get("type") == "text" else ""
                tem_ctwa   = referral and referral.get("ctwa_clid")
                tem_codigo = extrair_codigo_mensagem(texto)
                if not tem_ctwa and not tem_codigo:
                    continue
                if salvar_ctwa_click(phone, referral or {}, texto):
                    salvos += 1
                    app.logger.info(
                        f"[CTWA] NOVO: phone={phone} | ctwa={(referral or {}).get('ctwa_clid','—')[:20]} | codigo={tem_codigo or '—'}"
                    )
    return salvos

@app.route("/webhook/whatsapp", methods=["GET"])
def wa_verify():
    """Handshake de verificação do webhook com o Meta."""
    mode      = request.args.get("hub.mode")
    token     = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == WA_VERIFY_TOKEN:
        app.logger.info("[WA] Webhook verificado com sucesso")
        return challenge, 200
    app.logger.warning(f"[WA] Verificação falhou — token recebido: {token}")
    return "Forbidden", 403

@app.route("/webhook/whatsapp", methods=["POST"])
def wa_receive():
    """Recebe notificações do WhatsApp Business API."""
    corpo = request.get_data()
    if WA_APP_SECRET:
        sig      = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            WA_APP_SECRET.encode(), corpo, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return jsonify({"error": "invalid signature"}), 401
    try:
        payload = json.loads(corpo)
    except json.JSONDecodeError:
        return jsonify({"error": "invalid json"}), 400
    salvos = processar_wa_payload(payload)
    return jsonify({"status": "ok", "ctwa_clids_salvos": salvos}), 200

@app.route("/ctwa/lookup/<phone>", methods=["GET"])
def ctwa_lookup(phone):
    """Consulta ctwa_clid de um telefone (debug)."""
    resultado = lookup_ctwa_clid(phone)
    if resultado:
        return jsonify({"phone": phone, "ctwa_clid": resultado}), 200
    return jsonify({"phone": phone, "ctwa_clid": None}), 404

@app.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    """
    Recebe o authorization code do OAuth Nuvemshop e:
    1. Troca pelo access_token
    2. Registra os webhooks order/created e order/paid
    """
    code = request.args.get("code")
    if not code:
        return "<h2>❌ Código OAuth não encontrado na URL.</h2>", 400

    if not NUVEMSHOP_CLIENT_ID or not NUVEMSHOP_CLIENT_SECRET:
        return "<h2>❌ NUVEMSHOP_CLIENT_ID ou NUVEMSHOP_CLIENT_SECRET não configurados.</h2>", 500

    # 1. Trocar code por access_token
    try:
        token_resp = requests.post(
            "https://www.nuvemshop.com.br/apps/authorize/token",
            json={
                "client_id":     NUVEMSHOP_CLIENT_ID,
                "client_secret": NUVEMSHOP_CLIENT_SECRET,
                "grant_type":    "authorization_code",
                "code":          code,
            },
            timeout=15
        )
        token_data = token_resp.json()
    except Exception as e:
        return f"<h2>❌ Erro ao trocar token: {e}</h2>", 500

    if not token_resp.ok or "access_token" not in token_data:
        return f"<h2>❌ Falha ao obter token: {token_data}</h2>", 500

    access_token = token_data["access_token"]
    user_id      = token_data.get("user_id", "?")

    # 2. Registrar webhooks
    webhook_url = f"{WEBHOOK_BASE_URL}/webhook/nuvemshop"
    events      = ["order/created", "order/paid"]
    results     = []

    for event in events:
        try:
            r     = requests.post(
                f"https://api.tiendanube.com/v1/{user_id}/webhooks",
                headers={
                    "Authentication": f"bearer {access_token}",
                    "Content-Type":   "application/json",
                    "User-Agent":     "UltimatePPF-CAPI/1.0",
                },
                json={"url": webhook_url, "event": event},
                timeout=15
            )
            rdata = r.json() if r.content else {}
            if r.ok:
                results.append(f"✅ <b>{event}</b> — ID {rdata.get('id','?')}")
            elif r.status_code == 422 and "taken" in r.text:
                results.append(f"✓ <b>{event}</b> — já registrado")
            else:
                results.append(f"⚠️ <b>{event}</b> — status {r.status_code}: {r.text[:100]}")
        except Exception as e:
            results.append(f"❌ <b>{event}</b> — erro: {e}")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Webhook Registrado</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px;background:#0f1117;color:#e2e8f0}}
h2{{color:#34d399}}ul{{line-height:2}}code{{background:#1f2937;padding:2px 6px;border-radius:4px;color:#60a5fa}}</style>
</head><body>
<h2>🎉 OAuth concluído com sucesso!</h2>
<p>Store ID: <code>{user_id}</code></p>
<p>Access Token: <code>{access_token[:12]}...{access_token[-4:]}</code></p>
<h3>Webhooks registrados:</h3>
<ul>{''.join(f'<li>{r}</li>' for r in results)}</ul>
<p>Endpoint: <code>{webhook_url}</code></p>
<p style="color:#6b7280;margin-top:30px">Pode fechar esta aba.</p>
</body></html>"""
    return html, 200

@app.route("/admin/register-webhooks", methods=["GET"])
def admin_register_webhooks():
    """
    Registra os webhooks order/created e order/paid na Nuvemshop
    usando o NUVEMSHOP_TOKEN e NUVEMSHOP_USER_ID já configurados em env.
    """
    token   = NUVEMSHOP_TOKEN
    user_id = NUVEMSHOP_USER_ID

    if not token:
        return jsonify({"error": "NUVEMSHOP_TOKEN não configurado"}), 500
    if not user_id:
        return jsonify({"error": "NUVEMSHOP_USER_ID não configurado"}), 500

    webhook_url = f"{WEBHOOK_BASE_URL}/webhook/nuvemshop"
    events      = ["order/created", "order/paid"]
    results     = []

    for event in events:
        try:
            r     = requests.post(
                f"https://api.tiendanube.com/v1/{user_id}/webhooks",
                headers={
                    "Authentication": f"bearer {token}",
                    "Content-Type":   "application/json",
                    "User-Agent":     "UltimatePPF-CAPI/1.0",
                },
                json={"url": webhook_url, "event": event},
                timeout=15
            )
            rdata = r.json() if r.content else {}
            if r.ok:
                results.append({"event": event, "status": "created",           "id":   rdata.get("id")})
            elif r.status_code == 422 and "taken" in r.text:
                results.append({"event": event, "status": "already_registered"})
            else:
                results.append({"event": event, "status": "error", "code": r.status_code, "body": r.text[:200]})
        except Exception as e:
            results.append({"event": event, "status": "exception", "error": str(e)})

    # Listar webhooks existentes
    try:
        lr       = requests.get(
            f"https://api.tiendanube.com/v1/{user_id}/webhooks",
            headers={"Authentication": f"bearer {token}", "User-Agent": "UltimatePPF-CAPI/1.0"},
            timeout=15
        )
        existing = lr.json() if lr.ok else {"error": lr.status_code}
    except Exception as e:
        existing = {"error": str(e)}

    return jsonify({
        "store_id":             user_id,
        "token_preview":        f"{token[:8]}...{token[-4:]}",
        "webhook_url":          webhook_url,
        "registration_results": results,
        "existing_webhooks":    existing
    }), 200

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

init_db()
init_ctwa_db()
app.logger.setLevel("INFO")
if __name__ == "__main__":
    init_db()
    init_ctwa_db()
    app.logger.setLevel("INFO")
    print(f"""
╔═════════════════════════════════════════════════════════════╗
║     Nuvemshop → Meta CAPI — WhatsApp Attribution            ║
╠══════════════════════════════════════════════════════════════╣
║ Pixel ID  : {PIXEL_ID:<48}║
║ Porta     : {PORT:<48}║
║ DB        : {DB_PATH:<48}║
║ Test Mode : {str(TEST_MODE):<48}║
╠══════════════════════════════════════════════════════════════╣
║ Canais mapeados:                                             ║
║  • numero_0324 → 9692-0324 (Nuvem Chat / IA)                ║
║  • numero_6052 → 9646-6052 (Vendas Manual)                  ║
║  • numero_6900 → 9674-6900 (Vendas Manual)                  ║
╠══════════════════════════════════════════════════════════════╣
║ Endpoints:                                                   ║
║  POST /webhook/nuvemshop       ← recebe eventos             ║
║  GET  /webhook/nuvemshop/test  ← verifica configuração      ║
║  GET  /webhook/nuvemshop/events ← lista últimos 50 eventos  ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=PORT, debug=False)
