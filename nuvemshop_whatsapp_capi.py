#!/usr/bin/env python3
"""
nuvemshop_whatsapp_capi.py
==========================
Webhook server que recebe eventos de pedido da Nuvemshop (order/created, order/paid),
detecta pedidos originados via WhatsApp (utm_source=whatsapp) e dispara um evento
Purchase no Meta Conversions API com atribuição correta ao número de WhatsApp.

NÚMEROS MAPEADOS:
  - utm_content=numero_0324  →  +55 67 9692-0324  (Nuvem Chat / IA)
  - utm_content=numero_6052  →  +55 67 9646-6052  (vendas manual)
  - utm_content=numero_6900  →  +55 67 9674-6900  (vendas manual)

DEPENDÊNCIAS:
  pip install flask requests

USO:
  python nuvemshop_whatsapp_capi.py

  Variáveis de ambiente (obrigatórias):
    META_PIXEL_ID        → ID do Pixel Meta (ex: 123456789)
    META_ACCESS_TOKEN    → Token de acesso do Conversions API
    NUVEMSHOP_SECRET     → Secret do webhook da Nuvemshop (para validação HMAC)
    PORT                 → Porta do servidor (padrão: 5001)
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
# NOTA: se o WhatsApp armazenar no formato 9 dígitos (com 9 adicional), use:
#   0324 → 5567996920324   6052 → 5567996466052   6900 → 5567996746900
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
      - order["landing_url"] — URL de origem
      - order["utm_parameters"] — objeto UTM (nem sempre presente)
      - order["referring_url"]
    """
    utm = {
        "utm_source": "",
        "utm_medium": "",
        "utm_campaign": "",
        "utm_content": "",
        "utm_term": "",
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
    # Prefixo "wzap_" diferencia do event_id do CAPI nativo da Nuvemshop
    # (que provavelmente usa apenas o order_id ou "order_<id>").
    # O Meta só desduplicará eventos com event_id IDÊNTICO — prefixos diferentes
    # garantem que ambos os eventos cheguem ao Meta e sejam complementares.
    event_id = f"wzap_ctwa_{order_id}"

    # Valor e moeda
    total = float(order.get("total") or order.get("total_price") or 0)
    currency = str(order.get("currency") or "BRL").upper()

    # PII do cliente
    customer = order.get("customer") or {}
    billing = order.get("billing_address") or customer.get("default_address") or {}

    email_raw = (customer.get("email") or billing.get("email") or "").strip().lower()

    # Telefone do cliente (separado para uso no lookup ctwa_clid)
    customer_phone_raw = format_phone(customer.get("phone") or billing.get("phone") or "")
    # Para o campo ph: usar telefone do cliente ou, como fallback, o número do canal
    phone_raw = customer_phone_raw or format_phone(phone_number)

    first_name = (billing.get("first_name") or customer.get("name") or "").split()[0].lower()
    last_name_parts = (billing.get("last_name") or customer.get("name") or "").split()
    last_name = last_name_parts[-1].lower() if last_name_parts else ""
    city = (billing.get("city") or "").lower()
    state = (billing.get("province_code") or billing.get("state") or "").lower()
    zip_code = "".join(filter(str.isdigit, billing.get("zipcode") or billing.get("zip") or ""))
    country = (billing.get("country") or "BR").upper()

    # Timestamp do pedido
    created_at = order.get("created_at") or ""
    try:
        from dateutil import parser as dparser
        event_time = int(dparser.parse(created_at).timestamp())
    except Exception:
        event_time = int(time.time())

    # ── CTWA Attribution: buscar ctwa_clid do cliente ──────────────────────────
    # O ctwa_clid é capturado pelo whatsapp_ctwa_receiver.py quando o cliente
    # clica num anúncio CTWA e envia a primeira mensagem no WhatsApp.
    # Enviado como fbc, ele atribui a venda ao anúncio correto no Gerenciador.
    ctwa_clid = lookup_ctwa_clid(customer_phone_raw)
    fbc_value = f"fb.1.{int(time.time() * 1000)}.{ctwa_clid}" if ctwa_clid else ""
    # ───────────────────────────────────────────────────────────────────────────

    # user_data
    user_data = {
        "external_id": [sha256(str(order.get("customer_id") or email_raw or order_id))],
        "client_ip_address": order.get("client_ip") or "",
        "client_user_agent": "",
    }
    if fbc_value:
        user_data["fbc"] = fbc_value  # ← atribuição CTWA — campo crítico para ROAS
    if email_raw:
        user_data["em"] = [sha256(email_raw)]
    if phone_raw:
        user_data["ph"] = [sha256(phone_raw)]
    if first_name:
        user_data["fn"] = [sha256(first_name)]
    if last_name:
        user_data["ln"] = [sha256(last_name)]
    if city:
        user_data["ct"] = [sha256(city)]
    if state:
        user_data["st"] = [sha256(state)]
    if zip_code:
        user_data["zp"] = [sha256(zip_code)]
    if country:
        user_data["country"] = [sha256(country)]

    # custom_data
    contents = []
    for item in (order.get("products") or order.get("line_items") or []):
        contents.append({
            "id": str(item.get("product_id") or item.get("id") or ""),
            "quantity": int(item.get("quantity") or 1),
            "item_price": float(item.get("price") or 0),
        })

    custom_data = {
        "value": total,
        "currency": currency,
        "order_id": order_id,
        "content_type": "product",
    }
    if contents:
        custom_data["contents"] = contents

    # Informações do canal WhatsApp
    custom_data["whatsapp_channel"] = UTM_CONTENT_TO_CHANNEL.get(utm["utm_content"], utm["utm_content"])
    custom_data["utm_medium"] = utm["utm_medium"]
    custom_data["utm_campaign"] = utm["utm_campaign"]

    event = {
        "event_name": "Purchase",
        "event_time": event_time,
        "event_id": event_id,
        "event_source_url": order.get("landing_url") or f"https://loja.ultimateppf.com.br/",
        "action_source": "other",  # "other" para WhatsApp
        "user_data": user_data,
        "custom_data": custom_data,
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

    resp = requests.post(CAPI_URL, params=params, json=payload, timeout=10)
    result = resp.json()
    result["event_id"] = event_id
    result["http_status"] = resp.status_code
    result["_ctwa_clid"] = ctwa_clid  # para log interno (não vai para a API)
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
        request.headers.get("X-Nuvemshop-Token") or
        request.headers.get("X-HMAC-SHA256") or ""
    )
    if not validate_nuvemshop_signature(payload_bytes, sig_header):
        app.logger.warning("Assinatura HMAC inválida — rejeitando webhook")
        return jsonify({"error": "invalid_signature"}), 401

    try:
        data = request.get_json(force=True) or {}
    except Exception as e:
        return jsonify({"error": f"JSON inválido: {e}"}), 400

    # Nuvemshop envia { "topic": "orders/created", "store_id": ..., ... }
    topic = data.get("topic") or data.get("event") or ""
    order = data.get("order") or data  # às vezes o payload é o pedido direto

    order_id = str(order.get("id") or order.get("number") or "")

    # Só processar pedidos criados ou pagos
    if topic and "order" not in topic.lower():
        return jsonify({"status": "ignored", "reason": f"topic={topic}"}), 200

    # Extrair UTMs
    utm = extract_utm(order)

    app.logger.info(
        f"Pedido #{order_id} | topic={topic} | utm_source={utm['utm_source']} | utm_content={utm['utm_content']}"
    )

    # Verificar se veio do WhatsApp
    if utm["utm_source"].lower() != "whatsapp":
        return jsonify({
            "status": "ignored",
            "reason": "utm_source != whatsapp",
            "utm_source": utm["utm_source"],
            "order_id": order_id,
        }), 200

    # Identificar número pelo utm_content
    phone_number = UTM_CONTENT_TO_PHONE.get(utm["utm_content"])
    channel_name = UTM_CONTENT_TO_CHANNEL.get(utm["utm_content"], "WhatsApp Desconhecido")

    if not phone_number:
        app.logger.warning(
            f"utm_content não reconhecido: '{utm['utm_content']}' — pedido #{order_id}"
        )
        return jsonify({
            "status": "ignored",
            "reason": f"utm_content não mapeado: {utm['utm_content']}",
            "order_id": order_id,
        }), 200

    # Deduplicação (mesmo prefixo usado em send_capi_purchase)
    event_id = f"wzap_ctwa_{order_id}"
    if is_duplicate(event_id):
        app.logger.info(f"Pedido #{order_id} já processado (event_id={event_id}) — ignorando")
        return jsonify({"status": "duplicate", "event_id": event_id}), 200

    # ── GUARDA ANTI-DUPLICAÇÃO: só disparar CAPI se houver ctwa_clid ──────────
    # A Nuvemshop já possui CAPI nativo (via integração Facebook/Instagram
    # Shopping) que cobre TODOS os pedidos com action_source "website".
    # Disparar nosso CAPI sem ctwa_clid = evento duplicado sem valor adicional.
    # Com ctwa_clid: carregamos o fbc que atribui a venda ao anúncio CTWA exato
    # — informação que o CAPI da Nuvemshop NÃO tem. Isso justifica o segundo evento.
    customer_data = order.get("customer") or {}
    billing_data = order.get("billing_address") or customer_data.get("default_address") or {}
    pre_check_phone = format_phone(
        customer_data.get("phone") or billing_data.get("phone") or ""
    )
    pre_check_ctwa = lookup_ctwa_clid(pre_check_phone)

    if not pre_check_ctwa:
        app.logger.info(
            f"Pedido #{order_id} sem ctwa_clid — CAPI da Nuvemshop já cobre, ignorando"
        )
        return jsonify({
            "status": "skipped",
            "reason": "no_ctwa_clid — nuvemshop_capi_handles_it",
            "order_id": order_id,
            "channel": channel_name,
        }), 200
    # ─────────────────────────────────────────────────────────────────────────

    # Disparar evento CAPI
    try:
        capi_result = send_capi_purchase(order, utm, phone_number)
    except Exception as e:
        app.logger.error(f"Erro ao enviar CAPI: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

    # Salvar no banco
    value = float(order.get("total") or order.get("total_price") or 0)
    currency = str(order.get("currency") or "BRL").upper()
    save_event(order_id, event_id, utm["utm_content"], channel_name, value, currency, capi_result)

    app.logger.info(
        f"✅ CAPI enviado | pedido #{order_id} | canal={channel_name} | "
        f"valor={currency} {value:.2f} | event_id={event_id} | "
        f"ctwa={'✅ ' + capi_result.get('_ctwa_clid', '')[:16] + '...' if capi_result.get('_ctwa_clid') else '⚠️ sem ctwa_clid'}"
    )

    return jsonify({
        "status": "ok",
        "order_id": order_id,
        "event_id": event_id,
        "channel": channel_name,
        "value": value,
        "currency": currency,
        "capi": capi_result,
    }), 200


@app.route("/webhook/nuvemshop/test", methods=["GET"])
def test_endpoint():
    """Endpoint de teste — verifica configuração sem precisar de webhook real."""
    return jsonify({
        "status": "online",
        "pixel_id": PIXEL_ID,
        "test_mode": TEST_MODE,
        "db_path": DB_PATH,
        "channels": UTM_CONTENT_TO_CHANNEL,
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
# MAIN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.logger.setLevel("INFO")
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       Nuvemshop → Meta CAPI — WhatsApp Attribution          ║
╠══════════════════════════════════════════════════════════════╣
║  Pixel ID  : {PIXEL_ID:<48}║
║  Porta     : {PORT:<48}║
║  DB        : {DB_PATH:<48}║
║  Test Mode : {str(TEST_MODE):<48}║
╠══════════════════════════════════════════════════════════════╣
║  Canais mapeados:                                            ║
║  • numero_0324 → 9692-0324 (Nuvem Chat / IA)                ║
║  • numero_6052 → 9646-6052 (Vendas Manual)                  ║
║  • numero_6900 → 9674-6900 (Vendas Manual)                  ║
╠══════════════════════════════════════════════════════════════╣
║  Endpoints:                                                  ║
║  POST /webhook/nuvemshop        ← recebe eventos            ║
║  GET  /webhook/nuvemshop/test   ← verifica configuração     ║
║  GET  /webhook/nuvemshop/events ← lista últimos 50 eventos  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=PORT, debug=False)
