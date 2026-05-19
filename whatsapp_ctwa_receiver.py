#!/usr/bin/env python3
"""
whatsapp_ctwa_receiver.py
==========================
Servidor webhook que recebe notificações do WhatsApp Business Cloud API,
extrai o ctwa_clid (Click-to-WhatsApp Click ID) de mensagens originadas
em anúncios WZAP e armazena a relação phone → ctwa_clid em SQLite.

Por que isso importa:
  Cada clique num anúncio WZAP gera um ctwa_clid único. Quando enviado ao
  Meta CAPI como campo `fbc`, ele fecha o loop de atribuição: o Meta consegue
  ligar a venda ao anúncio exato que gerou o lead — mesmo sem pixel no site.

Como usar:
  1. Instale dependências:
       pip install flask

  2. Configure variáveis de ambiente:
       export WA_VERIFY_TOKEN="seu_token_de_verificacao"   # escolha qualquer string secreta
       export WA_APP_SECRET="seu_app_secret"               # opcional, para validar assinatura

  3. Execute:
       python3 whatsapp_ctwa_receiver.py

  4. Configure o webhook no Meta for Developers apontando para:
       https://seu-servidor.com/webhook/whatsapp
     com o mesmo WA_VERIFY_TOKEN.

  5. Para consultar o ctwa_clid de um telefone:
       python3 whatsapp_ctwa_receiver.py --lookup 5567999999999

  6. Para listar todos os registros:
       python3 whatsapp_ctwa_receiver.py --list

Estrutura do banco SQLite (ctwa_store.db):
  Tabela: ctwa_clicks
    - phone          TEXT  — número do remetente (formato: 5567999999999)
    - ctwa_clid      TEXT  — ID único do clique no anúncio WZAP
    - ad_id          TEXT  — ID do anúncio (se disponível)
    - source_type    TEXT  — "ad", "post", etc.
    - received_at    TEXT  — timestamp ISO 8601
    - raw_referral   TEXT  — JSON completo do objeto referral (para auditoria)
"""

import os
import json
import sqlite3
import hashlib
import hmac
import argparse
from datetime import datetime, timezone

# ─── CONFIGURAÇÕES ────────────────────────────────────────────────────────────
DB_PATH        = os.environ.get("CTWA_DB_PATH",       "ctwa_store.db")
VERIFY_TOKEN   = os.environ.get("WA_VERIFY_TOKEN",    "ultimate_ppf_webhook_2026")
APP_SECRET     = os.environ.get("WA_APP_SECRET",      "")  # opcional
PORT           = int(os.environ.get("PORT",            5050))
HOST           = os.environ.get("HOST",                "0.0.0.0")
# ──────────────────────────────────────────────────────────────────────────────


# ─── BANCO DE DADOS ───────────────────────────────────────────────────────────

def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Inicializa o banco SQLite e cria tabelas se necessário."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ctwa_clicks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            phone           TEXT NOT NULL,
            ctwa_clid       TEXT,
            mensagem_codigo TEXT,
            ad_id           TEXT,
            source_type     TEXT,
            headline        TEXT,
            received_at     TEXT NOT NULL,
            raw_referral    TEXT,
            UNIQUE(phone, ctwa_clid)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_phone ON ctwa_clicks(phone)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ctwa_clid ON ctwa_clicks(ctwa_clid)
    """)
    conn.commit()
    return conn


def extrair_codigo_mensagem(texto: str) -> str:
    """
    Tenta extrair um código de rastreamento da mensagem pré-preenchida.
    Suporta os formatos do sistema UltimatePPF:
        WZAP-PPFFULL-MAI26-A
        [WZAP-PPF-MAI26-B]
        Código: WZAP-INTERIOR-MAI26
    """
    import re
    # Padrão: palavras maiúsculas separadas por hifens (ex: WZAP-PPF-MAI26-A)
    padrao = r'\b([A-Z]{2,}-[A-Z0-9]{2,}(?:-[A-Z0-9]+)*)\b'
    match = re.search(padrao, texto.upper())
    return match.group(1) if match else ""


def salvar_ctwa(conn: sqlite3.Connection, phone: str, referral: dict,
                mensagem_texto: str = "") -> bool:
    """
    Salva um registro no banco.
    Captura ctwa_clid (quando disponível) e/ou o código da mensagem pré-preenchida.
    Retorna True se inserido.
    """
    ctwa_clid   = referral.get("ctwa_clid", "") if referral else ""
    ad_id       = referral.get("source_id", "") if referral else ""
    source_type = referral.get("source_type", "") if referral else ""
    headline    = referral.get("headline", "") if referral else ""

    # Extrair código do texto da mensagem (se mensagem pré-preenchida com código)
    codigo = extrair_codigo_mensagem(mensagem_texto) if mensagem_texto else ""

    # Precisa ter pelo menos um identificador
    if not ctwa_clid and not codigo:
        return False

    # Para UNIQUE constraint: se não tem ctwa_clid, usar phone+codigo como chave
    ctwa_key = ctwa_clid or f"MSG:{codigo}:{phone[-4:]}"

    now = datetime.now(timezone.utc).isoformat()

    try:
        conn.execute("""
            INSERT OR IGNORE INTO ctwa_clicks
                (phone, ctwa_clid, mensagem_codigo, ad_id, source_type, headline,
                 received_at, raw_referral)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (phone, ctwa_key, codigo, ad_id, source_type, headline,
              now, json.dumps(referral) if referral else "{}"))
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Erro ao salvar: {e}")
        return False


def buscar_ctwa(conn: sqlite3.Connection, phone: str) -> dict:
    """
    Retorna o ctwa_clid e/ou código de mensagem mais recente para o telefone.
    phone deve estar no formato internacional: 5567999999999
    Retorna dict vazio se não encontrado.
    """
    row = conn.execute("""
        SELECT ctwa_clid, mensagem_codigo, ad_id, source_type, headline, received_at
        FROM ctwa_clicks
        WHERE phone = ?
        ORDER BY received_at DESC
        LIMIT 1
    """, (phone,)).fetchone()

    if not row:
        return {}

    resultado = dict(row)

    # ctwa_clid real: não começa com "MSG:"
    if resultado.get("ctwa_clid", "").startswith("MSG:"):
        resultado["ctwa_clid"] = None  # não era ctwa_clid real, era apenas chave interna

    return resultado


def listar_todos(conn: sqlite3.Connection) -> list:
    """Retorna todos os registros ordenados por data decrescente."""
    rows = conn.execute("""
        SELECT phone, ctwa_clid, ad_id, source_type, headline, received_at
        FROM ctwa_clicks
        ORDER BY received_at DESC
    """).fetchall()
    return [dict(r) for r in rows]


# ─── PROCESSAMENTO DE WEBHOOK ─────────────────────────────────────────────────

def processar_payload(payload: dict, conn: sqlite3.Connection) -> int:
    """
    Processa um payload recebido do WhatsApp Business API.
    Extrai referral.ctwa_clid de cada mensagem e salva no banco.
    Retorna o número de ctwa_clids salvos.

    Estrutura esperada do payload:
    {
      "object": "whatsapp_business_account",
      "entry": [{
        "changes": [{
          "value": {
            "contacts": [{"wa_id": "PHONE"}],
            "messages": [{
              "from": "PHONE",
              "referral": {
                "ctwa_clid": "AQLo...",
                "source_id": "AD_ID",
                "source_type": "ad",
                "headline": "Texto do anúncio"
              }
            }]
          }
        }]
      }]
    }
    """
    salvos = 0

    if payload.get("object") != "whatsapp_business_account":
        return 0

    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})

            if change.get("field") != "messages":
                continue

            messages = value.get("messages", [])

            for msg in messages:
                referral = msg.get("referral")  # pode ser None (mensagem comum)

                # Telefone: preferir "from" do próprio msg, fallback para contacts
                phone = msg.get("from", "")
                if not phone:
                    contacts = value.get("contacts", [])
                    if contacts:
                        phone = contacts[0].get("wa_id", "")

                if not phone:
                    continue

                # Texto da mensagem (para capturar código pré-preenchido)
                texto = msg.get("text", {}).get("body", "") if msg.get("type") == "text" else ""

                # Só processa se veio de anúncio (tem referral) OU tem código na msg
                tem_ctwa  = referral and referral.get("ctwa_clid")
                tem_codigo = extrair_codigo_mensagem(texto) if texto else ""

                if not tem_ctwa and not tem_codigo:
                    continue  # mensagem comum sem código — ignorar

                inserido = salvar_ctwa(conn, phone, referral or {}, texto)
                if inserido:
                    ctwa_id = (referral or {}).get("ctwa_clid", "")
                    print(f"[CTWA] NOVO: phone={phone} | "
                          f"ctwa={ctwa_id[:16] + '...' if ctwa_id else '—'} | "
                          f"codigo={tem_codigo or '—'} | "
                          f"ad={( referral or {}).get('source_id', '—')}")
                    salvos += 1
                else:
                    print(f"[CTWA] duplicado: phone={phone}")

    return salvos


def validar_assinatura(corpo: bytes, assinatura_header: str, secret: str) -> bool:
    """
    Valida a assinatura X-Hub-Signature-256 enviada pelo Meta.
    Retorna True se válida ou se APP_SECRET não estiver configurado.
    """
    if not secret:
        return True  # sem secret configurado, aceita tudo

    if not assinatura_header or not assinatura_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        corpo,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, assinatura_header)


# ─── SERVIDOR FLASK ───────────────────────────────────────────────────────────

def criar_app(conn: sqlite3.Connection):
    """Cria e configura a aplicação Flask."""
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        print("ERRO: Flask não instalado. Execute: pip install flask")
        raise

    app = Flask(__name__)

    @app.route("/webhook/whatsapp", methods=["GET"])
    def verificar_webhook():
        """
        Endpoint de verificação do webhook (handshake inicial com o Meta).
        O Meta envia um GET com hub.challenge — devemos retornar o challenge
        se o hub.verify_token bater com o nosso.
        """
        mode      = request.args.get("hub.mode")
        token     = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            print(f"[WEBHOOK] Verificação bem-sucedida")
            return challenge, 200

        print(f"[WEBHOOK] Verificação falhou — token recebido: {token}")
        return "Forbidden", 403

    @app.route("/webhook/whatsapp", methods=["POST"])
    def receber_mensagem():
        """
        Endpoint principal — recebe notificações do WhatsApp Business API.
        """
        corpo = request.get_data()

        # Validar assinatura (opcional mas recomendado)
        if APP_SECRET:
            sig = request.headers.get("X-Hub-Signature-256", "")
            if not validar_assinatura(corpo, sig, APP_SECRET):
                print("[WEBHOOK] Assinatura inválida — rejeitando")
                return jsonify({"error": "invalid signature"}), 401

        try:
            payload = json.loads(corpo)
        except json.JSONDecodeError:
            return jsonify({"error": "invalid json"}), 400

        salvos = processar_payload(payload, conn)

        return jsonify({
            "status": "ok",
            "ctwa_clids_salvos": salvos
        }), 200

    @app.route("/ctwa/lookup/<phone>", methods=["GET"])
    def lookup_phone(phone: str):
        """
        Consulta o ctwa_clid de um telefone (para debug/teste).
        GET /ctwa/lookup/5567999999999
        """
        resultado = buscar_ctwa(conn, phone)
        if resultado:
            return jsonify({"phone": phone, **resultado}), 200
        return jsonify({"phone": phone, "ctwa_clid": None}), 404

    @app.route("/ctwa/list", methods=["GET"])
    def listar():
        """Lista todos os registros (para debug). Proteger em produção."""
        return jsonify(listar_todos(conn)), 200

    @app.route("/health", methods=["GET"])
    def health():
        count = conn.execute("SELECT COUNT(*) FROM ctwa_clicks").fetchone()[0]
        return jsonify({"status": "ok", "total_registros": count}), 200

    # ─── HANDLER NUVEMSHOP (pedido pago → Meta CAPI automático) ──────────────
    # ⚠️  ATENÇÃO: use APENAS se você NÃO estiver rodando nuvemshop_whatsapp_capi.py.
    #     Se ambos estiverem rodando, configure a Nuvemshop para enviar SOMENTE
    #     para nuvemshop_whatsapp_capi.py (porta 5001, /webhook/nuvemshop).
    #     Enviar para os dois causará duplicação de eventos Purchase no Meta CAPI.
    #
    # Configure em: Nuvemshop Admin → Configurações → API → Webhooks
    # Evento: order/paid  |  URL: https://seu-servidor.com/nuvemshop/order-paid

    @app.route("/nuvemshop/order-paid", methods=["POST"])
    def nuvemshop_order_paid():
        """
        Recebe webhook da Nuvemshop quando um pedido é pago e
        envia um evento Purchase ao Meta CAPI APENAS se a venda
        veio de um anúncio WZAP (cliente tem ctwa_clid no banco).

        SEGURANÇA CONTRA DUPLICATAS:
        - O pixel da Nuvemshop JÁ dispara Purchase (action_source: website)
          para todo pedido pago no site.
        - Este handler usa action_source: "other" (venda via WhatsApp),
          que o Meta trata como canal diferente — sem duplicar contagens.
        - Além disso, só dispara se o telefone tiver ctwa_clid registrado,
          garantindo que só leads WZAP recebam este evento adicional.
        - O pixel Nuvemshop continua intacto e rastreando normalmente.

        Para ativar, defina as variáveis:
            META_PIXEL_ID, META_ACCESS_TOKEN
        """
        import hashlib, time as _time, urllib.request, urllib.error

        pixel_id     = os.environ.get("META_PIXEL_ID", "")
        access_token = os.environ.get("META_ACCESS_TOKEN", "")

        if not pixel_id or not access_token:
            print("[NUVEMSHOP] META_PIXEL_ID ou META_ACCESS_TOKEN não configurados")
            return jsonify({"error": "CAPI não configurado no servidor"}), 500

        try:
            pedido = json.loads(request.get_data())
        except json.JSONDecodeError:
            return jsonify({"error": "invalid json"}), 400

        # Extrair dados do pedido Nuvemshop
        # Ref: https://tiendanube.github.io/api-documentation/resources/order
        pedido_id  = str(pedido.get("id", ""))
        total      = float(pedido.get("total", 0))
        moeda      = pedido.get("currency", "BRL")

        cliente    = pedido.get("customer", {}) or {}
        telefone   = (cliente.get("phone") or "").replace(r"\D", "")
        email      = (cliente.get("email") or "").strip().lower()
        nome       = cliente.get("name", "")

        # Normalizar telefone
        import re
        telefone = re.sub(r'\D', '', telefone)
        if telefone and len(telefone) in (10, 11):
            telefone = '55' + telefone

        if not telefone and not email:
            print(f"[NUVEMSHOP] Pedido {pedido_id} sem telefone/email — ignorando")
            return jsonify({"status": "skipped", "reason": "no contact info"}), 200

        # Buscar ctwa_clid do banco (só existe se lead veio de anúncio WZAP)
        ctwa_info = buscar_ctwa(conn, telefone) if telefone else {}
        ctwa_clid = ctwa_info.get("ctwa_clid") if ctwa_info else None
        fbc = f"fb.1.{int(_time.time() * 1000)}.{ctwa_clid}" if ctwa_clid else None

        # ─── PROTEÇÃO CONTRA DUPLICATAS ──────────────────────────────
        # Se NÃO temos ctwa_clid, o pixel Nuvemshop já cuidou deste pedido.
        # Não disparar CAPI para evitar duplicar compras nos relatórios Meta.
        if not ctwa_clid:
            print(f"[NUVEMSHOP] Pedido {pedido_id} sem ctwa_clid — pixel Nuvemshop cuida, ignorando")
            return jsonify({"status": "skipped", "reason": "no wzap origin, pixel handles it"}), 200
        # ─────────────────────────────────────────────────────────────

        # Hashs
        ph_hash = hashlib.sha256(telefone.encode()).hexdigest() if telefone else None
        em_hash = hashlib.sha256(email.encode()).hexdigest() if email else None

        # user_data
        user_data = {}
        if ph_hash: user_data["ph"] = [ph_hash]
        if em_hash: user_data["em"] = [em_hash]
        if fbc:     user_data["fbc"] = fbc  # ctwa_clid como fbc — atribuição WZAP

        # event_id deterministico
        eid_raw = f"nuvemshop|{pedido_id}|{total:.2f}"
        event_id = "nuvem_" + hashlib.sha256(eid_raw.encode()).hexdigest()[:16]

        evento = {
            "event_name": "Purchase",
            "event_time": int(_time.time()),
            "event_id": event_id,
            # action_source "other" = venda via WhatsApp (≠ "website" do pixel Nuvemshop)
            # O Meta trata como canal diferente — NÃO duplica com o pixel do site.
            "action_source": "other",
            "user_data": user_data,
            "custom_data": {
                "currency": moeda,
                "value": total,
                "order_id": pedido_id,
                "content_type": "product"
            }
        }

        payload = {
            "data": [evento],
            "access_token": access_token
        }

        url = f"https://graph.facebook.com/v18.0/{pixel_id}/events"

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                resultado = json.loads(resp.read())
                print(f"[NUVEMSHOP] Pedido {pedido_id} → CAPI OK | ctwa: {'✅' if ctwa_clid else '—'} | {resultado}")
                return jsonify({"status": "ok", "event_id": event_id,
                                "tem_ctwa": bool(ctwa_clid), "meta": resultado}), 200

        except Exception as e:
            print(f"[NUVEMSHOP] Erro CAPI pedido {pedido_id}: {e}")
            return jsonify({"error": str(e)}), 500

    return app


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WhatsApp ctwa_clid Receiver — UltimatePPF WZAP Attribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Iniciar servidor webhook
  python3 whatsapp_ctwa_receiver.py

  # Consultar ctwa_clid de um telefone
  python3 whatsapp_ctwa_receiver.py --lookup 5567999999999

  # Listar todos os registros
  python3 whatsapp_ctwa_receiver.py --list

  # Iniciar em porta diferente
  PORT=8080 python3 whatsapp_ctwa_receiver.py

Variáveis de ambiente:
  WA_VERIFY_TOKEN  Token de verificação do webhook (obrigatório)
  WA_APP_SECRET    App Secret para validar assinatura (recomendado)
  CTWA_DB_PATH     Caminho do banco SQLite (padrão: ctwa_store.db)
  PORT             Porta do servidor (padrão: 5050)
  HOST             Host do servidor (padrão: 0.0.0.0)
        """
    )

    parser.add_argument("--lookup", metavar="PHONE",
                        help="Buscar ctwa_clid de um telefone específico")
    parser.add_argument("--list", action="store_true",
                        help="Listar todos os registros no banco")
    parser.add_argument("--test-payload", metavar="JSON_FILE",
                        help="Processar um payload JSON de teste (sem iniciar servidor)")

    args = parser.parse_args()
    conn = init_db()

    if args.lookup:
        resultado = buscar_ctwa(conn, args.lookup)
        if resultado:
            print(f"\nctwa_clid encontrado para {args.lookup}:")
            for k, v in resultado.items():
                print(f"  {k}: {v}")

            # Construir fbc para uso no CAPI
            import time
            fbc = f"fb.1.{int(time.time() * 1000)}.{resultado['ctwa_clid']}"
            print(f"\n  fbc (para Meta CAPI): {fbc}")
        else:
            print(f"\nNenhum ctwa_clid encontrado para {args.lookup}")
        return

    if args.list:
        registros = listar_todos(conn)
        if not registros:
            print("Nenhum registro encontrado.")
        else:
            print(f"\n{'='*80}")
            print(f"  Total: {len(registros)} registros")
            print(f"{'='*80}")
            for r in registros:
                print(f"  📱 {r['phone']}")
                print(f"     ctwa_clid: {r['ctwa_clid']}")
                print(f"     ad_id: {r.get('ad_id', '-')} | {r.get('headline', '-')}")
                print(f"     recebido: {r['received_at']}")
                print()
        return

    if args.test_payload:
        with open(args.test_payload) as f:
            payload = json.load(f)
        salvos = processar_payload(payload, conn)
        print(f"\nPayload processado: {salvos} ctwa_clid(s) salvos")
        return

    # Iniciar servidor Flask
    print(f"\n{'='*60}")
    print(f"  WhatsApp ctwa_clid Receiver — UltimatePPF")
    print(f"{'='*60}")
    print(f"  Banco: {DB_PATH}")
    print(f"  Porta: {PORT}")
    print(f"  Verify Token: {VERIFY_TOKEN[:10]}...")
    print(f"  App Secret: {'configurado' if APP_SECRET else 'NÃO configurado (recomendado)'}")
    print(f"\n  Endpoints:")
    print(f"    GET/POST /webhook/whatsapp  — Webhook do Meta")
    print(f"    GET /ctwa/lookup/<phone>    — Consultar ctwa_clid")
    print(f"    GET /ctwa/list              — Listar todos")
    print(f"    GET /health                 — Status do servidor")
    print(f"\n  Configure no Meta for Developers:")
    print(f"    URL: https://seu-servidor.com/webhook/whatsapp")
    print(f"    Token: {VERIFY_TOKEN}")
    print(f"{'='*60}\n")

    app = criar_app(conn)

    try:
        app.run(host=HOST, port=PORT, debug=False)
    except KeyboardInterrupt:
        print("\n[INFO] Servidor encerrado.")


if __name__ == "__main__":
    main()
