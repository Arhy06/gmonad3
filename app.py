from flask import Flask, request, render_template, jsonify
import time, threading, queue, argparse, signal
from web3 import Web3
import re

app = Flask(__name__)
log_queue = queue.Queue()
stop_flag = threading.Event()

w3 = Web3(Web3.HTTPProvider("https://testnet-rpc.monad.xyz"))
GAS_LIMIT = 21000

def log(msg):
    print(msg)
    log_queue.put(msg)

def clean_private_key(pk):
    """Ajoute 0x si manquant et vérifie que c’est bien une clé hexa de 64 caractères"""
    pk = pk.lower()
    if pk.startswith('0x'):
        hex_part = pk[2:]
    else:
        hex_part = pk
        pk = '0x' + pk

    if len(hex_part) != 64 or not re.fullmatch(r'[a-f0-9]{64}', hex_part):
        return None  # invalide
    return pk

def is_valid_address(addr):
    return w3.is_address(addr)

def monad_bot(pk1, addr1, pk2, addr2, amount, repeat):
    try:
        amount_wei = w3.to_wei(amount, 'ether')
        for i in range(repeat):
            if stop_flag.is_set():
                log("🛑 Bot arrêté par l'utilisateur.")
                return

            log(f"🔁 Intéraction {i+1}/{repeat}")
            nonce1 = w3.eth.get_transaction_count(addr1)
            gas_price = w3.eth.gas_price
            tx1 = {
                'nonce': nonce1,
                'to': addr2,
                'value': amount_wei,
                'gas': GAS_LIMIT,
                'gasPrice': gas_price
            }
            signed_tx1 = w3.eth.account.sign_transaction(tx1, pk1)
            tx_hash1 = w3.eth.send_raw_transaction(signed_tx1.rawTransaction)
            log(f"📤 TX1 → Hash: {tx_hash1.hex()}")
            time.sleep(15)

            nonce2 = w3.eth.get_transaction_count(addr2)
            tx2 = {
                'nonce': nonce2,
                'to': addr1,
                'value': amount_wei,
                'gas': GAS_LIMIT,
                'gasPrice': gas_price
            }
            signed_tx2 = w3.eth.account.sign_transaction(tx2, pk2)
            tx_hash2 = w3.eth.send_raw_transaction(signed_tx2.rawTransaction)
            log(f"📤 TX2 → Hash: {tx_hash2.hex()}")
            time.sleep(15)

        log("✅ Toutes les transactions sont terminées.")
    except Exception as e:
        log(f"❌ Erreur détectée : {e}")

@app.route('/')
def index():
    return render_template("frontend-of-Gmonad3.html")

@app.route('/start', methods=['POST'])
def start():
    raw_pk1 = request.form['pk1']
    raw_pk2 = request.form['pk2']

    pk1 = clean_private_key(raw_pk1)
    pk2 = clean_private_key(raw_pk2)

    addr1 = request.form['addr1']
    addr2 = request.form['addr2']
    amount = float(request.form['amount'])
    repeat = int(request.form['repeat'])

    if not all([pk1, pk2]):
        return "❌ Clé privée invalide : elle doit être au format hexa (64 ou 66 caractères)", 400
    if not all([is_valid_address(addr1), is_valid_address(addr2)]):
        return "❌ Adresse invalide", 400

    stop_flag.clear()
    thread = threading.Thread(target=monad_bot, args=(pk1, addr1, pk2, addr2, amount, repeat))
    thread.start()
    return "✅ Bot lancé !"

@app.route('/stop', methods=['POST'])
def stop():
    stop_flag.set()
    return "🛑 Bot arreté avec succés."

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = []
    while not log_queue.empty():
        logs.append(log_queue.get())
    return jsonify(logs)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8084)
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port)
