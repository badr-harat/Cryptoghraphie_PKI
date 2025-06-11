from flask import Flask, render_template, request, redirect, send_file, flash, abort, url_for, get_flashed_messages
import os
import subprocess
import webbrowser
from threading import Timer
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = "certapp"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PASSWORD = "0000"

# Assurez-vous que le dossier leaf existe
leaf_dir = os.path.join(BASE_DIR, "leaf")
os.makedirs(leaf_dir, exist_ok=True)




# Fichier pour stocker les statuts de vérification
VERIFICATION_FILE = os.path.join(BASE_DIR, "verification_status.json")

def load_verification_status():
    """Charge les statuts de vérification depuis le fichier JSON"""
    if os.path.exists(VERIFICATION_FILE):
        try:
            with open(VERIFICATION_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_verification_status(status):
    """Sauvegarde les statuts de vérification dans un fichier JSON"""
    with open(VERIFICATION_FILE, 'w') as f:
        json.dump(status, f, indent=2)

def get_certificate_stats():
    """Calcule les statistiques des certificats"""
    try:
        files = os.listdir(leaf_dir)
        total_certs = sum(1 for f in files if f.endswith(".cert.pem"))
        
        # Charger les statuts de vérification
        verification_status = load_verification_status()
        
        # Compter les certificats vérifiés et révoqués
        verified_certs = 0
        revoked_certs = 0
        
        for f in files:
            if f.endswith(".cert.pem"):
                cert_name = f.replace(".cert.pem", "")
                status = verification_status.get(cert_name, {})
                if status.get("verified", False):
                    verified_certs += 1
                if status.get("revoked", False):
                    revoked_certs += 1
        
        return {
            'total_certs': total_certs,
            'verified_certs': verified_certs,
            'revoked_certs': revoked_certs
        }
    except Exception as e:
        print(f"Erreur calcul statistiques: {e}")
        return {
            'total_certs': 0,
            'verified_certs': 0,
            'revoked_certs': 0
        }

def get_recent_certificates(limit=5):
    """Récupère les certificats les plus récents"""
    try:
        certs = []
        files = os.listdir(leaf_dir)
        
        # Charger les statuts de vérification
        verification_status = load_verification_status()
        
        for file in files:
            if file.endswith(".cert.pem"):
                cert_name = file.replace(".cert.pem", "")
                cert_path = os.path.join(leaf_dir, file)
                creation_time = os.path.getctime(cert_path)
                
                # Obtenir le statut de vérification
                cert_status = verification_status.get(cert_name, {})
                
                certs.append({
                    'common_name': cert_name,
                    'creation_date': datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M"),
                    'verified': cert_status.get("verified", False),
                    'revoked': cert_status.get("revoked", False),
                    'verification_date': cert_status.get("verification_date", "")
                })
        
        # Trier par date de création (les plus récents en premier)
        certs.sort(key=lambda x: x['creation_date'], reverse=True)
        return certs[:limit]
    except Exception as e:
        print(f"Erreur récupération certificats: {e}")
        return []

@app.route("/")
def index():
    stats = get_certificate_stats()
    recent_certs = get_recent_certificates()
    current_date = datetime.now().strftime("%d/%m/%Y")
    
    return render_template(
        "index.html",
        stats=stats,
        recent_certs=recent_certs,
        current_date=current_date
    )



@app.route("/generate", methods=["GET", "POST"])
def generate():
    if request.method == "POST":
        cn = request.form.get("common_name", "").strip()
        if not cn:
            flash("Nom commun (CN) est requis.", "danger")
            return redirect(url_for("generate"))

        # Options avancées
        key_type = request.form.get("key_type", "rsa")
        key_size = request.form.get("key_size", "2048")
        wildcard = "wildcard" in request.form

        # Nettoyer le CN pour l'utiliser comme nom de fichier
        cn_safe = "".join(c for c in cn if c.isalnum() or c in ('-', '.')).rstrip()

        # Vérifier si le certificat existe déjà
        cert_path = os.path.join(leaf_dir, f"{cn_safe}.cert.pem")
        if os.path.exists(cert_path):
            flash(f"Un certificat pour '{cn_safe}' existe déjà. Choisissez un autre nom.", "danger")
            return redirect(url_for("generate"))

        # Chemins des fichiers
        key_path = os.path.join(leaf_dir, f"{cn_safe}.key.pem")
        csr_path = os.path.join(leaf_dir, f"{cn_safe}.csr.pem")

        # Étape 1 : Génération de la clé privée
        res = subprocess.run([
            "openssl", "genrsa", "-out", key_path, key_size
        ], capture_output=True, text=True)
        if res.returncode != 0:
            flash(f"Erreur génération clé : {res.stderr}", "danger")
            return redirect(url_for("generate"))

        # Étape 2 : Génération de la CSR
        res = subprocess.run([
            "openssl", "req", "-new", "-key", key_path, "-out", csr_path,
            "-subj", f"/CN={cn_safe}"
        ], capture_output=True, text=True)
        if res.returncode != 0:
            flash(f"Erreur génération CSR : {res.stderr}", "danger")
            return redirect(url_for("generate"))

        # Étape 3 : Signature du certificat avec l’intermédiaire
        config_path = os.path.join(BASE_DIR, "intermediate", "openssl.cnf")
        res = subprocess.run([
            "openssl", "ca", "-config", config_path,
            "-extensions", "usr_cert",
            "-days", "365",
            "-notext", "-md", "sha256",
            "-in", csr_path,
            "-out", cert_path,
            "-passin", f"pass:{PASSWORD}",
            "-batch"
        ], capture_output=True, text=True)
        if res.returncode != 0:
            flash(f"Erreur signature certificat : {res.stderr}", "danger")
            return redirect(url_for("generate"))

        # Marquer comme non vérifié
        verification_status = load_verification_status()
        verification_status[cn_safe] = {
            "verified": False,
            "verification_date": ""
        }
        save_verification_status(verification_status)

        message = f"Certificat généré pour {cn_safe} ✅"
        return render_template("result.html", message=message, continue_url=url_for("generate"), back_url=url_for("index"))

    return render_template("generate.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    message = None
    output = None
    if request.method == "POST":
        cert_name = request.form.get("cert_name", "").strip()
        leaf_dir = os.path.join(os.getcwd(), "leaf")
        cert_path = os.path.join(leaf_dir, f"{cert_name}.cert.pem")

        # Vérifie que le dossier existe
        if not os.path.isdir(leaf_dir):
            message = f"❌ Le dossier des certificats est introuvable : {leaf_dir}"
            return render_template("verify.html", message=message)

        if not os.path.isfile(cert_path):
            message = f"❌ Aucun certificat trouvé sous le nom '{cert_name}'. Veuillez vérifier le nom saisi."
        else:
            # Mettre à jour le statut de vérification
            verification_status = load_verification_status()
            verification_status[cert_name] = {
                "verified": True,
                "verification_date": datetime.now().strftime("%Y-%m-%d %H:%M")
            }
            save_verification_status(verification_status)
            
            output = f"✅ Le certificat '{cert_name}' est maintenant vérifié."
            message = "Vérification réussie."

    return render_template("verify.html", message=message, output=output)

@app.route("/download")
def list_certificates():
    try:
        files = os.listdir(leaf_dir)
        available_certs = []
        
        for file in files:
            if file.endswith(".cert.pem"):
                cert_name = file.replace(".cert.pem", "")
                cert_path = os.path.join(leaf_dir, file)
                creation_time = os.path.getctime(cert_path)
                
                available_certs.append({
                    'common_name': cert_name,
                    'creation_date': datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M"),
                    'expiration_date': "N/A",  # À implémenter avec OpenSSL
                    'status': 'valid'  # À implémenter avec vérification
                })
    except Exception as e:
        flash(f"Erreur lecture dossier certificats : {e}", "danger")
        available_certs = []

    return render_template("download.html", available_certs=available_certs)

@app.route('/download/<cert_name>')
def download(cert_name):
    cert_file = f"{cert_name}.cert.pem"
    cert_path = os.path.join(leaf_dir, cert_file)

    if os.path.exists(cert_path):
        return send_file(cert_path, as_attachment=True)
    else:
        flash("Fichier non trouvé.", "danger")
        return redirect(url_for("list_certificates"))

@app.route("/delete", methods=["GET", "POST"])
def delete():
    try:
        files = os.listdir(leaf_dir)
        available_certs = []
        
        for file in files:
            if file.endswith(".cert.pem"):
                cert_name = file.replace(".cert.pem", "")
                cert_path = os.path.join(leaf_dir, file)
                creation_time = os.path.getctime(cert_path)
                
                available_certs.append({
                    'common_name': cert_name,
                    'creation_date': datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M"),
                    'expiration_date': "N/A",  # À implémenter avec OpenSSL
                    'status': 'valid'  # À implémenter avec vérification
                })
    except Exception as e:
        flash(f"Erreur lecture dossier certificats : {e}", "danger")
        available_certs = []

    if request.method == "POST":
        cert_id = request.form.get("cert_id")
        cert_name = request.form.get("cert_name")
        cert_path = os.path.join(leaf_dir, f"{cert_name}.cert.pem")
        try:
            os.remove(cert_path)
            flash(f"✅ Le certificat '{cert_name}' a été supprimé avec succès.", "success")
            return redirect(url_for("delete"))
        except FileNotFoundError:
            flash(f"❌ Le certificat '{cert_name}' n'existe pas.", "danger")
        except Exception as e:
            flash(f"❌ Erreur lors de la suppression : {str(e)}", "danger")

    return render_template("delete.html", available_certs=available_certs)

# Les autres routes (verify, revoke) restent inchangées

@app.route("/revoke", methods=["GET", "POST"])
def revoke():
    if request.method == "POST":
        cn = request.form.get("cert_name", "").strip()
        cert_path = os.path.join(leaf_dir, f"{cn}.cert.pem")

        if not os.path.exists(cert_path):
            flash("Certificat introuvable, révocation annulée.", "danger")
            return redirect(url_for("revoke"))

        config_path = os.path.join(BASE_DIR, "intermediate", "openssl.cnf")
        crl_path = os.path.join(BASE_DIR, "intermediate", "crl", "intermediate.crl.pem")

        res = subprocess.run([
            "openssl", "ca", "-config", config_path,
            "-revoke", cert_path,
            "-passin", f"pass:{PASSWORD}"
        ], capture_output=True, text=True)
        if res.returncode != 0:
            flash(f"Erreur lors de la révocation : {res.stderr}", "danger")
            return redirect(url_for("revoke"))

        res = subprocess.run([
            "openssl", "ca", "-config", config_path,
            "-gencrl", "-out", crl_path,
            "-passin", f"pass:{PASSWORD}"
        ], capture_output=True, text=True)
        if res.returncode != 0:
            flash(f"Erreur lors de la génération de la CRL : {res.stderr}", "danger")
            return redirect(url_for("revoke"))
        
        # Mettre à jour le statut de révocation
        verification_status = load_verification_status()
        verification_status[cn] = {
            "verified": False,
            "verification_date": "",
            "revoked": True,
            "revocation_date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        save_verification_status(verification_status)

        message = f"Certificat de {cn} révoqué 🔥"
        return render_template("result.html", message=message, continue_url=url_for("revoke"), back_url=url_for("index"))

    return render_template("revoke.html")

if __name__ == "__main__":
    Timer(1, lambda: webbrowser.open_new("http://127.0.0.1:5000/")).start()
    app.run(debug=True, use_reloader=False)