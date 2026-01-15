"""
Interface Gradio pour le système anti-spam hybride

"""

import gradio as gr
from hybrid_filter import HybridSpamFilter
from dataset_manager import DatasetManager
import os
import sys
import socket


print(" Chargement du modèle...")
spam_filter = HybridSpamFilter(ml_threshold=0.5)  

model_path = './models/spam_model.pkl'
if os.path.exists(model_path):
    spam_filter.load_ml_model(model_path)
    print(" Modèle chargé")
else:
    print(" Modèle non trouvé, entraînement rapide...")
    dm = DatasetManager()
    X, y, _ = dm.load_dataset()
    spam_filter.train_ml_model(X[:500], y[:500])
    spam_filter.ml_classifier.save_model(model_path)
    print("Modèle entraîné et sauvegardé")


stats = {"total": 0, "spam": 0, "legitimate": 0}

def analyze_email(email_text):
    """Analyse un email avec seuil fixe optimisé"""
    
    if not email_text or not email_text.strip():
        return " Veuillez entrer un email à analyser", "", "", "", ""
    
 
    result = spam_filter.classify(email_text)
    
   
    stats["total"] += 1
    if result['is_spam']:
        stats["spam"] += 1
    else:
        stats["legitimate"] += 1
    
   
    if result['is_spam']:
        verdict = "🚫 **SPAM DÉTECTÉ**"
        verdict_color = "#fee"
    else:
        verdict = "✅ **EMAIL LÉGITIME**"
        verdict_color = "#efe"
    
    method = f"**Méthode:** {result['method'].upper()}"
    confidence = f"**Confiance:** {result['confidence']:.0%}"
    reason = f"**Raison:** {result['reason']}"
    
    
    stats_text = f"""
     **Statistiques globales:**
    - Total analysés: {stats['total']}
    - Spams bloqués: {stats['spam']}
    - Emails légitimes: {stats['legitimate']}
    - Ratio spam: {stats['spam']/max(stats['total'],1):.1%}
    """
    
    return verdict, method, confidence, reason, stats_text



examples = [
    "give me money if you don't give it i will kill you",
    "Bonjour, Dans le cadre de nos vérifications régulières, un paramétrage de votre compte nécessite une attention particulière. 👉 Accéder à mon espace",
    "URGENT!!! Téléchargez virus.exe bit.ly/xxx GAGNEZ 10000€ GRATUIT!!!",
    "Bonjour, voici le rapport #12345 demandé pour la réunion de demain. Cordialement",
    "CONGRATULATIONS!!! You WON the LOTTERY!!! Click bit.ly/winner123 NOW!!!",
    "Bonjour Madame, votre dossier administratif est en cours de traitement. Service client.",
]


def is_port_available(port):
    """Vérifie si un port est disponible"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('127.0.0.1', port))  
            return True
        except socket.error:
            return False


with gr.Blocks(title="Anti-Spam Hybride", theme=gr.themes.Soft()) as demo:
    
    gr.Markdown("""
    <style>
    .spam-verdict {
        background-color: #ffebee;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #f44336;
        margin: 10px 0;
    }
    .ham-verdict {
        background-color: #e8f5e9;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #4caf50;
        margin: 10px 0;
    }
    .stat-box {
        background-color: #f5f5f5;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #ddd;
    }
    </style>
    
    # 🛡️ Anti-Spam Hybride
    ### Système intelligent de détection de spam
    
    **Fonctionnement automatique :** Le système utilise des règles heuristiques et un modèle ML avec seuil optimisé pour détection précise.
    """)
    
    with gr.Row():
        with gr.Column(scale=2):
            email_input = gr.Textbox(
                label=" Email à analyser",
                placeholder="Collez le contenu de l'email ici...",
                lines=8
            )
            
            analyze_btn = gr.Button(" Analyser l'email", variant="primary", size="lg")
            
        with gr.Column(scale=1):
            verdict_output = gr.Markdown(label="##  Verdict")
            method_output = gr.Markdown(label="###  Méthode utilisée")
            confidence_output = gr.Markdown(label="###  Niveau de confiance")
            reason_output = gr.Markdown(label="###  Explication détaillée")
            stats_output = gr.Markdown(label="### 📊 Statistiques")
    
    gr.Markdown("### ** Exemples à tester**")
    gr.Examples(
        examples=examples,
        inputs=[email_input],
        label="Cliquez sur un exemple pour le charger"
    )
    
    gr.Markdown("""
    ---
   ### Comment fonctionne notre système ?
    
    ** Règles Heuristiques (Rapide & Fiable)**
    - Détecte automatiquement les fichiers dangereux (.exe, .bat, .vbs)
    - Identifie les URLs raccourcies suspectes (bit.ly, tinyurl)
    - Reconnaît les menaces et le phishing sophistiqué
    - Filtre les emails avec ponctuation/majuscules excessives
    
    ** Machine Learning (Intelligent & Adaptatif)**
    - Modèle Naive Bayes entraîné sur 1200+ emails
    - Comprend le contexte avec analyse bi-gram
    - Seuil optimisé pour performance maximale (0.6)
    - Apprentissage continu sur nouveaux patterns
    
    ** Approche Hybride (Le meilleur des deux mondes)**
    - Les règles traitent les cas évidents (ultra-rapide)
    - Le ML analyse les cas complexes (plus précis)
    - Résultats combinés pour décision finale
    """)
    
   
    analyze_btn.click(
        fn=analyze_email,
        inputs=[email_input],
        outputs=[verdict_output, method_output, confidence_output, reason_output, stats_output]
    )



if __name__ == "__main__":
    print("\n" + "="*60)
    print(" LANCEMENT DE L'INTERFACE GRADIO")
    print("="*60)
    
    import gradio as gr
    print(f" Version Gradio: {gr.__version__}")
    
    
    base_port = 7860
    port = base_port
    
    while not is_port_available(port) and port < base_port + 20:
        port += 1
    
    print(f"\nPort disponible trouvé: {port}")
    
    # MODES
    print(f"\n Modes disponibles:")
    print(f"  1.  Lien PUBLIC (Gradio Share)")
    print(f"  2.  Local SEULEMENT (Localhost:{port})")
    print(f"  3.  Terminal uniquement")
    print(f"  4.  Quitter")
    
    try:
        choice = input("\nVotre choix (1/2/3/4): ").strip()
        
        if choice == "4":
            print("\n Au revoir!")
            sys.exit(0)
            
        elif choice == "3":
            print("\n MODE TERMINAL ACTIVÉ")
            print("\n MODE TERMINAL ACTIVÉ")
            print("Tapez 'quit' pour quitter\n")
            
            test_count = 0
            spam_count = 0
            
            while True:
                email_text = input("\n Email à tester: ").strip()
                
                if email_text.lower() in ['quit', 'exit', 'q']:
                    print(f"\n RÉCAPITULATIF:")
                    print(f"   • Emails testés: {test_count}")
                    print(f"   • Spams détectés: {spam_count}")
                    print(f"   • Ratio spam: {spam_count/max(test_count,1):.1%}")
                    print("\n Au revoir!")
                    break
                
                if not email_text:
                    continue
                
                test_count += 1
                result = spam_filter.classify(email_text)
                
                if result['is_spam']:
                    spam_count += 1
                    print(f"\n🚫 SPAM DÉTECTÉ")
                else:
                    print(f"\n✅ EMAIL LÉGITIME")
                
                print(f"   Méthode: {result['method'].upper()}")
                print(f"   Confiance: {result['confidence']:.1%}")
                print(f"   Raison: {result['reason']}")
        
            
        elif choice == "1":
          
            print(f"\n CRÉATION DU LIEN PUBLIC...")
            print(f" Cela peut prendre 10-30 secondes...")
            
            try:
                ebug=True
                demo.queue()  
                demo.launch(
                    share=True,          
                    server_name="0.0.0.0", 
                    server_port=port,
                    show_error=True,
                    debug=True,          
                    inbrowser=False,    
                    prevent_thread_lock=False,
                    quiet=False          
                )
            except Exception as e:
                print(f"\n❌ ERREUR lors de la création du lien public:")
                print(f"   {str(e)}")
                print(f"\n SOLUTIONS ALTERNATIVES:")
                print(f"   1. Utilisez le mode LOCAL (option 2)")
                print(f"   2. Vérifiez votre connexion internet")
                print(f"   3. Désactivez temporairement votre pare-feu")
                print(f"   4. Installez la dernière version: pip install --upgrade gradio")
        
        else:
            # Mode LOCAL (option 2)
            print(f"\n INTERFACE LOCALE")
            print(f" URL: http://localhost:{port}")
            print(f" URL réseau: http://127.0.0.1:{port}")
            print(f"  Appuyez sur Ctrl+C pour arrêter\n")
            
            try:
                demo.launch(
                    share=False,         # Pas de lien public
                    server_name="127.0.0.1",
                    server_port=port,
                    show_error=True,
                    inbrowser=True      
                )
            except KeyboardInterrupt:
                print("\n\n Interface arrêtée")
    
    except KeyboardInterrupt:
        print("\n\n Opération annulée")
    except Exception as e:
        print(f"\n⚠️ Erreur: {e}")
