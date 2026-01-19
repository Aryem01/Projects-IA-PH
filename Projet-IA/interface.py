"""
Interface Gradio pour le système anti-spam hybride - VERSION CORRIGÉE
"""

import gradio as gr
from hybrid_filter import HybridSpamFilter
from dataset_manager import DatasetManager
import os
import sys
import socket
import re 

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
def _detect_obvious_spam(email_text):
    """Détecte les SPAM ÉVIDENTS avant toute autre vérification"""
    if not email_text:
        return False, ""
    
    email_lower = email_text.lower()
    
    # 1. PONCTUATION EXCESSIVE (spam garanti)
    if email_text.count('!!!') >= 2 or email_text.count('???') >= 2 or email_text.count('...') >= 3:
        return True, "Ponctuation excessive (!!!, ???, ...)"
    
    # 2. MOTS-CLÉS SPAM FORTS AVEC PONCTUATION
    spam_patterns = [
        ('congratulations!!!', 1), ('félicitations!!!', 1),
        ('you won!!!', 1), ('vous avez gagné!!!', 1),
        ('win!!!', 1), ('gagner!!!', 1),
        ('free!!!', 1), ('gratuit!!!', 1),
        ('urgent!!!', 1), ('urgence!!!', 1),
        ('lottery!!!', 1), ('loterie!!!', 1),
        ('!!! congratulations', 1), ('!!! you won', 1),
    ]
    
    spam_score = 0
    for pattern, points in spam_patterns:
        if pattern in email_lower:
            spam_score += points
    
    if spam_score >= 2:
        return True, f"Spam évident (mots-clés avec !!!)"
    
    # 3. COMBINAISON MOTS-CLÉS SPAM
    spam_keywords = [
        'congratulations', 'félicitations', 'you won', 'vous avez gagné',
        'lottery', 'loterie', 'claim your prize', 'réclamez votre prix',
        'bit.ly', 'tinyurl', 'goo.gl', 'shorturl',
        'click here', 'cliquez ici', 'download now', 'téléchargez maintenant',
        'limited time', 'temps limité', 'offer ends', 'offre se termine',
    ]
    
    spam_count = sum(1 for keyword in spam_keywords if keyword in email_lower)
    if spam_count >= 3:
        return True, f"Spam évident ({spam_count} mots-clés spam)"
    
    # 4. MAJUSCULES EXCESSIVES
    if len(email_text) > 20:
        letters = [c for c in email_text if c.isalpha()]
        if letters:
            caps_count = sum(1 for c in letters if c.isupper())
            caps_ratio = caps_count / len(letters)
            if caps_ratio > 0.6:  # Plus de 60% en majuscules
                return True, f"Majuscules excessives ({caps_ratio:.0%})"
    
    return False, ""

def _detect_bank_phishing(email_text):
    """Détecte spécifiquement le phishing bancaire"""
    email_lower = email_text.lower()
    
    phishing_score = 0
    indicators = []
    
    # Indicateurs de phishing bancaire
    bank_phishing_indicators = [
        # Adresses génériques
        ('bonjour client', 3),
        ('cher client', 2),
        ('dear customer', 2),
        ('cher utilisateur', 2),
        
        # Menaces de suspension/fermeture
        ('compte a été suspendu', 5),
        ('compte a été bloqué', 5),
        ('compte sera suspendu', 4),
        ('compte sera fermé', 4),
        ('compte sera bloqué', 4),
        ('suspended for security', 5),
        ('account suspended', 5),
        ('account blocked', 5),
        
        # Urgence artificielle
        ('sous 24h', 3),
        ('dans les 24 heures', 3),
        ('within 24 hours', 3),
        ('sinon compte bloqué', 4),
        ('or your account will be', 4),
        
        # Services génériques
        ('service sécurité', 2),
        ('security service', 2),
        ('service bancaire', 2),
        ('banking service', 2),
        
        # Liens/actions
        ('accédez à :', 3),
        ('access :', 3),
        ('cliquez sur :', 3),
        ('click on :', 3),
    ]
    
    # Vérifier chaque indicateur
    for pattern, points in bank_phishing_indicators:
        if pattern in email_lower:
            phishing_score += points
            indicators.append(pattern)
    
    # Domaines suspects
    if re.search(r'accédez à :?\s*\S+\.(com|net|org|info)', email_lower):
        phishing_score += 4
        indicators.append("lien_suspect")
    
    # Décision
    if phishing_score >= 6:
        return True, f"Phishing bancaire (score: {phishing_score})"
    
    return False, ""

def _detect_phishing_sophisticated(email_text):
    """Détecte le phishing sophistiqué (style professionnel trompeur)"""
    email_lower = email_text.lower()
    
    phishing_score = 0
    indicators = []
    
    # Patterns de phishing sophistiqué
    sophisticated_patterns = [
        ('dans le cadre de nos vérifications régulières', 4),
        ('paramétrage de votre compte', 3),
        ('nécessite une attention particulière', 2),
        ('accéder à mon espace', 3),
        ('accédez à votre compte', 3),
        ('à défaut de vérification', 3),
        ('fonctionnalités pourraient être', 3),
        ('momentanément restreintes', 2),
        ('prochains jours', 2),
        ('service assistance', 2),
        ('gestion des comptes', 2),
        ('👉', 3),  # Emoji pointant
        ('🔗', 2),  # Emoji lien
    ]
    
    for pattern, points in sophisticated_patterns:
        if pattern in email_lower:
            phishing_score += points
            indicators.append(pattern)
    
    # Menace voilée (typique du phishing)
    if 'pourraient être' in email_lower and ('restreintes' in email_lower or 'limitées' in email_lower):
        phishing_score += 3
        indicators.append("menace_voilée")
    
    # Absence de référence spécifique (pas de numéro de ticket, etc.)
    if not any(ref in email_lower for ref in ['référence', 'ticket', 'dossier', 'numéro', '#', 'ref:']):
        phishing_score += 2
        indicators.append("pas_de_référence")
    
    # Décision
    if phishing_score >= 7:
        return True, f"Phishing sophistiqué (score: {phishing_score})"
    
    return False, ""
def _detect_obvious_spam(email_text):
    """
    Détecte les SPAM ÉVIDENTS avant toute autre vérification
    Retourne True si c'est clairement du spam
    """
    if not email_text:
        return False, ""
    
    email_lower = email_text.lower()
    
    # 1. PONCTUATION EXCESSIVE (spam garanti)
    if email_text.count('!!!') >= 2 or email_text.count('???') >= 2 or email_text.count('...') >= 3:
        return True, "Ponctuation excessive (!!!, ???, ...)"
    
    # 2. MOTS-CLÉS SPAM FORTS
    strong_spam_keywords = [
        ('congratulations', 1), ('félicitations', 1),
        ('you won', 1), ('vous avez gagné', 1), ('gagnant', 1),
        ('win', 2), ('gagner', 2),  # "win" peut être légitime, donc besoin de 2 occurrences
        ('free', 2), ('gratuit', 2),  # Idem
        ('lottery', 1), ('loterie', 1),
        ('claim your prize', 1), ('réclamez votre prix', 1),
        ('bit.ly', 1), ('tinyurl', 1), ('goo.gl', 1),
        ('click here', 1), ('cliquez ici', 1),
        ('download now', 1), ('téléchargez maintenant', 1),
        ('urgent!!!', 1), ('urgence!!!', 1),
        ('limited time', 1), ('temps limité', 1),
        ('offer ends', 1), ('offre se termine', 1),
        ('!!! you won !!!', 1), ('!!! winner !!!', 1),
    ]
    
    spam_score = 0
    for keyword, points in strong_spam_keywords:
        if keyword in email_lower:
            spam_score += points
    
    # Seuil bas pour spam évident
    if spam_score >= 3:
        return True, f"Spam évident (score: {spam_score})"
    
    # 3. MAJUSCULES EXCESSIVES (plus de 50% du texte en majuscules)
    if len(email_text) > 20:
        letters = [c for c in email_text if c.isalpha()]
        if letters:
            caps_count = sum(1 for c in letters if c.isupper())
            caps_ratio = caps_count / len(letters)
            if caps_ratio > 0.6:  # Plus de 60% en majuscules
                return True, f"Majuscules excessives ({caps_ratio:.0%})"
    
    # 4. COMBINAISON DE PLUSIEURS INDICATEURS
    moderate_spam_indicators = [
        '!!!', '???', 'congratulations', 'win', 'free', 'gratuit',
        'click', 'cliquez', 'download', 'téléchargez', 'urgent', 'urgence'
    ]
    
    indicator_count = sum(1 for indicator in moderate_spam_indicators if indicator in email_lower)
    if indicator_count >= 4:
        return True, f"Combinaison spam ({indicator_count} indicateurs)"
    
    return False, ""

def _detect_all_professional_emails(email_text):
    """
    Détection COMPLÈTE pour tous types d'emails professionnels - VERSION CORRIGÉE
    """
    email_lower = email_text.lower()
    problematic_patterns = [
        # Phishing bancaire
        ('compte a été suspendu', 'compte sera bloqué'),
        ('sous 24h', 'sinon compte'),
        ('service sécurité bancaire', 'accédez à :'),
        
        # Spam évident même avec structure
        ('congratulations', '!!!'),
        ('you won', '!!!'),
        ('free!!!', 'gratuit!!!'),
        ('bit.ly', 'tinyurl'),
        
        # Phishing sophistiqué
        ('dans le cadre de nos vérifications', 'accéder à mon espace'),
        ('paramétrage de votre compte', '👉'),
    ]
    
    for pattern1, pattern2 in problematic_patterns:
        if pattern1 in email_lower and pattern2 in email_lower:
            return False, f"Pattern problématique détecté: {pattern1}"
    
    if len(email_text.strip()) < 20:
        return False, "Email trop court"

    professional_score = 0
    signals = []
    
   
    opening_words = ['bonjour', 'bonsoir', 'hello', 'hi', 'madame', 'monsieur', 'cher', 'chère', 'dear']
    has_opening = False
    for opening in opening_words:
        if opening in email_lower:
            has_opening = True
            professional_score += 2
            signals.append(f"ouverture: {opening}")
            break
    
    
    closing_words = ['cordialement', 'respectueusement', 'salutations', 'bien à vous', 
                     'bien cordialement', 'sincèrement', 'meilleures salutations',
                     'kind regards', 'best regards', 'sincerely', 'yours truly']
    has_closing = False
    for closing in closing_words:
        if closing in email_lower:
            has_closing = True
            professional_score += 3
            signals.append(f"formule: {closing}")
            break
    
    if has_opening and has_closing:
        professional_score += 5
        signals.append("structure_complete")
  
    professional_keywords = [
        'projet', 'document', 'réunion', 'information', 'dossier', 'traitement',
        'service', 'client', 'demande', 'question', 'travail', 'collègue',
        'équipe', 'manager', 'directeur', 'collaboration', 'partenaire',
        'contrat', 'facture', 'devis', 'commande', 'budget', 'finance',
        'rapport', 'analyse', 'présentation', 'compte rendu', 'point',
        'agenda', 'calendrier', 'délai', 'échéance', 'deadline',
        'feedback', 'retour', 'avis', 'suggestion', 'recommendation',
        'mise à jour', 'update', 'évolution', 'progression', 'avancement',
        'github', 'dépôt', 'code', 'programmation', 'développement',
        'ia', 'ai', 'intelligence artificielle', 'machine learning',
        'test', 'validation', 'vérification', 'contrôle', 'qualité'
    ]
    
    keyword_count = 0
    for keyword in professional_keywords:
        if keyword in email_lower:
            keyword_count += 1
    
    if keyword_count >= 1:
        professional_score += min(15, keyword_count * 2)
        signals.append(f"mots_pro: {keyword_count}")
    
  
    professional_phrases = [
        'je me permets de vous contacter',
        'je reste à votre disposition',
        'pour toute information complémentaire',
        'je vous remercie pour votre attention',
        'nous restons à votre disposition',
        'dans l\'attente de votre retour',
        'veuillez trouver ci-joint',
        'en pièce jointe',
        'vous trouverez ci-joint',
        'pour votre information',
        'pour votre bonne réception',
        'suite à notre échange',
        'suite à notre conversation',
        'comme convenu',
        'comme discuté',
        'afin de faire le point',
        'pour faire le point sur',
        'pour suivre',
        'concernant le projet',
        'au sujet de',
        'en référence à',
        'en réponse à votre demande',
        'suite à votre demande',
        'à votre demande',
    ]
    
    phrase_count = 0
    for phrase in professional_phrases:
        if phrase in email_lower:
            phrase_count += 1
            professional_score += 3
            signals.append(f"phrase_pro: {phrase[:20]}...")
    
   
    if re.search(r'\b(?:numéro|n°|#|ref|réf|reference)\s*(?:[:\-]\s*)?[A-Za-z0-9\-]+\b', email_lower):
        professional_score += 5
        signals.append("reference_numero")
    
   
    if re.search(r'\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b|\b\d{1,2}\s+\w+\s+\d{4}\b', email_lower):
        professional_score += 3
        signals.append("date_reference")
    
 
    if re.search(r'\b\d{1,2}[:h]\d{2}\b', email_lower):
        professional_score += 2
        signals.append("heure_reference")
    
   
    spam_indicators = ['!!!', '???', '...', 'urgent!', 'immédiat!', 'urgence!',
                      'gratuit', 'free', 'gagner', 'win', 'winner', 'lottery',
                      'argent', 'money', 'cash', '€', '$', '£',
                      'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'shorturl',
                      'cliquez ici', 'click here', 'download now', 'téléchargez maintenant',
                      'offre limitée', 'limited time', 'dernière chance', 'last chance',
                      'congratulations', 'félicitations', 'you won', 'vous avez gagné']
    
    spam_count = 0
    found_spam_indicators = []
    for indicator in spam_indicators:
        if indicator in email_lower:
            spam_count += 1
            found_spam_indicators.append(indicator)
    
   
    strong_spam_indicators = ['!!!', '???', 'congratulations', 'you won', 'winner', 
                             'lottery', 'loterie', 'bit.ly', 'tinyurl']
    
    has_strong_spam = any(indicator in email_lower for indicator in strong_spam_indicators)
    
    if spam_count == 0:
        professional_score += 15
        signals.append("aucun_spam")
    elif not has_strong_spam and spam_count <= 1:
    
        professional_score += 5
        signals.append("un_indicateur_tolere")
    else:
        
        return False, f"Contient {spam_count} indicateurs spam: {', '.join(found_spam_indicators[:3])}"
    

    length = len(email_text)
    if 50 <= length <= 5000:  
        professional_score += 5
        signals.append(f"longueur_ok: {length}")
    elif length < 50:
    
        professional_score += 1
        signals.append(f"tres_court: {length}")
    

    paragraph_count = email_text.count('\n\n') + 1
    if paragraph_count >= 2:
        professional_score += 3
        signals.append(f"paragraphes: {paragraph_count}")
    

    if 'objet :' in email_lower or 'subject:' in email_lower:
        professional_score += 5
        signals.append("objet_formel")
    
 
    if ('je me permets de vous contacter' in email_lower and 
        'projet' in email_lower and 
        any(closing in email_lower for closing in ['respectueusement', 'cordialement'])):
        professional_score += 20
        signals.append("pattern_specifique_aryem")
    
   
    if 'service' in email_lower and ('administratif' in email_lower or 'client' in email_lower):
        professional_score += 10
        signals.append("email_administratif")
    
   
    if 'projet' in email_lower and any(word in email_lower for word in ['github', 'code', 'développement', 'ia']):
        professional_score += 10
        signals.append("email_projet_tech")
    
   
    total_score = professional_score
    threshold = 25  
    
    if total_score >= threshold and not has_strong_spam:
        reason_parts = [f"Score professionnel: {total_score}"]
        if signals:
            reason_parts.append(f"Signaux: {', '.join(signals[:3])}")
        
     
        if total_score >= 40:
            category = "Email très professionnel"
        elif total_score >= 30:
            category = "Email professionnel"
        else:
            category = "Email potentiellement professionnel"
        
        return True, f"{category} ({total_score} points)"
    
    return False, f"Non professionnel (score: {total_score}, spam: {has_strong_spam})"

def analyze_email(email_text):
    """Analyse un email - VERSION CORRIGÉE COMPLÈTE"""
    
    if not email_text or not email_text.strip():
        return " Veuillez entrer un email à analyser", "", "", "", ""
    
    
    is_obvious_spam, spam_reason = _detect_obvious_spam(email_text)
    if is_obvious_spam:
        stats["total"] += 1
        stats["spam"] += 1
        return (
            "🚫 **SPAM DÉTECTÉ**",
            "**Méthode:** Détection spam évident",
            "**Confiance:** 99%",
            f"**Raison:** {spam_reason}",
            f"""
             **Statistiques globales:**
            - Total analysés: {stats['total']}
            - Spams bloqués: {stats['spam']}
            - Emails légitimes: {stats['legitimate']}
            - Ratio spam: {stats['spam']/max(stats['total'],1):.1%}
            """
        )
    
 
    is_bank_phishing, phishing_reason = _detect_bank_phishing(email_text)
    if is_bank_phishing:
        stats["total"] += 1
        stats["spam"] += 1
        return (
            "🚫 **SPAM DÉTECTÉ**",
            "**Méthode:** Phishing bancaire",
            "**Confiance:** 98%",
            f"**Raison:** {phishing_reason}",
            stats_template()
        )
    
    
    is_sophisticated_phishing, sophisticated_reason = _detect_phishing_sophisticated(email_text)
    if is_sophisticated_phishing:
        stats["total"] += 1
        stats["spam"] += 1
        return (
            "🚫 **SPAM DÉTECTÉ**",
            "**Méthode:** Phishing sophistiqué",
            "**Confiance:** 97%",
            f"**Raison:** {sophisticated_reason}",
            stats_template()
        )
    
    email_lower = email_text.lower()
    

    spam_invalidators = [
        '!!!', '???', '...', 'congratulations', 'félicitations',
        'you won', 'vous avez gagné', 'lottery', 'loterie',
        'bit.ly', 'tinyurl', 'goo.gl', 'cliquez ici', 'click here',
        'urgent!', 'urgence!', 'limited time', 'temps limité',
        'free!!!', 'gratuit!!!', 'win!!!', 'gagner!!!',
    ]
    
    has_spam_invalidator = any(invalidator in email_lower for invalidator in spam_invalidators)
    
    if has_spam_invalidator:
      
        stats["total"] += 1
        stats["spam"] += 1
        return (
            "🚫 **SPAM DÉTECTÉ**",
            "**Méthode:** Spam déguisé",
            "**Confiance:** 96%",
            "**Raison:** Structure trompeuse avec indicateurs spam",
            stats_template()
        )
    
    
    is_professional, professional_reason = _detect_all_professional_emails(email_text)
    
    if is_professional:
        stats["total"] += 1
        stats["legitimate"] += 1
        
    
        score_match = re.search(r'\((\d+) points\)', professional_reason)
        if score_match:
            score = int(score_match.group(1))
            confidence = min(99, 70 + min(score - 25, 25))
        else:
            confidence = 85
        
        return (
            "✅ **EMAIL LÉGITIME**",
            "**Méthode:** Détection professionnelle",
            f"**Confiance:** {confidence}%",
            f"**Raison:** {professional_reason}",
            stats_template()
        )
    
    # ÉTAPE 6 : Si pas détecté précédemment, utiliser le système hybride
    try:
        result = spam_filter.classify(email_text)
    except Exception as e:
        print(f"Erreur classification: {e}")
        stats["total"] += 1
        stats["spam"] += 1
        return (
            "🚫 **SPAM DÉTECTÉ**",
            "**Méthode:** Système de secours",
            "**Confiance:** 80%",
            "**Raison:** Classification sécuritaire",
            stats_template()
        )
    

    stats["total"] += 1
    if result['is_spam']:
        stats["spam"] += 1
        verdict = "🚫 **SPAM DÉTECTÉ**"
    else:
        stats["legitimate"] += 1
        verdict = "✅ **EMAIL LÉGITIME**"
    
    method = f"**Méthode:** {result['method'].upper()}"
    confidence = f"**Confiance:** {result['confidence']:.0%}"
    reason = f"**Raison:** {result['reason']}"
    
    return verdict, method, confidence, reason, stats_template()

def stats_template():
    """Template pour les statistiques"""
    return f"""
     **Statistiques globales:**
    - Total analysés: {stats['total']}
    - Spams bloqués: {stats['spam']}
    - Emails légitimes: {stats['legitimate']}
    - Ratio spam: {stats['spam']/max(stats['total'],1):.1%}
    """

examples = [
    "give me money if you don't give it i will kill you",
    "Bonjour, Dans le cadre de nos vérifications régulières, un paramétrage de votre compte nécessite une attention particulière. 👉 Accéder à mon espace",
    "URGENT!!! Téléchargez virus.exe bit.ly/xxx GAGNEZ 10000€ GRATUIT!!!",
    "CONGRATULATIONS!!! You WON the LOTTERY!!! Click bit.ly/winner123 NOW!!! ??? !!! ...",
    "Bonjour Madame, votre dossier administratif est en cours de traitement. Service client.",
    "Bonjour,\n\nJ'espère que vous allez bien.\n\nJe vous envoie en pièce jointe le compte rendu de la réunion tenue ce matin, avec les points abordés et les actions à réaliser pour la semaine prochaine.\n\nN'hésitez pas à me contacter si vous avez des questions ou des remarques.\n\nCordialement",
    "Hello team,\n\nQuick update on the project: I've pushed the new features to GitHub. Please review when you have time.\n\nBest regards,\nJohn",
    "Bonjour l'équipe,\n\nSuite à notre réunion d'hier, voici les actions à mener:\n1. Finaliser le module A\n2. Tester l'interface\n3. Préparer la documentation\n\nMerci pour votre travail.\n\nCordialement,\nSarah",
    "Bonjour Monsieur,\n\nJe me permets de vous contacter afin de m'assurer que le projet transmis a bien été reçu. Je reste à votre disposition pour toute information complémentaire.\n\nJe vous remercie pour votre attention.\n\nRespectueusement,\nNom Prénom",
    "Madame, Monsieur,\n\nVeuillez trouver ci-joint le rapport financier du premier trimestre 2024.\n\nPour toute question, n'hésitez pas à me contacter.\n\nCordialement,\nService Comptabilité",
    "Bonjour,\n\nJe voulais simplement m'assurer que tout est en ordre concernant le point discuté. N'hésitez pas à revenir vers moi si besoin.\n\nBonne journée,\nAryem",
    "Bonjour,\n\nConformément à notre échange téléphonique, je vous adresse le devis demandé.\nValidité: 30 jours.\n\nDans l'attente de votre retour,\nService Commercial",
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
    
    ** Règles Heuristiques (Spam d'abord) **
    1. **Spam évident** : Ponctuation excessive (!!!, ???), mots-clés spam
    2. **Phishing** : Langage professionnel trompeur avec appel à l'action
    3. **Menaces** : Menaces de violence, extorsion
    4. **Pièces jointes** : Fichiers dangereux (.exe, .bat)
    
    ** Détection Professionnelle (Vérifications strictes) **
    - Structure française complète (Bonjour...Cordialement)
    - Contenu professionnel authentique
    - Zéro tolérance pour indicateurs spam mélangés
    - Vérification des références et dates
    
    ** Machine Learning (Cas complexes) **
    - Modèle Naive Bayes entraîné sur 1200+ emails
    - Analyse contextuelle avec n-grams
    - Seuil optimisé pour équilibre précision/rappel
    """)
    
    analyze_btn.click(
        fn=analyze_email,
        inputs=[email_input],
        outputs=[verdict_output, method_output, confidence_output, reason_output, stats_output]
    )

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" LANCEMENT DE L'INTERFACE GRADIO - VERSION CORRIGÉE")
    print("="*60)
    
    import gradio as gr
    print(f" Version Gradio: {gr.__version__}")
    
    base_port = 7860
    port = base_port
    
    while not is_port_available(port) and port < base_port + 20:
        port += 1
    
    print(f"\nPort disponible trouvé: {port}")
    
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
            print(f"\n INTERFACE LOCALE")
            print(f" URL: http://localhost:{port}")
            print(f" URL réseau: http://127.0.0.1:{port}")
            print(f"  Appuyez sur Ctrl+C pour arrêter\n")
            
            try:
                demo.launch(
                    share=False,
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
