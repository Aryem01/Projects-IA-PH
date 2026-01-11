"""
Dataset Manager pour le vrai dataset Enron  + spam synthétique
"""

import os
import random
import email
from email import policy
from email.parser import BytesParser
from pathlib import Path
import numpy as np
import pandas as pd

class DatasetManager:
    def __init__(self, data_dir='./data'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.processed_dir = self.data_dir / 'processed'
        self.processed_dir.mkdir(exist_ok=True)
        
        # Chemin vers le dataset Enron (maildir dans le même dossier)
        self.enron_dir = Path('maildir')  # maildir 
        
    def _load_real_enron_emails(self, max_emails=800):
        """
        Charge de vrais emails depuis le dataset Enron (maildir)
        """
        print(f" Chargement des emails réels depuis Enron (max: {max_emails})...")
        
        legitimate_emails = []
        email_count = 0
        
        # Vérifier si maildir existe
        if not self.enron_dir.exists():
            print(f" Dossier 'maildir' non trouvé dans: {self.enron_dir.absolute()}")
            print("   Utilisation de données synthétiques à la place.")
            return []
        
        print(f"✓ Dossier Enron trouvé: {self.enron_dir.absolute()}")
        
        # Dossiers à scanner pour les emails légitimes
        email_folders = ['inbox', 'sent_items', '_sent_mail', 'sent', 'all_documents']
        
        try:
            # Parcourir tous les dossiers utilisateurs
            user_dirs = [d for d in self.enron_dir.iterdir() if d.is_dir()]
            print(f"  • {len(user_dirs)} dossiers utilisateurs trouvés")
            
            for user_dir in user_dirs:
                for folder in email_folders:
                    folder_path = user_dir / folder
                    if folder_path.exists():
                        # Compter les fichiers
                        email_files = list(folder_path.iterdir())
                        if email_files:
                            print(f"  • {user_dir.name}/{folder}: {len(email_files)} fichiers")
                            
                            # Lire quelques emails de ce dossier
                            for email_file in email_files[:50]:  # Limiter par dossier
                                if email_count >= max_emails:
                                    print(f"✓ {email_count} emails Enron chargés")
                                    return legitimate_emails
                                
                                try:
                                    # Lire le fichier email
                                    with open(email_file, 'rb') as f:
                                        msg = BytesParser(policy=policy.default).parse(f)
                                    
                                    # Extraire le sujet et le corps
                                    subject = msg.get('subject', '')
                                    body = self._extract_email_body(msg)
                                    
                                    if body and len(body) > 20:  # Email valide
                                        # Créer un texte d'email réaliste
                                        email_text = f"Subject: {subject}\n\n{body}"
                                        
                                        legitimate_emails.append({
                                            'text': email_text[:500],  # Limiter la taille
                                            'label': 0,  # Ham (légitime)
                                            'type': f'enron_{user_dir.name}',
                                            'source': str(email_file)
                                        })
                                        email_count += 1
                                        
                                        if email_count % 100 == 0:
                                            print(f"    {email_count} emails chargés...")
                                        
                                except Exception as e:
                                    # Passer en cas d'erreur sur un fichier
                                    continue
            
        except Exception as e:
            print(f"  Erreur lors du chargement d'Enron: {e}")
        
        print(f"✓ {email_count} emails Enron chargés au total")
        return legitimate_emails
    def _generate_spam_emails(self, count: int) -> list:
        """Génère des emails spam synthétiques - VERSION CORRIGÉE"""
        print(f"🔧 Génération de {count} emails spam synthétiques...")
        
        # PONDÉRATION: Plus de phishing sophistiqué (40%)
        phishing_templates = [
            # Phishing sophistiqué anglais
            "Hello, As part of our regular security review, we identified a configuration detail that may require your attention. To avoid any potential service limitations, we recommend reviewing your account settings at your convenience by accessing your personal area below: 👉 Access my account If the review is not completed within the next few days, certain features may be temporarily unavailable until verification is finalized. Thank you for your understanding, Support Services Account Management Team",
            
            "Important Security Update: We've detected unusual activity on your account. Please verify your identity immediately to prevent temporary restrictions. Click here to secure your account: Secure Login Portal. Failure to verify within 24 hours may result in limited access to your account. Best regards, Security Team",
            
            "Account Verification Required: To maintain the security of your account and prevent unauthorized access, we need you to confirm your details. Please access your account via this link: Account Verification Portal. This is a mandatory security check. Thank you, Account Protection Department",
            
            "Notification: Suspicious login attempt detected from new device. Confirm it was you or secure your account: Security Check Required. Without confirmation, your account may be temporarily locked for protection. Sincerely, Fraud Prevention Team",
            
            # Phishing sophistiqué français
            "Bonjour, Dans le cadre de nos vérifications régulières, un paramétrage de votre compte nécessite une attention particulière. Afin d'éviter toute limitation temporaire de certains services, nous vous invitons à consulter vos paramètres via votre espace personnel ci-dessous : 👉 Accéder à mon espace À défaut de vérification dans les prochains jours, certaines fonctionnalités pourraient être momentanément restreintes, le temps de finaliser le contrôle. Nous vous remercions de votre compréhension. Cordialement, Service assistance Gestion des comptes",
            
            "Alerte Sécurité : Nous avons détecté une activité inhabituelle sur votre compte. Veuillez vérifier votre identité pour éviter toute restriction temporaire. Cliquez ici pour sécuriser votre compte : Connexion Sécurisée. Sans vérification sous 48 heures, l'accès à certaines fonctionnalités pourrait être limité. Cordialement, Équipe de Sécurité",
            
            "Vérification de Compte Requise : Pour garantir la sécurité de votre compte et prévenir tout accès non autorisé, nous avons besoin de confirmer vos informations. Veuillez accéder à votre compte via ce lien : Portail de Vérification. Il s'agit d'un contrôle de sécurité obligatoire. Merci, Département Protection des Comptes",
        ]
        
        # SPAM traditionnels (60%)
        traditional_spam_templates = [
            # Anglais
            "URGENT!!! Your account will be suspended! Click here bit.ly/urgent to verify: bit.ly/verify123",
            "CONGRATULATIONS! You WON $10,000!!! Click NOW bit.ly/winner to claim your prize!!!",
            "Your package is waiting! Download shipping_label.exe to track your delivery!!!",
            "FINAL NOTICE!!! Your subscription expires TODAY! Renew now at bit.ly/renew or lose access!!!",
            "Important document attached: invoice_2024.exe. Please open immediately to process payment.",
            "Security update required! Download antivirus_update.exe to protect your computer from threats.",
            "Hello dear friend! I am prince from Nigeria. I need help transferring $50 MILLION dollars!!! You will get 20%!!!",
            "WORK FROM HOME!!! Make $5000 per week!!! NO EXPERIENCE needed!!! Click here: tinyurl.com/job123",
            "YOU ARE WINNER NUMBER 1000000!!! CLAIM your FREE iPhone NOW!!! LIMITED TIME!!! bit.ly/iphone",
            "Get rich QUICK!!! This ONE simple trick makes $10,000/month!!! Click here NOW!!!",
            
            # Français
            "URGENT!!! Votre compte sera bloqué! Donnez votre numéro de carte maintenant!!!",
            "Votre carte bancaire expire! Envoyez-nous vos coordonnées immédiatement!!!",
            "Confirmez votre identité bancaire sinon votre compte sera fermé!!!",
            "Si vous ne payez pas, nous attaquerons votre système!!!",
            "Payez maintenant ou nous bloquerons tout! bit.ly/paye",
            "GAGNEZ 50000€ MAINTENANT!!! Offre limitée!!! Cliquez bit.ly/gain",
            "Vous avez gagné un iPhone GRATUIT!!! Réclamez-le ici: tinyurl.com/iphone",
            "FÉLICITATIONS! Vous avez gagné 1000€! Cliquez ici pour réclamer: bit.ly/france",
            "Alerte sécurité! Téléchargez anti_virus.exe pour protéger votre ordinateur!",
            "Offre exclusive! Travaillez de chez vous et gagnez 5000€ par mois!",
        ]
        
        # Combiner avec pondération
        phishing_count = int(count * 0.4)  # 40% phishing
        traditional_count = count - phishing_count  # 60% spam traditionnel
        
        # Sélectionner aléatoirement
        emails = []
        for i in range(count):
            if i < phishing_count:
                text = random.choice(phishing_templates)
                email_type = 'phishing_sophisticated'
            else:
                text = random.choice(traditional_spam_templates)
                # ⭐⭐ CORRECTION : Ces lignes DOIVENT ÊTRE DANS LE ELSE
                # Déterminer sous-type
                if any(phrase in text.lower() for phrase in ['bit.ly', 'tinyurl', 'goo.gl']):
                    email_type = 'spam_url'
                elif any(phrase in text.lower() for phrase in ['.exe', '.zip', '.rar']):
                    email_type = 'spam_attachment'
                else:
                    email_type = 'spam_generic'
            
            # ⭐⭐ CORRECTION : BIEN AJOUTER À LA LISTE
            emails.append({
                'text': text,
                'label': 1,  # TRÈS IMPORTANT : 1 pour SPAM
                'type': email_type,
                'subtype': 'phishing' if 'phishing' in email_type else 'traditional'
            })
        
        # Mélanger
        random.shuffle(emails)
        
        # Statistiques
        phishing_emails = sum(1 for e in emails if 'phishing' in e['type'])
        print(f"✅ {phishing_emails} emails de phishing sophistiqué générés")
        print(f"✅ {count - phishing_emails} emails de spam traditionnel générés")
        print(f"✅ Total: {len(emails)} spams générés avec succès")
        
        return emails
    
    
    def _extract_email_body(self, msg):
        """Extrait le corps texte d'un email"""
        body = ""
        
        if msg.is_multipart():
            # Chercher la partie texte
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    try:
                        body = part.get_content()
                        break
                    except:
                        continue
        else:
            # Email simple
            if msg.get_content_type() == 'text/plain':
                try:
                    body = msg.get_content()
                except:
                    pass
        
        # Nettoyer le texte
        if body:
            # Supprimer les réponses et signatures
            lines = body.split('\n')
            cleaned_lines = []
            for line in lines:
                if line.startswith('>') or line.startswith('On ') and 'wrote:' in line:
                    break
                cleaned_lines.append(line)
            body = '\n'.join(cleaned_lines[:20])  # Garder les premières lignes
        
        return body
    
    def _generate_legitimate_emails(self, count: int) -> list:
        """Génère des emails légitimes synthétiques (fallback)"""
        print(f" Génération de {count} emails légitimes synthétiques...")
        
        templates = [
            "Hi {name}, here is the {doc_type} for {period}. Please review and let me know if you have questions. Best regards",
            "Dear {name}, I wanted to follow up on our meeting last {day}. Could we schedule another call for next week?",
            "Hello {name}, the project update is attached. We're on track for the {month} deadline. Thanks for your support.",
            "Good morning {name}, please find the {doc_type} attached. Let me know if you need any clarification.",
            "{name}, I've completed the analysis you requested. The results show positive trends in Q{quarter}.",
            "Hi team, reminder about tomorrow's meeting at {time}. Agenda is attached. See you there!",
            "Dear {name}, thank you for your email. I will review the documents and get back to you by {day}.",
            "Hello, the monthly report is ready. Key highlights: revenue increased by {percent}% compared to last month.",
            "{name}, following up on your request from last week. I've attached the requested information.",
            "Hi {name}, congratulations on the successful project launch! Looking forward to the next phase."
        ]
        
    
        templates = [
          
          "Hi {name}, here is the {doc_type} for {period}. Please review...",
        
          #  Français
          "Bonjour {name}, nous accusons réception de votre {doc_type}. Le traitement est en cours.",
          "Madame, Monsieur, votre dossier a bien été reçu le {date}. Nous vous tiendrons informé.",
           "Objet : Suivi de votre demande. Votre requête est actuellement à l'étude.",
           "Cher collègue, veuillez trouver ci-joint le {doc_type} demandé. Cordialement",
           "Service client : Votre ticket #{number} est en cours de traitement. Merci de votre patience.",
        ]
        names = ["John", "Sarah", "Michael", "Emma", "David", "Lisa", "Robert", "Jennifer", "Tom", "Mary"]
        doc_types = ["report", "presentation", "analysis", "summary", "proposal", "contract"]
        periods = ["Q1", "Q2", "Q3", "Q4", "January", "February", "March", "this quarter"]
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        months = ["January", "February", "March", "April", "May", "June"]
        times = ["9am", "10am", "2pm", "3pm", "4pm"]
        
        emails = []
        for i in range(count):
            template = random.choice(templates)
            text = template.format(
                name=random.choice(names),
                doc_type=random.choice(doc_types),
                period=random.choice(periods),
                day=random.choice(days),
                month=random.choice(months),
                time=random.choice(times),
                quarter=random.randint(1, 4),
                percent=random.randint(5, 25)
            )
            
            emails.append({
                'text': text,
                'label': 0,
                'type': 'synthetic_legitimate'
            })
        
        return emails
    # Dans _generate_spam_emails, ajouter ces nouveaux templates :

    compliance_phishing_templates = [
     # Phishing conformité français
     "Bonjour, Dans le cadre de nos contrôles périodiques de conformité, un point administratif concernant votre profil a été signalé comme nécessitant une vérification complémentaire. Aucune action urgente n'est requise à ce stade. Toutefois, afin d'éviter toute mesure automatique liée à la politique de conformité, nous vous recommandons de consulter votre espace utilisateur lors de votre prochaine connexion. 👉 Accéder à l'espace utilisateur À défaut de consultation, certaines fonctionnalités pourraient être ajustées temporairement conformément aux procédures en vigueur. Cordialement, Cellule conformité Services numériques",
    
     "Objet : Mise à jour de conformité requise Cher utilisateur, Suite à une révision de nos normes de conformité, votre profil nécessite une actualisation. Bien qu'aucune action immédiate ne soit exigée, nous vous invitons à procéder à la mise à jour dans les meilleurs délais pour prévenir toute restriction automatique. 👉 Accéder au portail de conformité En l'absence de mise à jour, l'accès à certaines fonctionnalités pourrait être progressivement limité. Respectueusement, Service Conformité Digitale",
    
     # Phishing conformité anglais
     "Hello, As part of our periodic compliance checks, an administrative point regarding your profile has been flagged as requiring additional verification. No urgent action is required at this stage. However, to avoid any automatic measures related to the compliance policy, we recommend consulting your user space during your next login. 👉 Access user space Without consultation, some features could be temporarily adjusted according to current procedures. Best regards, Compliance Cell Digital Services",
    
     "Subject: Compliance Update Required Dear user, Following a review of our compliance standards, your profile requires updating. While no immediate action is demanded, we invite you to proceed with the update promptly to prevent any automatic restrictions. 👉 Access compliance portal In the absence of an update, access to certain features may be gradually limited. Respectfully, Digital Compliance Service",
    ]
    
    
    
    def download_enron_dataset(self):
        """
        Crée le dataset hybride: vrais emails Enron + spam synthétique
        """
        print("\n Création du dataset hybride...")
        
        # Étape 1: Charger les vrais emails Enron
        legitimate_emails = self._load_real_enron_emails(max_emails=800)
        
        # Étape 2: Si pas assez d'emails Enron, compléter avec des synthétiques
        if len(legitimate_emails) < 400:  # Moins de 400 emails réels
            print(f" Seulement {len(legitimate_emails)} emails Enron trouvés")
            needed = 800 - len(legitimate_emails)
            print(f"   Ajout de {needed} emails légitimes synthétiques...")
            synthetic_emails = self._generate_legitimate_emails(needed)
            legitimate_emails.extend(synthetic_emails)
        else:
            print(f" {len(legitimate_emails)} emails légitimes chargés (vrais Enron)")
        
        # Étape 3: Générer les spams - AUGMENTÉ DE 200 À 400
        spam_emails = self._generate_spam_emails(400)  
        
        # Étape 4: Combiner et mélanger
        all_emails = legitimate_emails + spam_emails
        random.shuffle(all_emails)
        
        # Étape 5: Sauvegarder
        df = pd.DataFrame(all_emails)
        output_file = self.processed_dir / 'enron_hybrid_dataset.csv'
        df.to_csv(output_file, index=False)
        
        # Statistiques
        enron_count = sum(1 for e in all_emails if 'enron' in str(e.get('type', '')))
        synthetic_count = len(all_emails) - enron_count - len(spam_emails)
        
        print(f"\nDataset créé: {output_file}")
        print(f"   Statistiques:")
        print(f"     • Total emails: {len(all_emails)}")
        print(f"     • Vrais emails Enron: {enron_count}")
        print(f"     • Légitimes synthétiques: {synthetic_count}")
        print(f"     • Spams synthétiques: {len(spam_emails)}")
        print(f"     • Ratio spam: {len(spam_emails)/len(all_emails):.1%}")
        
        # Afficher quelques exemples
        print(f"\n   Exemples:")
        for i, email_data in enumerate(all_emails[:3], 1):
            email_type = email_data['type']
            label = "SPAM" if email_data['label'] == 1 else "LEGITIME"
            preview = email_data['text'][:80].replace('\n', ' ')
            print(f"     {i}. [{label}] {email_type}: {preview}...")
        
        return output_file
    
    def load_dataset(self):
        """Charge le dataset préparé"""
        dataset_file = self.processed_dir / 'enron_hybrid_dataset.csv'
        
        if not dataset_file.exists():
            print("Dataset non trouvé, création en cours...")
            dataset_file = self.download_enron_dataset()
        
        df = pd.read_csv(dataset_file)
        
        X = df['text'].tolist()
        y = df['label'].tolist()
        
        return X, y, df
    
    def get_train_test_split(self, test_size=0.2, random_state=42):
        """Retourne train/test split"""
        from sklearn.model_selection import train_test_split
        
        X, y, df = self.load_dataset()
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"\nDataset split:")
        print(f"  • Train: {len(X_train)} emails")
        print(f"  • Test: {len(X_test)} emails")
        
        # Analyse de la distribution
        train_spam = sum(y_train)
        train_ham = len(y_train) - train_spam
        test_spam = sum(y_test)
        test_ham = len(y_test) - test_spam
        
        print(f"  • Train - Légitimes: {train_ham}, Spam: {train_spam} ({train_spam/len(y_train):.1%})")
        print(f"  • Test - Légitimes: {test_ham}, Spam: {test_spam} ({test_spam/len(y_test):.1%})")
        
        return X_train, X_test, y_train, y_test
    
    def get_dataset_info(self):
        """Retourne des informations sur le dataset"""
        try:
            X, y, df = self.load_dataset()
            
            info = {
                'total_emails': len(X),
                'spam_count': sum(y),
                'ham_count': len(y) - sum(y),
                'spam_ratio': sum(y) / len(y),
                'enron_emails': sum(1 for t in df.get('type', []) if 'enron' in str(t)),
                'synthetic_emails': sum(1 for t in df.get('type', []) if 'synthetic' in str(t)),
                'avg_text_length': np.mean([len(str(text)) for text in X]) if X else 0,
            }
            
            return info
        except:
            return {}


# Test du dataset manager
if __name__ == "__main__":
    print(" Test du DatasetManager avec maildir...")
    
    dm = DatasetManager()
    
    # Vérifier si maildir existe
    if dm.enron_dir.exists():
        print(f" maildir trouvé: {dm.enron_dir.absolute()}")
        
        # Tester le chargement de quelques emails
        print("\nTest de chargement des emails Enron...")
        emails = dm._load_real_enron_emails(max_emails=10)
        
        if emails:
            print(f"\n {len(emails)} emails chargés avec succès")
            print(f"\nExemple d'email Enron:")
            print("-" * 50)
            print(emails[0]['text'][:200] + "...")
            print(f"Type: {emails[0]['type']}")
        else:
            print(" Aucun email Enron chargé")
            print("\nCréation d'un dataset synthétique...")
            dm.download_enron_dataset()
    else:
        print(f" maildir NON trouvé dans: {dm.enron_dir.absolute()}")
        print("   Création d'un dataset entièrement synthétique...")
        dm.download_enron_dataset()
    
    # Charger et splitter le dataset
    print("\n\n Chargement et split du dataset...")
    X_train, X_test, y_train, y_test = dm.get_train_test_split()


