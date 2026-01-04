"""
Règles heuristiques pour la détection de spam 
"""
import re

class HeuristicRules:
    def __init__(self):
        # 1. EXTENSIONS DANGEREUSES
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
            '.vbs', '.js', '.jar', '.msi', '.dmg', '.app', '.apk',
            '.vbe', '.jse', '.wsf', '.hta', '.lnk',
        ]
        
        # 2. URLs SUSPECTES (raccourcisseurs)
        self.suspicious_url_patterns = [
            r'bit\.ly/', r'tinyurl\.com/', r'goo\.gl/',
            r't\.co/', r'ow\.ly/', r'is\.gd/', r'cli\.gs/',
            r'bc\.vc/', r'adf\.ly/', r'ouo\.io/',
            r'short\.ly/', r'cutt\.ly/', r'shorturl\.at/',
        ]
        
        # 3. MOTS-CLÉS SPAM (Anglais + Français) 
        self.spam_keywords =[
            # Gains / Argent (forte suspicion)
            'win money', 'free money', 'gagner argent', 'argent gratuit',
            'cash prize', 'lottery winner', 'gagnant loterie',
            'claim prize', 'réclamer prix', 'winner selected',
            
            # Urgence extrême
            'act now', 'click now', 'limited time', 'expire today',
            'maintenant', 'urgent action', 'dernière chance',
            'expires today', 'expire demain', 'action immédiate',
            
            # Menaces directes
            'account suspended', 'compte suspendu', 'compte bloqué',
            'account blocked', 'will be closed', 'sera fermé',
            
            # Spam évident
            'congratulations winner', 'félicitations gagnant',
            'you won', 'vous avez gagné', 'selected winner',
            'free iphone', 'iphone gratuit', 'free gift',
            
            # NOUVEAU: Phishing sophistiqué
            'activité inhabituelle', 'unusual activity', 'suspicious activity',
            'vérifier vos informations', 'verify your information', 'verify account',
            'accéder à mon espace', 'access your account', 'login to verify',
            'sécurisé', 'secured', 'secure access',
            'interruption de service', 'service interruption', 'account limited',
            'sous 48 heures', 'within 48 hours', 'dans les 24 heures',
            'action requise', 'action required', 'immediate action',
            
            # AJOUT: Phrases de phishing sophistiqué
            'regular security review', 'vérifications régulières',
            'configuration detail', 'paramétrage de votre compte',
            'service limitations', 'limitation temporaire',
            'personal area', 'espace personnel',
            'temporarily unavailable', 'momentanément restreintes',
            'access my account', 'accéder à mon espace',
            'support services', 'service assistance',
            'account management', 'gestion des comptes',
            # AJOUTER CES NOUVEAUX:
            'contrôles périodiques',
            'point administratif',
            'vérification complémentaire',
            'mesure automatique',
            'politique de conformité',
            'espace utilisateur',
            'prochaine connexion',
            'cellule conformité',
            'services numériques',
            'periodic checks',
            'administrative point',
            'additional verification',
            'automatic measures',
            'compliance policy',
            'user space',
            'next login',
            'compliance cell',
            'digital services',

        ]
        
        # 4. MOTS LÉGITIMES FRANÇAIS 
        self.french_legitimate_patterns = [
            'bonne réception', 'accusons réception', 'en cours de traitement',
            'cordialement', 'bien cordialement', 'veuillez agréer',
            'madame', 'monsieur', 'cher collègue', 'chère équipe',
            'service client', 'service administratif',
            'dossier transmis', 'pièce jointe', 'ci-joint',
            'informations complémentaires', 'merci de votre',
            'nous vous informons', 'suite à votre demande',
            'objet : suivi', 'votre demande', 'ticket #',
            'référence', 'case #', 'numéro de dossier',
        ]
        
        # 5. PATTERNS DE MENACES (plus précis)
        self.threat_patterns = [
            # Menaces directes
            r'sinon\s+(nous|je|on)\s+(bloqu|ferm|supprim)',
            r'if\s+you\s+don\'?t.*?(suspend|block|close)',
            r'compte\s+(sera|va être)\s+(fermé|bloqué|suspendu)',
            r'compte\s+(sera|va etre)\s+(ferme|bloque|suspendu)',
            r'account\s+will\s+be\s+(suspended|closed|blocked)',
            r'dernier\s+(avertissement|rappel|délai)',
            r'dernier\s+(avertissement|rappel|delai)',
            r'final\s+(warning|notice|reminder)',
            
            #  Menaces indirectes (phishing)
            r'sans\s+action.*?(sous|dans|avant).*?(heure|jour)',
            r'(without|unless).*?action.*?(hour|day)',
            r'fonctionnalités?\s+(seront?|pourrai(en)?t\s+être)\s+(limitées?|restreintes?|bloquées?)',
            r'(service|account|features?)\s+(will\s+be|may\s+be)\s+(limited|restricted|suspended)',
            r'éviter.*?(interruption|suspension|blocage)',
            r'(avoid|prevent).*?(interruption|suspension|closure)',
            # AJOUTER CES NOUVEAUX:
            r'afin d\'éviter toute mesure automatique',
            r'to avoid any automatic measures',
            r'pourraient être ajustées temporairement',
            r'could be temporarily adjusted',
            r'conformément aux procédures en vigueur',
            r'according to current procedures',
            r'à défaut de consultation',
            r'without consultation',
        ]
        
        # 6. STATISTIQUES DES RÈGLES
        self.rule_triggers = {
            'dangerous_attachment': 0,
            'suspicious_url': 0,
            'spam_keywords': 0,
            'excessive_punctuation': 0,
            'excessive_caps': 0,
            'threats': 0,
            'money_amounts': 0,
            'phishing_sophisticated': 0,  #  phishing sophistiqué
        }
        
        # 7. CONFIGURATION
        self.min_keywords_for_spam = 2
        self.caps_ratio_threshold = 0.6
    
    def check_dangerous_attachments(self, email_text):
        """
        Détecte les VRAIES menaces de pièces jointes (VERSION CORRIGÉE)
        """
        email_lower = email_text.lower()
        
        # Patterns qui indiquent une discussion LÉGITIME sur .exe
        safe_discussion_patterns = [
            r'rapport.*\.exe',
            r'document.*\.exe',
            r'fichier.*\.exe',
            r'extension.*\.exe',
            r'format.*\.exe',
            r'le\s+fichier.*\.exe',
            r'un\s+fichier.*\.exe',
            r'des\s+fichiers.*\.exe',
            r'\.exe\s+(file|format|extension)',
        ]
        
        # Vérifier SI une discussion légitime
        for pattern in safe_discussion_patterns:
            if re.search(pattern, email_lower):
                return False  # C'est sûr, juste une discussion
        
        # Patterns dangereux RÉELS 
        dangerous_action_patterns = [
            r'download\s+\w*\.exe',
            r'click\s+\w*\.exe',
            r'open\s+\w*\.exe',
            r'run\s+\w*\.exe',
            r'install\s+\w*\.exe',
            r'télécharge\w*\s+\w*\.exe',
            r'ouvre\w*\s+\w*\.exe',
            r'exécute\w*\s+\w*\.exe',
        ]
        
        for pattern in dangerous_action_patterns:
            if re.search(pattern, email_lower):
                self.rule_triggers['dangerous_attachment'] += 1
                return True
        
        # Vérifier les archives suspectes avec actions
        archive_patterns = [
            r'download.*\.(zip|rar|7z)',
            r'télécharge.*\.(zip|rar|7z)',
            r'click.*\.(zip|rar|7z)',
        ]
        
        for pattern in archive_patterns:
            if re.search(pattern, email_lower):
                self.rule_triggers['dangerous_attachment'] += 1
                return True
        
        return False
    
    def check_suspicious_urls(self, email_text):
        """Vérifie la présence d'URLs raccourcies suspectes"""
        for pattern in self.suspicious_url_patterns:
            if re.search(pattern, email_text, re.IGNORECASE):
                self.rule_triggers['suspicious_url'] += 1
                return True
        return False
    
    def check_spam_keywords(self, email_text):
        """
        Compte les mots-clés spam 
        Ignore les patterns légitimes français
        """
        email_lower = email_text.lower()
        
        #  Vérifier d'abord si c'est un email légitime français
        legitimate_score = 0
        for pattern in self.french_legitimate_patterns:
            if pattern in email_lower:
                legitimate_score += 1
        
        # Si 2+ patterns légitimes détectés, être plus tolérant
        if legitimate_score >= 2:
            # Augmenter le seuil pour ces emails
            required_keywords = 3
        else:
            required_keywords = self.min_keywords_for_spam
        
        # Compter les mots-clés spam
        count = 0
        found_keywords = []
        
        for keyword in self.spam_keywords:
            if keyword in email_lower:
                count += 1
                found_keywords.append(keyword)
        
        if count >= required_keywords:
            self.rule_triggers['spam_keywords'] += 1
            return True
        
        return False
    
    def check_excessive_punctuation(self, email_text):
        """Détecte la ponctuation excessive (!!!, ???, ...)"""
        # Plus strict : au moins 3 répétitions
        patterns = [
            r'!{4,}',      # !!!! (4+)
            r'\?{4,}',     # ???? (4+)
            r'\.{5,}',     # ..... (5+)
        ]
        
        for pattern in patterns:
            if re.search(pattern, email_text):
                self.rule_triggers['excessive_punctuation'] += 1
                return True
        return False
    
    def check_excessive_caps(self, email_text):
        """Détecte les majuscules excessives (VERSION AMÉLIORÉE)"""
        if len(email_text) < 30:  
            return False
        
        letters = [c for c in email_text if c.isalpha()]
        if len(letters) < 20:  # Pas assez de lettres
            return False
        
        caps_count = sum(1 for c in letters if c.isupper())
        caps_ratio = caps_count / len(letters)
        
        # Seuil augmenté pour réduire faux positifs
        if caps_ratio > self.caps_ratio_threshold:
            self.rule_triggers['excessive_caps'] += 1
            return True
        return False
    
    def check_threats(self, email_text):
        """Détecte les menaces et fausses urgences (VERSION AMÉLIORÉE)"""
        email_lower = email_text.lower()
        
        # Vérifier les patterns de menaces directs
        for pattern in self.threat_patterns:
            if re.search(pattern, email_lower):
                self.rule_triggers['threats'] += 1
                return True
        
        return False
    
    def check_money_amounts(self, email_text):
        """
        Détecte les montants d'argent suspects 
        Seulement les GROS montants ou combinés avec mots-clés spam
        """
        # Patterns pour gros montants seulement
        big_money_patterns = [
            r'[\$€]\s*\d{4,}', 
            r'\d{4,}\s*[\$€]\s*[\$DA]\s*[\$da]',  
            r'\d+\s*(million|milliard|thousand|mille)\s*(dollars?|euros?|DZD?)',
        ]
        
        for pattern in big_money_patterns:
            if re.search(pattern, email_text, re.IGNORECASE):
                # Vérifier si combiné avec mots spam
                email_lower = email_text.lower()
                spam_money_words = ['win', 'gagner', 'free', 'gratuit', 'prize', 'prix']
                
                for word in spam_money_words:
                    if word in email_lower:
                        self.rule_triggers['money_amounts'] += 1
                        return True
        
        return False
    
    def check_phishing_sophisticated(self, email_text):
        """
        Détecte les emails de phishing sophistiqués
        Ces emails imitent des communications légitimes mais contiennent des signaux suspects
        """
        email_lower = email_text.lower()
        
        phishing_score = 0
        
        security_phrases = [
            'security review', 'security check', 'verification required',
            'configuration detail', 'account settings', 'personal area',
            'vérifications régulières', 'paramétrage de votre compte',
            'espace personnel', 'accéder à mon espace', 'access my account',
            'regular security', 'vérification de sécurité'
        ]
        
        for phrase in security_phrases:
            if phrase in email_lower:
                phishing_score += 1
        
        # 2. Menace voilée de limitation
        limitation_phrases = [
            'service limitations', 'temporarily unavailable',
            'features may be temporarily unavailable', 'limited access',
            'limitation temporaire', 'fonctionnalités pourraient être restreintes',
            'certains services pourraient être limités', 'restricted access',
            'temporary restrictions', 'restrictions temporaires'
        ]
        
        for phrase in limitation_phrases:
            if phrase in email_lower:
                phishing_score += 2  # Plus grave
      
        time_pressure = [
            'within the next few days', 'in the next few days',
            'dans les prochains jours', 'sous 48 heures', 'under 48 hours',
            'within 24 hours', 'dans les 24 heures', 'as soon as possible',
            'dès que possible', 'urgent attention'
        ]
        
        for phrase in time_pressure:
            if phrase in email_lower:
                phishing_score += 1
        
        # 4. Lien caché ou emoji de lien
        link_indicators = ['👉', 'lien ci-dessous', 'link below', 'cliquez ici', 'click here',
                          'suivant le lien', 'via le lien', 'formulaire ci-dessous',
                          'bouton ci-dessous', 'button below', '🔗']
        
        for indicator in link_indicators:
            if indicator in email_lower:
                phishing_score += 2
                break
        
        # 5. Signature générique
        generic_signatures = [
            'support services', 'account management team',
            'service assistance', 'gestion des comptes',
            'customer support', 'technical team', 'security team',
            'équipe de sécurité', 'équipe support',
            'account department', 'département comptes'
        ]
        
        for signature in generic_signatures:
            if signature in email_lower:
                phishing_score += 1
        
        # 6. Absence d'informations spécifiques
        # Les vrais emails de service ont des références
        has_reference = any(word in email_lower for word in 
                           ['reference', 'ticket', 'case', 'dossier', 'numéro', '#', 'id:', 'ref:'])
        
        # 7. Pas de nom de contact spécifique
        has_specific_contact = any(word in email_lower for word in
                                  ['john', 'sarah', 'michael', 'david', 'lisa',  
                                   'mr.', 'ms.', 'm.', 'madame', 'monsieur'])  
        
        # Calcul final
        if not has_reference:
            phishing_score += 1
        
        if not has_specific_contact and phishing_score >= 2:
            phishing_score += 1
        
        # Déclencher si 4 points ou plus (seuil sensible)
        if phishing_score >= 4:
            self.rule_triggers['phishing_sophisticated'] = self.rule_triggers.get('phishing_sophisticated', 0) + 1
            return True
        
        return False
    
    def check_compliance_phishing(self, email_text):
        """Détecte le phishing utilisant le jargon de conformité"""
        email_lower = email_text.lower()
        
        phishing_score = 0
        signals = []
        
        compliance_phrases = [
            'contrôles périodiques de conformité',
            'point administratif concernant votre profil',
            'vérification complémentaire',
            'mesure automatique liée à la politique',
            'procédures en vigueur',
            'cellule conformité',
            'periodic compliance checks',
            'administrative point regarding your profile',
            'additional verification required',
            'automatic measures according to policy',
            'current procedures',
            'compliance cell'
        ]
        
        for phrase in compliance_phrases:
            if phrase in email_lower:
                phishing_score += 2
                signals.append(f"jargon_compliance: {phrase}")
                break  # Un seul suffit
        
        # 2. Contradiction interne ("aucune action urgente" mais menace implicite)
        if 'aucune action urgente' in email_lower or 'no urgent action' in email_lower:
            if 'pourraient être ajustées' in email_lower or 'could be adjusted' in email_lower:
                phishing_score += 3
                signals.append("contradiction_urgence_mesure")
        
        # 3. Menace voilée sous forme de "recommandation"
        threat_patterns = [
            r'afin d\'éviter toute mesure automatique',
            r'to avoid any automatic measures',
            r'certaines fonctionnalités pourraient être ajustées',
            r'some features could be adjusted',
            r'conformément aux procédures en vigueur',
            r'according to current procedures'
        ]
        
        for pattern in threat_patterns:
            if re.search(pattern, email_lower):
                phishing_score += 2
                signals.append("menace_voilee")
                break
        
        # 4. Lien avec emoji + appel à action
        if '👉' in email_text and any(word in email_lower for word in ['accéder', 'access', 'consulter', 'consult']):
            phishing_score += 3
            signals.append("lien_avec_emoji")
        
        # 5. Signature générique de service
        generic_services = [
            'cellule conformité',
            'services numériques',
            'compliance cell',
            'digital services',
            'administrative unit',
            'compliance department'
        ]
        
        for service in generic_services:
            if service in email_lower:
                phishing_score += 1
                signals.append(f"service_generique: {service}")
                break
        
        # 6. Absence totale de référence personnelle
        if not any(pattern in email_lower for pattern in ['votre dossier', 'votre compte', 'référence', 'ticket', 'case', '#']):
            phishing_score += 2
            signals.append("absence_reference")
        
        # Seuil de détection pour ce type sophistiqué
        if phishing_score >= 6:
            self.rule_triggers['phishing_sophisticated'] = self.rule_triggers.get('phishing_sophisticated', 0) + 1
            return True, f"Phishing conformité détecté: {', '.join(signals)}"
        
        return False, ""
    
    def check_passive_threats(self, email_text):
        """Détecte les menaces passives (pourraient, pourrait être)"""
        email_lower = email_text.lower()
        
        # Patterns de menaces passives
        passive_threat_patterns = [
            r'pourraient\s+être\s+(ajustées?|limitée?s?|restreintes?|modifiées?)',
            r'could\s+be\s+(adjusted|limited|restricted|modified)',
            r'afin d\'éviter\s+(toute|des)\s+mesures?',
            r'to avoid\s+(any|some)\s+measures?',
            r'conformément aux\s+(procédures|règles)',
            r'according to\s+(procedures|rules|policies)'
        ]
        
        for pattern in passive_threat_patterns:
            if re.search(pattern, email_lower):
                # Vérifier si combiné avec appel à action
                if any(word in email_lower for word in ['👉', 'cliquez', 'click', 'accéder', 'access']):
                    return True, "Menace passive avec appel à action détectée"
        
        return False, ""
    
    # CORRECTION : UNE SEULE méthode apply_rules BIEN INDENTÉE
    def apply_rules(self, email_text):
        """
        Applique toutes les règles heuristiques 
        Ordre d'exécution optimisé pour réduire faux positifs
        """
        # 1. Pièces jointes dangereuses (très fiable)
        if self.check_dangerous_attachments(email_text):
            return True, "Pièce jointe dangereuse détectée (.exe, .zip avec action suspecte)"
        
        # 2. URLs suspectes (fiable)
        if self.check_suspicious_urls(email_text):
            return True, "URL raccourcie suspecte détectée (bit.ly, tinyurl, etc.)"
        
        # 3. NOUVEAU: Phishing conformité sophistiqué
        is_compliance_phishing, compliance_reason = self.check_compliance_phishing(email_text)
        if is_compliance_phishing:
            return True, compliance_reason
        
        # 4. NOUVEAU: Menaces passives
        is_passive_threat, passive_reason = self.check_passive_threats(email_text)
        if is_passive_threat:
            return True, passive_reason
        
        # 5. Phishing sophistiqué général
        if self.check_phishing_sophisticated(email_text):
            return True, "Tentative de phishing sophistiquée détectée"
        
        # 6. Menaces directes (fiable)
        if self.check_threats(email_text):
            return True, "Menace ou ultimatum détecté"
        
        # 7. Combinaison de signaux (plus prudent)
        signals = 0
        reasons = []
        
        if self.check_money_amounts(email_text):
            signals += 1
            reasons.append("gros montant d'argent")
        
        if self.check_spam_keywords(email_text):
            signals += 2  # Poids plus important
            reasons.append("mots-clés spam multiples")
        
        if self.check_excessive_caps(email_text):
            signals += 1
            reasons.append("majuscules excessives")
        
        if self.check_excessive_punctuation(email_text):
            signals += 1
            reasons.append("ponctuation excessive")
        
        # Déclencher seulement si 2+ signaux
        if signals >= 2:
            return True, f"Signaux spam combinés: {', '.join(reasons)}"
        
        # Aucune règle déclenchée
        return False, ""
    
    def get_statistics(self):
        """Retourne les statistiques de déclenchement des règles"""
        return self.rule_triggers.copy()
    
    def reset_statistics(self):
        """Réinitialise les statistiques"""
        for key in self.rule_triggers:
            self.rule_triggers[key] = 0


# TEST
if __name__ == "__main__":
    print(" Test des règles améliorées avec phishing...\n")
    
    rules = HeuristicRules()
    
    test_emails = [
        # Phishing sophistiqué 
        ("Hello,As part of our regular security review, we identified a configuration detail that may require your attention.To avoid any potential service limitations, we recommend reviewing your account settings at your convenience by accessing your personal area below:👉 Access my accountIf the review is not completed within the next few days, certain features may be temporarily unavailable until verification is finalized.Thank you for your understanding,Support ServicesAccount Management Team", True),
        
        ("Bonjour,Dans le cadre de nos vérifications régulières, un paramétrage de votre compte nécessite une attention particulière.Afin d'éviter toute limitation temporaire de certains services, nous vous invitons à consulter vos paramètres via votre espace personnel ci-dessous :👉 Accéder à mon espaceÀ défaut de vérification dans les prochains jours, certaines fonctionnalités pourraient être momentanément restreintes, le temps de finaliser le contrôle.Nous vous remercions de votre compréhension.Cordialement,Service assistanceGestion des comptes", True),
        
        # LÉGITIMES 
        ("Dear user, your ticket #12345 has been received. We will process it within 24 hours. You can check status at our support portal. Sincerely, Customer Support", False),
        
        ("Bonjour, nous accusons réception de votre dossier #REF789. Le traitement est en cours. Cordialement, Service Client", False),
        
        # SPAM évidents
        ("URGENT!!! Download virus.exe NOW!!! Click bit.ly/xxx", True),
        ("WIN 10000 DZD FREE MONEY!!! Click bit.ly/scam NOW!!!", True),
    ]
    
    correct = 0
    for email, expected in test_emails:
        is_spam, reason = rules.apply_rules(email)
        status = "✅" if is_spam == expected else "❌"
        correct += (is_spam == expected)
        
        print(f"{status} {'SPAM' if expected else 'LÉGIT'}: {email[:60]}...")
        print(f"   Résultat: {'SPAM' if is_spam else 'LÉGIT'}")
        if reason:
            print(f"   Raison: {reason}")
        print()
    
    print(f"\n Précision: {correct}/{len(test_emails)} ({correct/len(test_emails)*100:.1f}%)")