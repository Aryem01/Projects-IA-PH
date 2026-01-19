import re

class HeuristicRules:
    def __init__(self):
   
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
            '.vbs', '.js', '.jar', '.msi', '.dmg', '.app', '.apk',
            '.vbe', '.jse', '.wsf', '.hta', '.lnk',
        ]
        
       
        self.suspicious_url_patterns = [
            r'bit\.ly/', r'tinyurl\.com/', r'goo\.gl/',
            r't\.co/', r'ow\.ly/', r'is\.gd/', r'cli\.gs/',
            r'bc\.vc/', r'adf\.ly/', r'ouo\.io/',
            r'short\.ly/', r'cutt\.ly/', r'shorturl\.at/',
        ]
        
        
        self.spam_keywords =[
           
            'win money', 'free money', 'gagner argent', 'argent gratuit',
            'cash prize', 'lottery winner', 'gagnant loterie',
            'claim prize', 'réclamer prix', 'winner selected',
            
            
            'act now', 'click now', 'limited time', 'expire today',
            'maintenant', 'urgent action', 'dernière chance',
            'expires today', 'expire demain', 'action immédiate',
            
           
            'account suspended', 'compte suspendu', 'compte bloqué',
            'account blocked', 'will be closed', 'sera fermé',
            
          
            'congratulations winner', 'félicitations gagnant',
            'you won', 'vous avez gagné', 'selected winner',
            'free iphone', 'iphone gratuit', 'free gift',
            
           
            'activité inhabituelle', 'unusual activity', 'suspicious activity',
            'vérifier vos informations', 'verify your information', 'verify account',
            'accéder à mon espace', 'access your account', 'login to verify',
            'sécurisé', 'secured', 'secure access',
            'interruption de service', 'service interruption', 'account limited',
            'sous 48 heures', 'within 48 hours', 'dans les 24 heures',
            'action requise', 'action required', 'immediate action',
            
           
            'regular security review', 'vérifications régulières',
            'configuration detail', 'paramétrage de votre compte',
            'service limitations', 'limitation temporaire',
            'personal area', 'espace personnel',
            'temporarily unavailable', 'momentanément restreintes',
            'access my account', 'accéder à mon espace',
            'support services', 'service assistance',
            'account management', 'gestion des comptes',
            
            
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
            
            
            'vérification de compte',
            'compte nécessaire',
            'validation requise',
            'mise à jour nécessaire',
            'problème de sécurité',
            'activité suspecte',
            'connexion inhabituelle',
            'sécuriser votre compte',
            'votre compte a été',
            'accès à votre compte',
            'action nécessaire',
            'mesures nécessaires',
            'cher client',
            'cher utilisateur',
            
           
            'kill you', 'i will kill', 'je vais tuer',
            'hurt you', 'i will hurt', 'je vais blesser',
            'attack you', 'i will attack', 'je vais attaquer',
            'threat', 'menace', 'danger', 'dangereux',
            'violence', 'violent', 'weapon', 'arme',
            'give me or', 'donne moi ou', 'give me or else',
            'if you don\'t give', 'si tu ne donnes pas',
            'or i will', 'ou je vais', 'otherwise i', 'sinon je',
            'i will harm', 'je vais nuire', 'harm you', 'te nuire',
            'bad things', 'mauvaises choses', 'regret', 'regretter',
            'sorry', 'désolé', 'consequences', 'conséquences',
            'pay the price', 'payer le prix', 'suffer', 'souffrir',
            'destroy you', 'détruire toi', 'break you', 'casser toi',
            'make you pay', 'te faire payer', 'you will die', 'tu vas mourir',
            'going to kill', 'vais tuer', 'going to hurt', 'vais blesser',
        ]
        
        
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
            'facture', 'devis', 'commande', 'contrat', 
            'réunion', 'meeting', 'appel', 'conférence',  
            'rapport', 'présentation', 'analyse', 'budget',  
            
    
            'suivi de votre demande', 'prise en charge',
            'finalisation du traitement', 'bien été prise en charge',
            'vous sera communiqué', 'retour vous sera communiqué',
            'demande a bien été', 'votre demande a été',
            'notre service', 'par notre service',
            'dès que possible', 'dès finalisation',
            'en attente de traitement', 'traitement en cours',
            'nous traitons votre demande', 'votre requête',
            'suivi de dossier', 'numéro de suivi',
            'pour information', 'pour votre information',
            'en copie', 'cc :', 'c.c :',
        ]
        
       
        self.threat_patterns = [
           
            r'sinon\s+(nous|je|on)\s+(bloqu|ferm|supprim)',
            r'if\s+you\s+don\'?t.*?(suspend|block|close)',
            r'compte\s+(sera|va être)\s+(fermé|bloqué|suspendu)',
            r'compte\s+(sera|va etre)\s+(ferme|bloque|suspendu)',
            r'account\s+will\s+be\s+(suspended|closed|blocked)',
            r'dernier\s+(avertissement|rappel|délai)',
            r'dernier\s+(avertissement|rappel|delai)',
            r'final\s+(warning|notice|reminder)',
            
            
            r'sans\s+action.*?(sous|dans|avant).*?(heure|jour)',
            r'(without|unless).*?action.*?(hour|day)',
            r'fonctionnalités?\s+(seront?|pourrai(en)?t\s+être)\s+(limitées?|restreintes?|bloquées?)',
            r'(service|account|features?)\s+(will\s+be|may\s+be)\s+(limited|restricted|suspended)',
            r'éviter.*?(interruption|suspension|blocage)',
            r'(avoid|prevent).*?(interruption|suspension|closure)',
            
            
            r'afin d\'éviter toute mesure automatique',
            r'to avoid any automatic measures',
            r'pourraient être ajustées temporairement',
            r'could be temporarily adjusted',
            r'conformément aux procédures en vigueur',
            r'according to current procedures',
            r'à défaut de consultation',
            r'without consultation',
            
           
            r'i will\s+(kill|hurt|harm|attack|destroy)\s+you',
            r'je vais\s+(tuer|blesser|nuire|attaquer|détruire)\s+(toi|vous)',
            r'if you don\'t\s+.*?\s+i will',
            r'si tu ne\s+.*?\s+je vais',
            r'give me\s+.*?\s+or\s+i will',
            r'donne moi\s+.*?\s+ou\s+je vais',
            r'or i will\s+(kill|hurt|harm)',
            r'ou je vais\s+(tuer|blesser|nuire)',
            r'otherwise\s+i will\s+.*?(bad|harm|hurt)',
            r'sinon\s+je vais\s+.*?(mal|blesser|nuire)',
            r'threaten\s+to\s+(kill|hurt|harm)',
            r'menace\s+de\s+(tuer|blesser|nuire)',
            r'make you\s+(suffer|regret|pay)',
            r'faire\s+(souffrir|regretter|payer)',
            r'you will\s+(regret|suffer|die)',
            r'tu vas\s+(regretter|souffrir|mourir)',
            
          
            r'give me (money|cash|argent|bitcoin) or',
            r'donne moi (argent|bitcoin|monnaie) ou',
            r'send me (money|funds) or else',
            r'envoie moi (argent|fonds) sinon',
            r'pay me or i will',
            r'paye moi ou je vais',
            r'transfer (money|bitcoin) or',
            r'transfère (argent|bitcoin) ou',
            r'send.*?or i will.*?(kill|hurt)',
            r'envoie.*?ou je vais.*?(tuer|blesser)',
        ]
        
        self.indirect_phishing_patterns = [
            
            r'vérification\s+(de\s+)?(votre\s+)?compte\s+(est\s+)?(nécessaire|requise|obligatoire)',
            r'validation\s+(de\s+)?(votre\s+)?compte\s+(est\s+)?(nécessaire|requise)',
            r'mise\s+à\s+jour\s+(de\s+)?(vos\s+)?informations',
            r'actualisation\s+(de\s+)?(votre\s+)?profil',
            r'problème\s+(de\s+)?sécurité\s+(avec\s+)?(votre\s+)?compte',
            r'activité\s+suspecte\s+(sur\s+)?(votre\s+)?compte',
            r'connexion\s+inhabituelle\s+(à\s+)?(votre\s+)?compte',
            r'votre\s+compte\s+(a\s+été|est)\s+(signalé|flagé|noté)',
            r'action\s+(est\s+)?(requise|nécessaire|obligatoire)',
            r'mesures\s+(sont\s+)?(nécessaires|requises|obligatoires)',
            r'étapes\s+(sont\s+)?(à\s+suivre|requises|nécessaires)',
            
            
            r'cher\s+(client|utilisateur|membre|abonné)',
            r'dear\s+(customer|user|member|subscriber)',
            
            
            r'pour\s+(des\s+)?raisons\s+(de\s+)?sécurité',
            r'for\s+security\s+reasons',
            r'afin\s+de\s+(protéger|sécuriser)\s+votre\s+compte',
            r'to\s+(protect|secure)\s+your\s+account',
        ]
        
       
        self.violent_threat_patterns = [
           
            r'\bkill\s+(you|u|ya)\b',
            r'\btuer\s+(toi|vous)\b',
            r'\bmurder\s+(you|him|her)\b',
            r'\bassassin(er)?\s+(toi|vous)\b',
            
     
            r'\bhurt\s+(you|u)\b',
            r'\bblesser\s+(toi|vous)\b',
            r'\battack\s+(you|u)\b',
            r'\battaquer\s+(toi|vous)\b',
            
           
            r'if\s+.*?\s+(don\'t|do not)\s+.*?\s+(kill|hurt|harm)',
            r'si\s+.*?\s+(ne|n\')\s+.*?\s+(tuer|blesser|nuire)',
            r'unless\s+.*?\s+(kill|hurt|harm)',
            r'\à\s+moins\s+que\s+.*?\s+(tuer|blesser|nuire)',
            
            r'give\s+.*?\s+or\s+.*?\s+(kill|hurt|harm)',
            r'donne\s+.*?\s+ou\s+.*?\s+(tuer|blesser|nuire)',
            r'pay\s+.*?\s+or\s+.*?\s+(kill|hurt)',
            r'paye\s+.*?\s+ou\s+.*?\s+(tuer|blesser)',
            
            
            r'you will\s+(die|suffer|regret)',
            r'tu vas\s+(mourir|souffrir|regretter)',
            r'bad things\s+will\s+happen',
            r'il va\s+(t\'arriver|vous arriver)\s+malheur',
        ]
        
      
        self.rule_triggers = {
            'dangerous_attachment': 0,
            'suspicious_url': 0,
            'spam_keywords': 0,
            'excessive_punctuation': 0,
            'excessive_caps': 0,
            'threats': 0,
            'money_amounts': 0,
            'phishing_sophisticated': 0,
            'phishing_indirect': 0,
            'short_suspicious': 0,
            'no_reference': 0,
            'violent_threats': 0, 
        }
        
        self.min_keywords_for_spam = 2
        self.caps_ratio_threshold = 0.6
    
    def check_extreme_threats(self, email_text):
        """Vérification ultra-rapide pour les menaces extrêmes"""
        email_lower = email_text.lower()
        
        # Liste des menaces extrêmes qui doivent être bloquées immédiatement
        extreme_threats = [
            'kill you', 'i will kill', 'going to kill',
            'tuer toi', 'je vais tuer', 'vais te tuer',
            'hurt you', 'i will hurt', 'going to hurt',
            'blesser toi', 'je vais blesser',
            'give me or i will', 'donne moi ou je vais',
            'or i will kill', 'ou je vais tuer',
            'if you don\'t i will', 'si tu ne je vais',
            'i\'ll kill you', 'j\'vais te tuer',
            'make you die', 'te faire mourir',
            'you will die', 'tu vas mourir',
        ]
        
        for threat in extreme_threats:
            if threat in email_lower:
                self.rule_triggers['violent_threats'] += 1
                return True, f"Menace extrême détectée: '{threat}'"
        
        return False, ""
    
    def check_violent_threats(self, email_text):
        """Détecte spécifiquement les menaces de violence et extorsion"""
        email_lower = email_text.lower()
        
       
        threat_score = 0
        signals = []
        
        
        violent_words = [
            'kill', 'tuer', 'murder', 'assassin',
            'hurt', 'blesser', 'harm', 'nuire',
            'attack', 'attaquer', 'beat', 'battre',
            'destroy', 'détruire', 'break', 'casser',
            'die', 'mourir', 'death', 'mort',
        ]
        
        for word in violent_words:
            if word in email_lower:
                threat_score += 2
                signals.append(f"mot_violent: {word}")
        
       
        for pattern in self.violent_threat_patterns:
            if re.search(pattern, email_lower):
                threat_score += 3
                signals.append("pattern_menace_violente")
                break
     
        extortion_patterns = [
            r'give me (money|bitcoin|cash|argent) or i will',
            r'donne moi (argent|bitcoin|monnaie) ou je vais',
            r'send me (money|funds) or else',
            r'envoie moi (argent|fonds) sinon',
            r'pay me or i will',
            r'paye moi ou je vais',
            r'transfer .*? or i will',
            r'transfère .*? ou je vais',
        ]
        
        for pattern in extortion_patterns:
            if re.search(pattern, email_lower):
                threat_score += 4
                signals.append("extorsion_menace")
                break
        
        
        conditional_patterns = [
            r'if you don\'t .*? i will .*? (kill|hurt|harm|attack)',
            r'si tu ne .*? je vais .*? (tuer|blesser|nuire|attaquer)',
            r'unless you .*? i will .*? (kill|hurt|attack)',
            r'\à moins que tu .*? je vais .*? (tuer|blesser|attaquer)',
        ]
        
        for pattern in conditional_patterns:
            if re.search(pattern, email_lower):
                threat_score += 3
                signals.append("condition_menaçante")
                break
        
       
        personal_threats = [
            ('i will', 'kill you'), ('i will', 'hurt you'),
            ('je vais', 'te tuer'), ('je vais', 'te blesser'),
            ('i\'ll', 'kill you'), ('i\'ll', 'hurt you'),
            ('j\'vais', 'te tuer'), ('j\'vais', 'te blesser'),
        ]
        
        for pronoun, action in personal_threats:
            if pronoun in email_lower and action in email_lower:
                threat_score += 5
                signals.append(f"menace_personnelle: {pronoun} {action}")
                break
        
       
        consequence_words = ['regret', 'suffer', 'pay', 'consequences',
                           'regretter', 'souffrir', 'payer', 'conséquences',
                           'bad things', 'mauvaises choses', 'malheur']
        
        consequence_count = 0
        for word in consequence_words:
            if word in email_lower:
                consequence_count += 1
        
        if consequence_count >= 2:
            threat_score += 2
            signals.append(f"conséquences_multiples: {consequence_count}")
        
      
        if threat_score >= 4:
            self.rule_triggers['violent_threats'] += 1
            reason_parts = [f"Score menace: {threat_score}"]
            if signals:
                reason_parts.append(f"Signaux: {', '.join(signals[:3])}")
            return True, " | ".join(reason_parts)
        
        return False, ""
    
    def check_dangerous_attachments(self, email_text):
        """
        Détecte les VRAIES menaces de pièces jointes
        """
        email_lower = email_text.lower()
        
       
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
        
      
        for pattern in safe_discussion_patterns:
            if re.search(pattern, email_lower):
                return False  
        
      
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
        
        
        legitimate_score = 0
        for pattern in self.french_legitimate_patterns:
            if pattern in email_lower:
                legitimate_score += 1
        
        
        if legitimate_score >= 2:
    
            required_keywords = 3
        else:
            required_keywords = self.min_keywords_for_spam
        
       
        count = 0
        found_keywords = []
        
        for keyword in self.spam_keywords:
          
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, email_lower):
                count += 1
                found_keywords.append(keyword)
        
        if count >= required_keywords:
            self.rule_triggers['spam_keywords'] += 1
            return True
        
        return False
    
    def check_excessive_punctuation(self, email_text):
        """Détecte la ponctuation excessive (!!!, ???, ...)"""
       
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
        """Détecte les majuscules excessives"""
        if len(email_text) < 30:  
            return False
        
        letters = [c for c in email_text if c.isalpha()]
        if len(letters) < 20: 
            return False
        
        caps_count = sum(1 for c in letters if c.isupper())
        caps_ratio = caps_count / len(letters)
        
    
        if caps_ratio > self.caps_ratio_threshold:
            self.rule_triggers['excessive_caps'] += 1
            return True
        return False
    
    def check_threats(self, email_text):
        """Détecte les menaces et fausses urgences - VERSION AMÉLIORÉE"""
        email_lower = email_text.lower()
        
        
        for pattern in self.threat_patterns:
            if re.search(pattern, email_lower):
                self.rule_triggers['threats'] += 1
                return True
        
        
        violent_phrases = [
            # Menaces de mort
            'i will kill you', 'kill you', 'going to kill',
            'je vais te tuer', 'te tuer', 'vais te tuer',
            'you will die', 'tu vas mourir',
            
            # Menaces de violence
            'i will hurt you', 'hurt you', 'going to hurt',
            'je vais te blesser', 'te blesser', 'vais te blesser',
            'break your', 'casser ton', 'casser votre',
            
            # Extorsion
            'give me or i will', 'give me or else',
            'donne moi ou je vais', 'donne moi sinon',
            'send money or', 'envoie argent ou',
            
            # Menaces implicites
            'bad things will happen', 'il va t\'arriver malheur',
            'you will regret', 'tu vas regretter',
            'make you suffer', 'te faire souffrir',
        ]
        
        for phrase in violent_phrases:
            if phrase in email_lower:
                self.rule_triggers['threats'] += 1
                return True
       
        if_then_patterns = [
            r'if you (don\'t|do not) .*? (i will|i\'ll) .*? (kill|hurt|harm|attack)',
            r'si tu (ne|n\') .*? (je vais|j\'vais) .*? (tuer|blesser|nuire|attaquer)',
            r'unless you .*? (i will|i\'ll) .*? (kill|hurt)',
            r'\à moins que tu .*? (je vais) .*? (tuer|blesser)',
        ]
        
        for pattern in if_then_patterns:
            if re.search(pattern, email_lower):
                self.rule_triggers['threats'] += 1
                return True
        
        return False
    
    def check_money_amounts(self, email_text):
        """
        Détecte les montants d'argent suspects 
        Seulement les GROS montants ou combinés avec mots-clés spam
        """
        
        big_money_patterns = [
            r'[\$€]\s*\d{4,}', 
            r'\d{4,}\s*[\$€]\s*[\$DA]\s*[\$da]',  
            r'\d+\s*(million|milliard|thousand|mille)\s*(dollars?|euros?|DZD?)',
        ]
        
        for pattern in big_money_patterns:
            if re.search(pattern, email_text, re.IGNORECASE):
                
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
        
       
        limitation_phrases = [
            'service limitations', 'temporarily unavailable',
            'features may be temporarily unavailable', 'limited access',
            'limitation temporaire', 'fonctionnalités pourraient être restreintes',
            'certains services pourraient être limités', 'restricted access',
            'temporary restrictions', 'restrictions temporaires'
        ]
        
        for phrase in limitation_phrases:
            if phrase in email_lower:
                phishing_score += 2 
        
        time_pressure = [
            'within the next few days', 'in the next few days',
            'dans les prochains jours', 'sous 48 heures', 'under 48 hours',
            'within 24 hours', 'dans les 24 heures', 'as soon as possible',
            'dès que possible', 'urgent attention'
        ]
        
        for phrase in time_pressure:
            if phrase in email_lower:
                phishing_score += 1
        
        
        link_indicators = ['👉', 'lien ci-dessous', 'link below', 'cliquez ici', 'click here',
                          'suivant le lien', 'via le lien', 'formulaire ci-dessous',
                          'bouton ci-dessous', 'button below', '🔗']
        
        for indicator in link_indicators:
            if indicator in email_lower:
                phishing_score += 2
                break
        
    
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
        
       
        has_reference = any(word in email_lower for word in 
                           ['reference', 'ticket', 'case', 'dossier', 'numéro', '#', 'id:', 'ref:'])
       
        has_specific_contact = any(word in email_lower for word in
                                  ['john', 'sarah', 'michael', 'david', 'lisa',  
                                   'mr.', 'ms.', 'm.', 'madame', 'monsieur'])  
        
      
        if not has_reference:
            phishing_score += 1
        
        if not has_specific_contact and phishing_score >= 2:
            phishing_score += 1
        
        
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
                break 
        
        
        if 'aucune action urgente' in email_lower or 'no urgent action' in email_lower:
            if 'pourraient être ajustées' in email_lower or 'could be adjusted' in email_lower:
                phishing_score += 3
                signals.append("contradiction_urgence_mesure")

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
      
        if '👉' in email_text and any(word in email_lower for word in ['accéder', 'access', 'consulter', 'consult']):
            phishing_score += 3
            signals.append("lien_avec_emoji")
        
        
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
        
       
        if not any(pattern in email_lower for pattern in ['votre dossier', 'votre compte', 'référence', 'ticket', 'case', '#']):
            phishing_score += 2
            signals.append("absence_reference")
        
        
        if phishing_score >= 6:
            self.rule_triggers['phishing_sophisticated'] = self.rule_triggers.get('phishing_sophisticated', 0) + 1
            return True, f"Phishing conformité détecté: {', '.join(signals)}"
        
        return False, ""
    
    def check_passive_threats(self, email_text):
        """Détecte les menaces passives (pourraient, pourrait être)"""
        email_lower = email_text.lower()
        
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
                
                if any(word in email_lower for word in ['👉', 'cliquez', 'click', 'accéder', 'access']):
                    return True, "Menace passive avec appel à action détectée"
        
        return False, ""
    
    def check_indirect_phishing(self, email_text):
        """Détecte le phishing indirect/subtil"""
        email_lower = email_text.lower()
        
       
        indirect_score = 0
        for pattern in self.indirect_phishing_patterns:
            if re.search(pattern, email_lower):
                indirect_score += 2
        
       
        if len(email_text) < 150: 
            short_suspicious_terms = [
                'vérification', 'compte', 'nécessaire', 'requis',
                'sécurité', 'action', 'urgence', 'important',
                'validation', 'mise à jour', 'problème',
            ]
            
            term_count = 0
            for term in short_suspicious_terms:
                if term in email_lower:
                    term_count += 1
            
            if term_count >= 2:
                indirect_score += 2
        
       
        has_legitimate_reference = any(pattern in email_lower for pattern in [
            'référence', 'ticket', 'dossier', 'numéro', '#', 
            'facture', 'devis', 'commande', 'contrat',
            'rapport', 'présentation', 'meeting', 'réunion'
        ])
        
        if not has_legitimate_reference and indirect_score > 0:
            indirect_score += 2
            self.rule_triggers['no_reference'] += 1
        
        
        has_generic_call = any(pattern in email_lower for pattern in [
            'cher client', 'cher utilisateur', 'dear customer', 'dear user'
        ])
        
        has_specific_call = any(pattern in email_lower for pattern in [
            'madame', 'monsieur', 'm.', 'mr.', 'ms.',
            'john', 'sarah', 'michael', 'david', 'lisa'
        ])
        
        if has_generic_call and not has_specific_call:
            indirect_score += 1
        
     
        if indirect_score >= 5:
            self.rule_triggers['phishing_indirect'] += 1
            return True, f"Phishing indirect détecté (score: {indirect_score})"
        
        return False, ""
    
    def check_short_suspicious_email(self, email_text):
        """Détecte les emails courts mais suspects"""
        if len(email_text) < 120:  
            email_lower = email_text.lower()
            
           
            suspicious_in_short = [
                'vérification de compte',
                'compte nécessaire',
                'action requise',
                'sécurité',
                'urgence',
                'important',
                'cliquez',
                'lien',
                'accéder',
            ]
            
            count = 0
            for term in suspicious_in_short:
                if term in email_lower:
                    count += 1
            
            if count >= 2:
                self.rule_triggers['short_suspicious'] += 1
                return True, f"Email court mais suspect ({count} indicateurs)"
        
        return False, ""
    def is_clearly_ham(self, email_text):
 
     email_lower = email_text.lower()
     if 'je me permets de vous contacter' in email_lower:
         if 'projet' in email_lower and 'respectueusement' in email_lower:
              return True, "Email professionnel de suivi"
    
   
     if ('bonjour' in email_lower or 'monsieur' in email_lower or 'madame' in email_lower) and \
       ('respectueusement' in email_lower or 'cordialement' in email_lower):
 
        professional_keywords = ['projet', 'document', 'réunion', 'information', 'dossier', 
                                'traitement', 'service', 'client', 'demande']
        if any(keyword in email_lower for keyword in professional_keywords):
            
            spam_indicators = ['!!!', '???', 'gratuit', 'gagner', 'urgent!', 'bit.ly', 'tinyurl']
            if not any(indicator in email_lower for indicator in spam_indicators):
                return True, "Email professionnel avec formules de politesse"
    
    
     if any(ref in email_lower for ref in ['référence', 'dossier n°', 'numéro', '#', 'ref:']) and \
       'cordialement' in email_lower:
        return True, "Email administratif avec référence"
    
   
     if len(email_text) < 200:
        if 'bonjour' in email_lower and ('cordialement' in email_lower or 'merci' in email_lower):
            # Vérifier que ce n'est pas un spam
            if not any(spam in email_lower for spam in ['!!!', '???', 'gagner', 'gratuit']):
                if any(pro in email_lower for pro in ['projet', 'document', 'réunion']):
                    return True, "Courte communication professionnelle"
    
     return False, ""
 
    def apply_rules(self, email_text):
       
  
     is_ham, ham_reason = self.is_clearly_ham(email_text)
     if is_ham:
        return False, f"Email légitime détecté: {ham_reason}"
    
   
     is_extreme_threat, extreme_reason = self.check_extreme_threats(email_text)
     if is_extreme_threat:
         return True, extreme_reason
    
  
     is_ham, ham_reason = self.is_clearly_ham(email_text)
     if is_ham:
            return False, f"Email légitime: {ham_reason}"
        
        
     is_extreme_threat, extreme_reason = self.check_extreme_threats(email_text)
     if is_extreme_threat:
            return True, extreme_reason
        
      
     is_violent_threat, violent_reason = self.check_violent_threats(email_text)
     if is_violent_threat:
            return True, violent_reason
        
       
     if self.check_dangerous_attachments(email_text):
            return True, "Pièce jointe dangereuse détectée (.exe, .zip avec action suspecte)"
        
   
     if self.check_suspicious_urls(email_text):
            return True, "URL raccourcie suspecte détectée (bit.ly, tinyurl, etc.)"
        
    
     if self.check_threats(email_text):
            return True, "Menace ou ultimatum détecté"
    
     is_compliance_phishing, compliance_reason = self.check_compliance_phishing(email_text)
     if is_compliance_phishing:
            return True, compliance_reason
        
       
     is_indirect_phishing, indirect_reason = self.check_indirect_phishing(email_text)
     if is_indirect_phishing:
            return True, indirect_reason
        
       
     is_short_suspicious, short_reason = self.check_short_suspicious_email(email_text)
     if is_short_suspicious:
            return True, short_reason
        
       
     is_passive_threat, passive_reason = self.check_passive_threats(email_text)
     if is_passive_threat:
            return True, passive_reason
        
       
     if self.check_phishing_sophisticated(email_text):
            return True, "Tentative de phishing sophistiquée détectée"
    
     signals = 0
     reasons = []
        
     if self.check_money_amounts(email_text):
            signals += 1
            reasons.append("gros montant d'argent")
        
     if self.check_spam_keywords(email_text):
            signals += 2
            reasons.append("mots-clés spam multiples")
        
     if self.check_excessive_caps(email_text):
            signals += 1
            reasons.append("majuscules excessives")
        
     if self.check_excessive_punctuation(email_text):
            signals += 1
            reasons.append("ponctuation excessive")
        
       
     if signals >= 2:
            return True, f"Signaux spam combinés: {', '.join(reasons)}"
        
       
     return False, ""
    
    def get_statistics(self):
        """Retourne les statistiques de déclenchement des règles"""
        return self.rule_triggers.copy()
    
    def reset_statistics(self):
        """Réinitialise les statistiques"""
        for key in self.rule_triggers:
            self.rule_triggers[key] = 0
            
               
    def _is_general_professional_email(self, email_text):
  
        email_lower = email_text.lower()
 
        score = 0
        
        
        positive_keywords = [
            'projet', 'github', 'dépôt', 'code', 'collaboration', 'conseils',
            'compte rendu', 'réunion', 'modifications', 'intégrées',
            'vérifier', 'retour', 'nécessaire', 'travail', 'équipe',
            'développement', 'ia', 'ai', 'programmation', 'logiciel',
            'document', 'pièce jointe', 'fichier', 'rapport', 'analyse',
            'mise à jour', 'update', 'avancement', 'progression',
            'feedback', 'retour', 'review', 'revue', 'commentaires',
            'tâche', 'mission', 'objectif', 'délai', 'échéance',
            'réunion', 'meeting', 'conférence', 'présentation',
            'client', 'collègue', 'manager', 'équipe', 'service'
        ]
        
        positive_count = 0
        for keyword in positive_keywords:
            if keyword in email_lower:
                positive_count += 1
                score += 1
        

        if 'bonjour' in email_lower or 'hello' in email_lower or 'hi ' in email_lower:
            score += 2
            if any(end in email_lower for end in ['cordialement', 'bien cordialement', 'merci', 'sincerely', 'regards', 'best regards']):
                score += 3
        

        if 'objet :' in email_lower or 'subject:' in email_lower:
            score += 2
        
        spam_indicators = [
            '!!!', '???', '...', '!!', '??',
            'gratuit', 'free', 'gagner', 'win', 'winner',
            'argent', 'money', 'cash', '€', '$',
            'urgent!', 'urgent', 'immédiat', 'immediate',
            'cliquez', 'click', 'bit.ly', 'tinyurl', 'goo.gl',
            'gagnez', 'winner', 'lottery', 'loterie',
            'limited time', 'temps limité', 'offer ends', 'offre se termine'
        ]
        
        spam_count = 0
        for indicator in spam_indicators:
            if indicator in email_lower:
                spam_count += 1
                score -= 3 
        
       
        length = len(email_text)
        if 100 <= length <= 2000:   
            score += 2
        elif length < 100: 
          
            if positive_count >= 2 and 'bonjour' in email_lower:
                score += 1
        

        polite_words = ['merci', 'thank you', 'thanks', 'cordialement', 'sincerely', 
                       'regards', 'best regards', 'salutations', 'kind regards']
        if any(polite in email_lower for polite in polite_words):
            score += 2
        
   
        threat_words = ['tuer', 'kill', 'donne', 'give me', 'send me', 'envoie moi',
                       'money', 'argent', 'bitcoin', 'crypto', 'payer', 'pay',
                       'sinon', 'or else', 'otherwise', 'i will', 'je vais']
        has_threats = any(threat in email_lower for threat in threat_words)
        
        if not has_threats:
            score += 2
  
        if any(ref in email_lower for ref in ['projet', 'project', 'réf', 'ref', '#', 'numéro', 'number']):
            score += 1

        if score >= 7 and spam_count <= 1:  
            self.rule_triggers['professional_work'] = self.rule_triggers.get('professional_work', 0) + 1
            return True, f"Email professionnel détecté (score: {score}, {positive_count} mots-clés positifs)"
        
        return False, ""

    def _check_short_professional_email(self, email_text):
   
        if len(email_text) < 150:   
            email_lower = email_text.lower()
            
            has_structure = (('bonjour' in email_lower or 'hello' in email_lower) and 
                           any(end in email_lower for end in ['cordialement', 'merci', 'thanks', 'regards']))
            
            if not has_structure:
                return False, ""
            
            
            professional_terms = [
                'projet', 'project', 'réunion', 'meeting', 
                'document', 'document', 'code', 'github', 
                'travail', 'work', 'équipe', 'team',
                'update', 'mise à jour', 'feedback', 'retour'
            ]
            pro_term_count = sum(1 for term in professional_terms if term in email_lower)
            
          
            spam_terms = ['!!!', '???', 'urgent!', 'gratuit', 'free', 'gagner', 'win', 'cliquez ici', 'click here']
            has_spam_terms = any(term in email_lower for term in spam_terms)
            
            if has_structure and pro_term_count >= 1 and not has_spam_terms:
                self.rule_triggers['short_professional'] = self.rule_triggers.get('short_professional', 0) + 1
                return True, f"Email professionnel court ({pro_term_count} termes professionnels)"
        
        return False, ""

    def _force_professional_detection(self, email_text):
    
        """
        Détection FORCÉE pour emails clairement professionnels
        """
        email_lower = email_text.lower()
        
       
        if 'ci-joint' in email_lower or 'ci joint' in email_lower:
            if 'cordialement' in email_lower and ('bonjour' in email_lower or 'veuillez' in email_lower):
                return True, "Email formel avec pièce jointe"
        
      
        if 'veuillez trouver' in email_lower and 'cordialement' in email_lower:
            return True, "Formulation formelle 'Veuillez trouver'"
        
       
        if 'votre disposition' in email_lower and 'cordialement'and ' Respectueusement ' in email_lower:
            return True, "Formulation professionnelle de disponibilité"
        email_lower = email_text.lower()
        
       
        if 'github' in email_lower and 'projet' in email_lower:
            if 'bonjour' in email_lower and ('cordialement' in email_lower or 'merci' in email_lower):
                return True, "Email projet GitHub détecté"
        
        if ('compte rendu' in email_lower or 'réunion' in email_lower) and 'points' in email_lower:
            if 'bonjour' in email_lower and len(email_text) > 80:
                return True, "Compte rendu réunion détecté"
        
        if 'objet :' in email_lower:
   
            lines = email_text.split('\n')
            for line in lines:
                if 'objet :' in line.lower():
                    subject = line.lower()
                  
                    professional_subjects = ['projet', 'mise à jour', 'update', 'réunion', 'meeting', 
                                           'rapport', 'report', 'document', 'code', 'développement']
                    if any(keyword in subject for keyword in professional_subjects):
                        if 'bonjour' in email_lower:
                            return True, f"Email avec sujet professionnel: {subject[:50]}..."
        
        return False, ""
if __name__ == "__main__":
    print(" Test des règles améliorées avec détection de menaces violentes...\n")
    
    rules = HeuristicRules()
    
    test_emails = [
       
        ("give me monney if you don't give it i will kill you", True),
        ("give me money or i will hurt you", True),
        ("donne moi l'argent sinon je vais te tuer", True),
        ("send bitcoin or i will attack you", True),
        ("if you don't pay i will kill your family", True),
        ("je vais te blesser si tu ne donnes pas", True),
        ("pay me $1000 or i will destroy you", True),
        ("transfer the money or you will regret", True),
        ("bonjour Une vérification de votre compte est nécessaire", True),
        ("Cher client, une action est requise pour votre compte", True),
        ("Notification: problème de sécurité détecté sur votre compte", True),
        
       
        ("Bonjour, votre dossier #12345 est en traitement", False),
        ("Madame Dupont, voici le rapport demandé pour la réunion", False),
        ("Facture #F2024001 en pièce jointe", False),
        ("Please review the attached document for tomorrow's meeting", False),
        
        
        ("Subject: Suivi de votre demande\n\nBonjour,\n\nVotre demande a bien été prise en charge par notre service.\nUn retour vous sera communiqué dès finalisation du traitement.\n\nCordialement,\nService administratif", False),
        
        
        ("Bonjour,\n\nVotre demande est en attente de traitement.\nNous vous répondrons dès que possible.\n\nBien cordialement,\nService client", False),
        ("Suite à votre demande du 15/01/2024, nous traitons votre requête.\nNuméro de suivi: REF-2024-00123", False),
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
    
    
    print("\n" + "="*80)
    print("TEST SPÉCIFIQUE DE VOTRE CAS:")
    print("="*80)
    email = "give me monney if you don't give it i will kill you"
    is_spam, reason = rules.apply_rules(email)
    print(f"Email: {email}")
    print(f"Résultat: {'🚫 SPAM' if is_spam else '✅ LÉGITIME'}")
    print(f"Raison: {reason}")
    
    print("\n" + "="*80)
    print("TEST DE L'EMAIL LÉGITIME:")
    print("="*80)
    email_legitime = """Bonjour,

Votre demande a bien été prise en charge par notre service.
Un retour vous sera communiqué dès finalisation du traitement.

Cordialement,
Service administratif"""
    is_spam, reason = rules.apply_rules(email_legitime)
    print(f"Email: {email_legitime}")
    print(f"Résultat: {'🚫 SPAM' if is_spam else '✅ LÉGITIME'}")
    print(f"Raison: {reason}")
    print("="*80)
