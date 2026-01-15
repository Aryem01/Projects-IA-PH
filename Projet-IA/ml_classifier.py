"""
Classifieur ML avec Support Français Complet - VERSION AMÉLIORÉE
Détection améliorée des emails administratifs légitimes
"""

import pickle
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from typing import List, Tuple, Dict, Optional, Any
import time

class MLClassifier:
    def __init__(self, max_features: int = 3000, ngram_range: tuple = (1, 2), 
                 alpha: float = 0.1, language: str = 'french',  
                 administrative_boost: float = 0.3):
        """
        Initialise le classifieur ML avec support amélioré du français
        
        Args:
            max_features: Nombre maximum de features TF-IDF
            ngram_range: Plage de n-grams (ex: (1,2) pour unigrams+bigrams)
            alpha: Paramètre de lissage pour Naive Bayes
            language: Langue ('french', 'english', ou 'both')
            administrative_boost: Réduction de probabilité spam pour emails administratifs
        """
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.alpha = alpha
        self.language = language
        self.administrative_boost = administrative_boost
        
        stop_words = self._get_stopwords(language)
        
        
        
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=max_features,
                min_df=2,
                max_df=0.85,
                ngram_range=ngram_range,
                stop_words=stop_words,
                sublinear_tf=True,
                strip_accents='unicode',
                analyzer='word',
            )),
            ('classifier', MultinomialNB(alpha=alpha))
        ])
        
        
        self.is_trained = False
        self.training_info = {}
        self.class_names = ['legitimate', 'spam']
        
       
        self.administrative_patterns = self._initialize_administrative_patterns()
    
    def _initialize_administrative_patterns(self) -> Dict[str, Any]:
        """Initialise les patterns pour détection d'emails administratifs"""
        return {
            'clear_indicators': [
                'suivi de votre demande',
                'demande a bien été prise en charge',
                'retour vous sera communiqué dès finalisation',
                'cordialement, service administratif',
                'bonne réception de votre demande',
                'accusons réception de votre demande',
                'en cours de traitement',
                'votre dossier est en traitement',
                'nous traitons votre demande',
            ],
            'structure_patterns': [
                (r'bonjour.*cordialement', 0.5),
                (r'madame.*monsieur.*cordialement', 0.6),
                (r'cher.*client.*cordialement', 0.5),
                (r'bonjour.*service.*cordialement', 0.5),
            ],
            'content_keywords': [
                'service', 'administratif', 'client', 'demande', 'traitement',
                'dossier', 'référence', 'cordialement', 'bonjour', 'madame',
                'monsieur', 'prise en charge', 'finalisation', 'réponse',
                'informations', 'document', 'pièce jointe',
            ],
            'professional_phrases': [
                'veuillez agréer',
                'bien cordialement',
                'dans l\'attente de votre retour',
                'pour toute information complémentaire',
                'nous restons à votre disposition',
                'en vous remerciant',
                'sincères salutations',
            ]
        }
    
    def _get_stopwords(self, language: str) -> Optional[List[str]]:
        """Retourne la liste des stopwords selon la langue"""
        if language == 'english':
            return 'english'
        elif language == 'french':
            # Liste étendue de stopwords français 
            french_stopwords = {
                # Articles
                'le', 'la', 'les', 'l', 'un', 'une', 'des', 'du', 'de',
                # Prépositions
                'à', 'au', 'aux', 'en', 'dans', 'sur', 'sous', 'avec', 'sans',
                'pour', 'par', 'vers', 'chez', 'contre', 'entre',
                # Conjonctions
                'et', 'ou', 'mais', 'donc', 'or', 'ni', 'car',
                # Pronoms (conserver certains pour contexte)
                # 'je', 'tu', 'il', 'elle', 'nous', 'vous', 'ils', 'elles',
                'me', 'te', 'se', 'lui', 'leur', 'moi', 'toi', 'soi',
                'ce', 'cet', 'cette', 'ces', 'celui', 'celle', 'ceux', 'celles',
                'mon', 'ton', 'son', 'ma', 'ta', 'sa', 'mes', 'tes', 'ses',
                'notre', 'votre', 'leur', 'nos', 'vos', 'leurs',
                # Verbes auxiliaires (conserver pour structure)
                # 'être', 'est', 'sont', 'était', 'été', 'suis', 'es', 'sommes', 'êtes',
                # 'avoir', 'a', 'ai', 'as', 'avons', 'avez', 'ont', 'eu',
                # Mots fréquents neutres
                'que', 'qui', 'quoi', 'quel', 'quelle', 'quels', 'quelles',
                'où', 'quand', 'comment', 'pourquoi',
                'tout', 'tous', 'toute', 'toutes',
                'plus', 'moins', 'très', 'bien', 'pas', 'ne', 'non',
                'si', 'oui', 'comme', 'aussi', 'encore',
            }
            return list(french_stopwords)
        elif language == 'both':
            # Combinaison anglais + français
            french = self._get_stopwords('french')
            return french
        else:
            return None
    
    def preprocess_text(self, text: str, advanced: bool = True) -> str:
        """
        Prétraite le texte pour l'analyse ML - VERSION AMÉLIORÉE
        Protège les patterns administratifs légitimes
        """
        if not text or not isinstance(text, str):
            return ""
        
  
        text = text.lower()
        
        if advanced:
          
            protective_patterns = {
              
                'suivi de votre demande': ' LEGIT_FOLLOWUP_REQUEST ',
                'prise en charge par notre service': ' LEGIT_SERVICE_HANDLING ',
                'retour vous sera communiqué': ' LEGIT_RESPONSE_PROMISE ',
                'dès finalisation du traitement': ' LEGIT_PROCESS_COMPLETION ',
                'service administratif': ' LEGIT_ADMIN_SERVICE ',
                'en cours de traitement': ' LEGIT_IN_PROCESS ',
                'bonne réception': ' LEGIT_ACKNOWLEDGMENT ',
                'accusons réception': ' LEGIT_FORMAL_ACKNOWLEDGMENT ',
                
               
                'cordialement': ' PROFESSIONAL_SIGNATURE ',
                'bien cordialement': ' PROFESSIONAL_SIGNATURE_WARM ',
                'veuillez agréer': ' PROFESSIONAL_CLOSING ',
                
             
                'référence numéro': ' LEGIT_REFERENCE_NUMBER ',
                'numéro de dossier': ' LEGIT_CASE_NUMBER ',
                'numéro de ticket': ' LEGIT_TICKET_NUMBER ',
                
               
                'pour toute information complémentaire': ' PROFESSIONAL_OFFER_ASSISTANCE ',
                'nous restons à votre disposition': ' PROFESSIONAL_AVAILABILITY ',
            }
            
            for pattern, token in protective_patterns.items():
                text = text.replace(pattern, token)
            
          
            
            important_words = {
                'service': ' SERVICE_TERM ',
                'administratif': ' ADMINISTRATIVE_TERM ',
                'client': ' CLIENT_TERM ',
                'demande': ' REQUEST_TERM ',
                'traitement': ' PROCESSING_TERM ',
                'dossier': ' CASE_TERM ',
                'facture': ' INVOICE_TERM ',
                'devis': ' QUOTE_TERM ',
                'contrat': ' CONTRACT_TERM ',
            }
            
            for word, token in important_words.items():
                text = re.sub(r'\b' + word + r'\b', token, text)
            
           
            text = re.sub(r'bit\.ly/\S+|tinyurl\.com/\S+|goo\.gl/\S+', ' SUSPICIOUS_SHORTURL ', text)
            text = re.sub(r'https?://\S+|www\.\S+', ' GENERIC_URL ', text)
            
           
            text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' EMAIL_ADDRESS ', text)
            
           
            text = re.sub(r'\b\d{6,}\b', ' LONG_NUMBER_REF ', text)
            
            text = re.sub(r'\b[A-Z]{2,}\d{3,}\b', ' CODE_REFERENCE ', text)
            text = re.sub(r'\b\d{3,}[A-Z]{2,}\b', ' CODE_REFERENCE ', text)
            
            
            text = re.sub(r'[\$€£]\s*\d{5,}', ' LARGE_MONEY_AMOUNT ', text)  
            text = re.sub(r'[\$€£]\s*\d{1,4}', ' SMALL_MONEY_AMOUNT ', text)  
            
           
            threat_indicators = {
                'urgent': ' URGENCY_INDICATOR ',
                'immédiat': ' IMMEDIACY_INDICATOR ',
                'important': ' IMPORTANCE_INDICATOR ',
                'dernière chance': ' LAST_CHANCE_INDICATOR ',
                'limited time': ' TIME_LIMIT_INDICATOR ',
                'expire today': ' EXPIRATION_INDICATOR ',
            }
            
            for indicator, token in threat_indicators.items():
                text = re.sub(r'\b' + indicator + r'\b', token, text)
            
            
            phishing_tokens = {
                '👉': ' LINK_ARROW_INDICATOR ',
                '🔗': ' LINK_CHAIN_INDICATOR ',
                'cliquez ici': ' CLICK_HERE_PHRASE ',
                'click here': ' CLICK_HERE_ENGLISH ',
                'accéder à mon espace': ' ACCOUNT_ACCESS_FRENCH ',
                'access my account': ' ACCOUNT_ACCESS_ENGLISH ',
                'vérification de sécurité': ' SECURITY_CHECK_FRENCH ',
                'security verification': ' SECURITY_CHECK_ENGLISH ',
            }
            
            for indicator, token in phishing_tokens.items():
                text = text.replace(indicator, token)
            
           
            text = re.sub(r'([!?.]){4,}', r'\1\1\1', text)  
            
          
            text = re.sub(r'[^\w\s.!?,;:àâäæçéèêëïîôùûüÿœÀÂÄÆÇÉÈÊËÏÎÔÙÛÜŸ]', ' ', text)
            

            if re.search(r'bonjour.*cordialement', text, re.DOTALL):
                text += ' PROFESSIONAL_EMAIL_STRUCTURE '
            
            if re.search(r'madame.*monsieur', text, re.DOTALL):
                text += ' FORMAL_ADDRESS_STRUCTURE '
            
           
            text = re.sub(r'\s+', ' ', text)
            
           
            words = text.split()
            important_short_words = {'a', 'i', 'y', 'à', 'ou', 'et', 'or', 'of', 'in', 'to', 'de', 'la', 'le'}
            words = [w for w in words if len(w) > 1 or w in important_short_words]
            text = ' '.join(words)
        
        return text.strip()
    
    def _is_clearly_administrative(self, email_text: str) -> bool:
        """
        Détecte les emails clairement administratifs (sans ambiguïté)
        Retourne True pour forcer classification légitime
        """
        email_lower = email_text.lower()
        
      
        for indicator in self.administrative_patterns['clear_indicators']:
            if indicator in email_lower:
                return True
        
     
        structure_score = 0
        for pattern, points in self.administrative_patterns['structure_patterns']:
            if re.search(pattern, email_lower, re.DOTALL):
                structure_score += points
        
        if structure_score >= 1.0:
            return True
        
        
        content_keywords_found = 0
        for keyword in self.administrative_patterns['content_keywords']:
            if keyword in email_lower:
                content_keywords_found += 1
        
        professional_phrases_found = 0
        for phrase in self.administrative_patterns['professional_phrases']:
            if phrase in email_lower:
                professional_phrases_found += 1
        
       
        if content_keywords_found >= 5 and professional_phrases_found >= 1:
            return True
        
        if content_keywords_found >= 3 and 'service administratif' in email_lower:
            return True
        
        return False
    
    def _calculate_administrative_score(self, email_text: str) -> float:
        """
        Calcule un score d'authenticité administrative (0-3)
        Plus le score est élevé, plus l'email est probablement légitime
        """
        email_lower = email_text.lower()
        score = 0.0
        
      
        if re.search(r'^bonjour', email_lower):
            score += 0.2
        if re.search(r'cordialement$', email_lower) or re.search(r'cordialement\s*$', email_lower):
            score += 0.3
        if re.search(r'madame.*monsieur', email_lower):
            score += 0.2
        if re.search(r'cher.*client', email_lower):
            score += 0.3
        
       
        professional_terms = ['service', 'administratif', 'client', 'demande', 'traitement', 
                            'dossier', 'référence', 'facture', 'devis', 'contrat']
        term_count = sum(1 for term in professional_terms if term in email_lower)
        score += min(1.0, term_count * 0.15)
        
       
        if re.search(r'\b#?\d{4,}\b', email_lower):  
            score += 0.3
        if re.search(r'\b[A-Z]{2,}\d{3,}\b|\b\d{3,}[A-Z]{2,}\b', email_lower):  
            score += 0.2
        
      
        professional_phrases = [
            'en cours de traitement',
            'prise en charge',
            'retour vous sera communiqué',
            'nous traitons votre',
            'votre demande a été',
        ]
        for phrase in professional_phrases:
            if phrase in email_lower:
                score += 0.1
        
        return min(3.0, score)
    
    def train(self, X_train: List[str], y_train: List[int], 
              X_val: Optional[List[str]] = None, y_val: Optional[List[int]] = None) -> Dict:
        """
        Entraîne le modèle ML avec gestion des données déséquilibrées
        """
        print(f" Début de l'entraînement (langue: {self.language})...")
        start_time = time.time()
        
        if len(X_train) != len(y_train):
            raise ValueError(f"X_train ({len(X_train)}) et y_train ({len(y_train)}) doivent avoir la même taille")
        
     
        spam_count = sum(y_train)
        ham_count = len(y_train) - spam_count
        
        print(f"  • Données d'entraînement: {len(X_train)} emails")
        print(f"  • Légitimes: {ham_count}, Spams: {spam_count}")
        print(f"  • Ratio spam: {spam_count/len(y_train):.1%}")
        
        
        print("   Prétraitement des textes...")
        X_train_processed = [self.preprocess_text(text) for text in X_train]
        
       
        valid_indices = [i for i, text in enumerate(X_train_processed) if text.strip()]
        X_train_processed = [X_train_processed[i] for i in valid_indices]
        y_train = [y_train[i] for i in valid_indices]
        
        print(f"  • Textes valides après prétraitement: {len(X_train_processed)}")
        
       
        print("   Entraînement du modèle Naive Bayes...")
        self.pipeline.fit(X_train_processed, y_train)
        self.is_trained = True
        
     
        train_predictions = self.pipeline.predict(X_train_processed)
        train_accuracy = np.mean(train_predictions == y_train)
        
        training_time = time.time() - start_time
        
       
        self.training_info = {
            'train_size': len(X_train_processed),
            'train_accuracy': train_accuracy,
            'training_time_seconds': training_time,
            'feature_count': self.get_feature_count(),
            'vocabulary_size': len(self.pipeline.named_steps['tfidf'].vocabulary_),
            'data_distribution': {
                'spam': sum(y_train),
                'ham': len(y_train) - sum(y_train),
                'spam_ratio': sum(y_train) / len(y_train)
            },
            'parameters': {
                'max_features': self.max_features,
                'ngram_range': self.ngram_range,
                'alpha': self.alpha,
                'language': self.language,
                'administrative_boost': self.administrative_boost,
            }
        }
        
      
        if X_val is not None and y_val is not None:
            X_val_processed = [self.preprocess_text(text) for text in X_val]
            val_predictions = self.pipeline.predict(X_val_processed)
            val_accuracy = np.mean(val_predictions == y_val)
            
            self.training_info.update({
                'val_size': len(X_val),
                'val_accuracy': val_accuracy,
            })
        
        print(f" Modèle entraîné en {training_time:.1f}s")
        print(f"   Précision entraînement: {train_accuracy:.2%}")
        
        if 'val_accuracy' in self.training_info:
            print(f"   Précision validation: {self.training_info['val_accuracy']:.2%}")
        
        print(f"   Features: {self.training_info['feature_count']}")
        
        return self.training_info
    
    def predict(self, email_text: str, apply_administrative_boost: bool = True) -> Tuple[bool, float]:
        """
        Prédit si un email est spam avec ajustement pour emails administratifs
        """
        if not self.is_trained:
            raise Exception("Le modèle doit être entraîné avant de prédire")
        
       
        if apply_administrative_boost and self._is_clearly_administrative(email_text):
            return False, 0.1  
        
    
        processed_text = self.preprocess_text(email_text)
        
        if not processed_text.strip():
            return False, 0.0
        
      
        prediction = self.pipeline.predict([processed_text])[0]
        probabilities = self.pipeline.predict_proba([processed_text])[0]
        spam_probability = probabilities[1]
        
       
        if apply_administrative_boost:
            admin_score = self._calculate_administrative_score(email_text)
            if admin_score > 0:
             
                reduction = min(self.administrative_boost, admin_score * 0.15)
                adjusted_prob = max(0.0, spam_probability - reduction)
                
                
                if adjusted_prob < 0.5:
                    return False, adjusted_prob
                else:
                    return bool(prediction), adjusted_prob
        
        return bool(prediction), spam_probability
    
    def predict_with_explanation(self, email_text: str) -> Dict[str, Any]:
        """
        Prédiction avec explication détaillée pour débogage
        """
       
        is_clearly_admin = self._is_clearly_administrative(email_text)
        admin_score = self._calculate_administrative_score(email_text)
        
    
        raw_prediction, raw_probability = self.predict(email_text, apply_administrative_boost=False)
        
    
        final_prediction, final_probability = self.predict(email_text, apply_administrative_boost=True)
        
       
        processed_text = self.preprocess_text(email_text)
        
        explanation = {
            'email_preview': email_text[:100] + '...' if len(email_text) > 100 else email_text,
            'processed_text_preview': processed_text[:150] + '...' if len(processed_text) > 150 else processed_text,
            'is_clearly_administrative': is_clearly_admin,
            'administrative_score': float(admin_score),
            'raw_ml_prediction': bool(raw_prediction),
            'raw_ml_probability': float(raw_probability),
            'final_prediction': bool(final_prediction),
            'final_probability': float(final_probability),
            'administrative_boost_applied': (is_clearly_admin or admin_score > 0),
            'boost_strength': min(self.administrative_boost, admin_score * 0.15) if admin_score > 0 else 0.0,
            'decision_override': is_clearly_admin,
        }
        
        return explanation
    
    def predict_batch(self, email_texts: List[str]) -> List[Tuple[bool, float]]:
        """Prédit pour plusieurs emails avec ajustement administratif"""
        if not self.is_trained:
            raise Exception("Le modèle doit être entraîné")
        
        if not email_texts:
            return []
        
        results = []
        for text in email_texts:
            is_spam, prob = self.predict(text)
            results.append((is_spam, prob))
        
        return results
    
    def get_feature_count(self) -> int:
        """Retourne le nombre de features"""
        if not self.is_trained:
            return 0
        try:
            return len(self.pipeline.named_steps['tfidf'].get_feature_names_out())
        except:
            return 0
    
    def get_model_info(self) -> Dict:
        """Retourne les informations sur le modèle"""
        info = {
            'is_trained': self.is_trained,
            'parameters': {
                'max_features': self.max_features,
                'ngram_range': self.ngram_range,
                'alpha': self.alpha,
                'language': self.language,
                'administrative_boost': self.administrative_boost,
            },
            'training_info': self.training_info if self.training_info else {},
            'administrative_patterns_count': {
                'clear_indicators': len(self.administrative_patterns['clear_indicators']),
                'structure_patterns': len(self.administrative_patterns['structure_patterns']),
                'content_keywords': len(self.administrative_patterns['content_keywords']),
                'professional_phrases': len(self.administrative_patterns['professional_phrases']),
            }
        }
        
        if self.is_trained:
            info['feature_count'] = self.get_feature_count()
            info['class_names'] = self.class_names
        
        return info
    
    def save_model(self, filepath: str):
        """Sauvegarde le modèle avec tous les patterns"""
        if not self.is_trained:
            raise Exception("Le modèle doit être entraîné avant d'être sauvegardé")
        
        model_data = {
            'pipeline': self.pipeline,
            'training_info': self.training_info,
            'parameters': {
                'max_features': self.max_features,
                'ngram_range': self.ngram_range,
                'alpha': self.alpha,
                'language': self.language,
                'administrative_boost': self.administrative_boost,
            },
            'administrative_patterns': self.administrative_patterns,
            'class_names': self.class_names,
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f" Modèle sauvegardé: {filepath}")
        print(f"   Patterns administratifs inclus: {len(self.administrative_patterns['clear_indicators'])}")
    
    def load_model(self, filepath: str):
        """Charge un modèle pré-entraîné avec patterns"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.pipeline = model_data['pipeline']
            self.training_info = model_data.get('training_info', {})
            
            params = model_data.get('parameters', {})
            self.max_features = params.get('max_features', 3000)
            self.ngram_range = params.get('ngram_range', (1, 2))
            self.alpha = params.get('alpha', 0.1)
            self.language = params.get('language', 'french')
            self.administrative_boost = params.get('administrative_boost', 0.3)
            
            self.administrative_patterns = model_data.get('administrative_patterns', 
                                                         self._initialize_administrative_patterns())
            self.class_names = model_data.get('class_names', ['legitimate', 'spam'])
            self.is_trained = True
            
            print(f"Modèle chargé: {filepath}")
            print(f"   Langue: {self.language}")
            print(f"   Features: {self.get_feature_count()}")
            print(f"   Boost administratif: {self.administrative_boost}")
            
        except FileNotFoundError:
            raise Exception(f"Fichier modèle non trouvé: {filepath}")
        except Exception as e:
            raise Exception(f"Erreur lors du chargement: {e}")


def create_french_friendly_classifier() -> MLClassifier:
    """Crée un classifieur optimisé pour le français avec détection administrative"""
    return MLClassifier(
        max_features=4000, 
        ngram_range=(1, 3),  
        alpha=0.05, 
        language='french',
        administrative_boost=0.4,  
    )


if __name__ == "__main__":
    print(" Test du classifieur amélioré avec support français administratif...\n")
    

  
    classifier = MLClassifier(language='french')

    X_train = [
       
        "Bonjour, votre demande a bien été prise en charge par notre service. Un retour vous sera communiqué dès finalisation du traitement. Cordialement, Service administratif",
        "Madame, Monsieur, Nous accusons réception de votre dossier numéro 12345. Il est en cours de traitement. Bien cordialement, Service Client",
        "Objet : Suivi de votre demande - Bonjour, nous traitons actuellement votre requête REF-2024-001. Nous vous répondrons dans les meilleurs délais. Cordialement",
        "Suite à votre demande du 15/01/2024, nous vous informons que votre facture F2024001 est en pièce jointe. Pour toute information, contactez notre service. Sincères salutations",
        
        
        "GAGNEZ 1000€ MAINTENANT GRATUIT!!! Cliquez bit.ly/arnaque",
        "URGENT: Votre compte a été hacké! Accédez à security-verif.com pour vérifier",
        "WIN $1,000,000 NOW! Limited time offer!!! Click here: tinyurl.com/lottery-scam",
        "Téléchargez virus.exe pour booster votre PC!!! C'est GRATUIT et SÉCURISÉ",
        
       
        "Cher client, une vérification de sécurité est nécessaire pour votre compte. Accédez à mon-espace-securise.com pour éviter la suspension. Service Assistance",
        "Notification importante: Votre compte nécessite une mise à jour. Cliquez 👉 lien-verif.com pour sécuriser vos informations. Équipe Support",
    ]
    
    y_train = [0, 0, 0, 0,  # HAM
               1, 1, 1, 1,  # SPAM
               1, 1]        # SPAM (phishing)
    
    print("Entraînement du modèle...")
    classifier.train(X_train, y_train)
    
    print("\n" + "="*80)
    print("TESTS DE DÉTECTION AMÉLIORÉE:")
    print("="*80)
    
    test_emails = [
       
        ("Suivi de votre demande\n\nBonjour,\n\nVotre demande a bien été prise en charge par notre service.\nUn retour vous sera communiqué dès finalisation du traitement.\n\nCordialement,\nService administratif", False),
        
        
        ("give me money or i will kill you", True),
        
       
        ("Bonjour Madame Dupont,\n\nVotre dossier #45678 est en traitement.\nNous vous contacterons pour toute information complémentaire.\n\nBien cordialement,\nService Clientèle", False),
        
       
        ("Cher utilisateur, votre compte nécessite une vérification immédiate. Accédez à vérification-compte.com pour éviter la limitation de vos fonctionnalités. Service de Sécurité", True),
        
      
        ("Madame, Monsieur,\n\nVeuillez trouver ci-joint la facture n°F2024002.\nDate d'échéance: 30/01/2024.\n\nPour tout renseignement, contactez notre service comptabilité.\n\nVeuillez agréer nos salutations distinguées.", False),
    ]
    
    correct_predictions = 0
    total_tests = len(test_emails)
    
    for i, (email, expected) in enumerate(test_emails, 1):
        print(f"\nTest {i}:")
        print(f"Type attendu: {'🚫 SPAM' if expected else '✅ LÉGIT'}")
        print(f"Email: {email[:80]}...")
        
        
        explanation = classifier.predict_with_explanation(email)
        is_spam = explanation['final_prediction']
        probability = explanation['final_probability']
        
        status = "✅" if is_spam == expected else "❌"
        if is_spam == expected:
            correct_predictions += 1
        
        print(f"Résultat: {status} {'🚫 SPAM' if is_spam else '✅ LÉGIT'} (prob: {probability:.1%})")
        
       
        if explanation['is_clearly_administrative']:
            print(f"  → Détecté comme clairement administratif (OVERRIDE)")
        elif explanation['administrative_score'] > 0:
            print(f"  → Score administratif: {explanation['administrative_score']:.1f}")
            print(f"  → Boost appliqué: {explanation['boost_strength']:.1%}")
        
        if explanation['decision_override']:
            print(f"  → Décision override activée")
    
    print("\n" + "="*80)
    print(f"RÉSULTATS FINAUX: {correct_predictions}/{total_tests} corrects ({correct_predictions/total_tests:.1%})")
    print("="*80)
    
   
    print("\n" + "="*80)
    print("TEST SPÉCIFIQUE DE L'EMAIL PROBLÉMATIQUE:")
    print("="*80)
    
    problematic_email = """Bonjour,

Votre demande a bien été prise en charge par notre service.
Un retour vous sera communiqué dès finalisation du traitement.

Cordialement,
Service administratif"""
    
    explanation = classifier.predict_with_explanation(problematic_email)
    
    print(f"Email: {problematic_email}")
    print(f"\nAnalyse détaillée:")
    print(f"  • Clairement administratif: {explanation['is_clearly_administrative']}")
    print(f"  • Score administratif: {explanation['administrative_score']:.1f}")
    print(f"  • Prédiction ML brute: {'SPAM' if explanation['raw_ml_prediction'] else 'LÉGIT'} ({explanation['raw_ml_probability']:.1%})")
    print(f"  • Prédiction finale: {'🚫 SPAM' if explanation['final_prediction'] else '✅ LÉGIT'} ({explanation['final_probability']:.1%})")
    
    if explanation['decision_override']:
        print(f"  • RAISON: Email détecté comme clairement administratif - classification forcée comme légitime")
    
    print("="*80)


