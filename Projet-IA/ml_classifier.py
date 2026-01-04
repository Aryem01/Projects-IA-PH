"""
Classifieur ML avec Support Français Complet
"""

import pickle
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from typing import List, Tuple, Dict, Optional
import time

class MLClassifier:
    def __init__(self, max_features: int = 3000, ngram_range: tuple = (1, 2), 
                 alpha: float = 0.1, language: str = 'english'): 
        """
        Initialise le classifieur ML avec support multilingue
        
        Args:
            max_features: Nombre maximum de features TF-IDF
            ngram_range: Plage de n-grams (ex: (1,2) pour unigrams+bigrams)
            alpha: Paramètre de lissage pour Naive Bayes
            language: Langue ('french', 'english', ou 'both')
        """
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.alpha = alpha
        self.language = language
        
        # Configuration des stopwords
        stop_words = self._get_stopwords(language)
        
        # Pipeline ML
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=max_features,
                min_df=2,
                max_df=0.85,  # Augmenté de 0.8 à 0.85
                ngram_range=ngram_range,
                stop_words=stop_words,
                sublinear_tf=True,
                strip_accents='unicode',  # IMPORTANT pour français
            )),
            ('classifier', MultinomialNB(alpha=alpha))
        ])
        
        # État du modèle
        self.is_trained = False
        self.training_info = {}
        self.class_names = ['legitimate', 'spam']
    
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
                # Pronoms
                'je', 'tu', 'il', 'elle', 'nous', 'vous', 'ils', 'elles',
                'me', 'te', 'se', 'lui', 'leur', 'moi', 'toi', 'soi',
                'ce', 'cet', 'cette', 'ces', 'celui', 'celle', 'ceux', 'celles',
                'mon', 'ton', 'son', 'ma', 'ta', 'sa', 'mes', 'tes', 'ses',
                'notre', 'votre', 'leur', 'nos', 'vos', 'leurs',
                # Verbes auxiliaires
                'être', 'est', 'sont', 'était', 'été', 'suis', 'es', 'sommes', 'êtes',
                'avoir', 'a', 'ai', 'as', 'avons', 'avez', 'ont', 'eu',
                # Mots fréquents
                'que', 'qui', 'quoi', 'quel', 'quelle', 'quels', 'quelles',
                'où', 'quand', 'comment', 'pourquoi',
                'tout', 'tous', 'toute', 'toutes',
                'plus', 'moins', 'très', 'bien', 'pas', 'ne', 'non',
                'si', 'oui', 'comme', 'aussi', 'encore',
                'fait', 'faire', 'peut', 'peuvent', 'pouvoir',
                'dois', 'doit', 'doivent', 'devoir',
                'va', 'vais', 'vas', 'allons', 'allez', 'vont', 'aller',
                'dit', 'dis', 'disent', 'dire',
            }
            return list(french_stopwords)
        elif language == 'both':
            # Combinaison anglais + français
            french = self._get_stopwords('french')
            return french  # sklearn.feature_extraction.text.ENGLISH_STOP_WORDS sera ajouté
        else:
            return None
    
    def preprocess_text(self, text: str, advanced: bool = True) -> str:
        """
        Prétraite le texte pour l'analyse ML (VERSION AMÉLIORÉE)
        Support complet du français
        """
        if not text or not isinstance(text, str):
            return ""
        
        # 1. Minuscules
        text = text.lower()
        
        if advanced:
            # 2. Nettoyer les caractères spéciaux français
            # Garder les accents mais normaliser
            text = text.replace('œ', 'oe').replace('æ', 'ae')
            
            # 3. URLs
            text = re.sub(r'https?://\S+|www\.\S+', 'URL', text)
            text = re.sub(r'bit\.ly/\S+|tinyurl\.com/\S+', 'SHORTURL', text)
            
            # 4. Emails
            text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL', text)
            
            # 5. Téléphones et numéros
            text = re.sub(r'\b\d{10,}\b', 'PHONE', text)
            text = re.sub(r'\b\d{1,9}\b', 'NUM', text)
            
            # 6. Montants d'argent
            text = re.sub(r'[\$€£]\s*\d+', 'MONEY', text)
            text = re.sub(r'\d+\s*[\$€£]', 'MONEY', text)
            
            # 7. Répétitions excessives (!!!, ???)
            text = re.sub(r'([!?.]){3,}', r'\1\1', text)  # Réduire à 2 max
            
            # 8. Caractères spéciaux (garder ponctuation de base)
            text = re.sub(r'[^\w\s.!?,àâäæçéèêëïîôùûüÿœ]', ' ', text)
            
            # 9. Espaces multiples
            text = re.sub(r'\s+', ' ', text)
            
            # 10. Mots trop courts (sauf "a", "i", "y", "à")
            words = text.split()
            words = [w for w in words if len(w) > 1 or w in ['a', 'i', 'y', 'à']]
            text = ' '.join(words)
        
        return text.strip()
    
    def train(self, X_train: List[str], y_train: List[int], 
              X_val: Optional[List[str]] = None, y_val: Optional[List[int]] = None) -> Dict:
        """
        Entraîne le modèle ML
        """
        print(f" Début de l'entraînement (langue: {self.language})...")
        start_time = time.time()
        
        if len(X_train) != len(y_train):
            raise ValueError(f"X_train ({len(X_train)}) et y_train ({len(y_train)}) doivent avoir la même taille")
        
        # Statistiques
        spam_count = sum(y_train)
        ham_count = len(y_train) - spam_count
        
        print(f"  • Données d'entraînement: {len(X_train)} emails")
        print(f"  • Légitimes: {ham_count}, Spams: {spam_count}")
        print(f"  • Ratio spam: {spam_count/len(y_train):.1%}")
        
        # Prétraitement
        print("   Prétraitement des textes...")
        X_train_processed = [self.preprocess_text(text) for text in X_train]
        
        # Filtrer les textes vides (peut arriver après prétraitement)
        valid_indices = [i for i, text in enumerate(X_train_processed) if text.strip()]
        X_train_processed = [X_train_processed[i] for i in valid_indices]
        y_train = [y_train[i] for i in valid_indices]
        
        print(f"  • Textes valides après prétraitement: {len(X_train_processed)}")
        
        # Entraînement
        print("   Entraînement du modèle Naive Bayes...")
        self.pipeline.fit(X_train_processed, y_train)
        self.is_trained = True
        
        # Métriques
        train_predictions = self.pipeline.predict(X_train_processed)
        train_accuracy = np.mean(train_predictions == y_train)
        
        training_time = time.time() - start_time
        
        # Informations
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
                'language': self.language
            }
        }
        
        # Validation
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
    
    def predict(self, email_text: str) -> Tuple[bool, float]:
        """
        Prédit si un email est spam
        """
        if not self.is_trained:
            raise Exception("Le modèle doit être entraîné avant de prédire")
        
        # Prétraitement
        processed_text = self.preprocess_text(email_text)
        
        if not processed_text.strip():
            # Texte vide après prétraitement -> légitime par défaut
            return False, 0.0
        
        # Prédiction
        prediction = self.pipeline.predict([processed_text])[0]
        probabilities = self.pipeline.predict_proba([processed_text])[0]
        
        spam_probability = probabilities[1]
        
        return bool(prediction), spam_probability
    
    def predict_batch(self, email_texts: List[str]) -> List[Tuple[bool, float]]:
        """Prédit pour plusieurs emails"""
        if not self.is_trained:
            raise Exception("Le modèle doit être entraîné")
        
        if not email_texts:
            return []
        
        processed_texts = [self.preprocess_text(text) for text in email_texts]
        
        # Gérer les textes vides
        results = []
        for text in processed_texts:
            if not text.strip():
                results.append((False, 0.0))
            else:
                pred = self.pipeline.predict([text])[0]
                prob = self.pipeline.predict_proba([text])[0][1]
                results.append((bool(pred), prob))
        
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
            },
            'training_info': self.training_info if self.training_info else {},
        }
        
        if self.is_trained:
            info['feature_count'] = self.get_feature_count()
            info['class_names'] = self.class_names
        
        return info
    
    def save_model(self, filepath: str):
        """Sauvegarde le modèle"""
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
            },
            'class_names': self.class_names,
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f" Modèle sauvegardé: {filepath}")
    
    def load_model(self, filepath: str):
        """Charge un modèle pré-entraîné"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.pipeline = model_data['pipeline']
            self.training_info = model_data.get('training_info', {})
            
            params = model_data.get('parameters', {})
            self.max_features = params.get('max_features', 3000)
            self.ngram_range = params.get('ngram_range', (1, 2))
            self.alpha = params.get('alpha', 0.1)
            self.language = params.get('language', 'english')  
            
            self.class_names = model_data.get('class_names', ['legitimate', 'spam'])
            self.is_trained = True
            
            print(f"Modèle chargé: {filepath}")
            print(f"   Langue: {self.language}")
            print(f"   Features: {self.get_feature_count()}")
            
        except FileNotFoundError:
            raise Exception(f"Fichier modèle non trouvé: {filepath}")
        except Exception as e:
            raise Exception(f"Erreur lors du chargement: {e}")
def preprocess_text(self, text: str, advanced: bool = True) -> str:
    """
    Prétraite le texte pour l'analyse ML (VERSION AMÉLIORÉE pour phishing)
    """
    if not text or not isinstance(text, str):
        return ""
    
    # 1. Minuscules
    text = text.lower()
    
    if advanced:
        # 2. Remplacer les indicateurs de phishing par des tokens spéciaux
        phishing_indicators = {
            '👉': ' LINK_INDICATOR ',
            '🔗': ' LINK_INDICATOR ',
            'click here': ' CLICK_HERE ',
            'cliquez ici': ' CLICK_HERE ',
            'access my account': ' ACCOUNT_ACCESS ',
            'accéder à mon espace': ' ACCOUNT_ACCESS ',
            'security review': ' SECURITY_REVIEW ',
            'vérifications régulières': ' SECURITY_REVIEW ',
            'temporarily unavailable': ' SERVICE_LIMITATION ',
            'limitation temporaire': ' SERVICE_LIMITATION ',
            'within the next few days': ' TIME_PRESSURE ',
            'dans les prochains jours': ' TIME_PRESSURE ',
        }
        
        for indicator, token in phishing_indicators.items():
            text = text.replace(indicator, token)
        
        # 3. URLs
        text = re.sub(r'https?://\S+|www\.\S+', 'URL', text)
        text = re.sub(r'bit\.ly/\S+|tinyurl\.com/\S+', 'SHORTURL', text)
        
        # 4. Emails
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL', text)
        
        # 5. Références (garder comme features importantes)
        text = re.sub(r'\b#[A-Za-z0-9]+\b', 'REFERENCE', text)
        text = re.sub(r'\bticket\s+#?\d+\b', 'TICKET_REF', text)
        text = re.sub(r'\bdossier\s+#?\d+\b', 'DOSSIER_REF', text)
        
        # 6. Montants d'argent
        text = re.sub(r'[\$€£]\s*\d+', 'MONEY', text)
        text = re.sub(r'\d+\s*[\$€£]', 'MONEY', text)
        
        # 7. Répétitions excessives
        text = re.sub(r'([!?.]){3,}', r'\1\1', text)
        
        # 8. Caractères spéciaux
        text = re.sub(r'[^\w\s.!?,àâäæçéèêëïîôùûüÿœ]', ' ', text)
        
        # 9. Espaces multiples
        text = re.sub(r'\s+', ' ', text)
        
        # 10. Garder les mots courts importants
        words = text.split()
        important_short_words = {'a', 'i', 'y', 'à', 'ou', 'et', 'or', 'of', 'in', 'to'}
        words = [w for w in words if len(w) > 1 or w in important_short_words]
        text = ' '.join(words)
    
    return text.strip()

if __name__ == "__main__":
    print(" Test du classifieur avec support français...\n")
    
    # Test avec données françaises
    classifier = MLClassifier(language='french')
    
    X_train = [
        "Bonjour, voici le rapport demandé",
        "GAGNEZ 1000€ MAINTENANT GRATUIT!!!",
        "Réunion demain à 14h",
        "URGENT: Téléchargez virus.exe!!!",
        "Madame, votre dossier est traité",
        "Cliquez bit.ly/arnaque pour gagner!!!",
    ]
    y_train = [0, 1, 0, 1, 0, 1]
    
    print("Entraînement...")
    classifier.train(X_train, y_train)
    
    print("\nTests:")
    tests = [
        "Bonjour, accusons réception",
        "GAGNEZ GRATUIT URGENT!!!",
    ]
    
    for text in tests:
        is_spam, prob = classifier.predict(text)
        print(f"{'🚫 SPAM' if is_spam else '✅ LÉGIT'}: {text[:40]}... (prob: {prob:.1%})")