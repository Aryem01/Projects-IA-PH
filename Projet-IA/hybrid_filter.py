
from heuristic_rules import HeuristicRules
from ml_classifier import MLClassifier
from typing import Dict, List, Optional
import time


class HybridSpamFilter:
    def __init__(self, ml_threshold: float = 0.65, use_cache: bool = False, language: str = 'french'):
        """
        Initialise le système hybride anti-spam
        
        Args:
            ml_threshold: Seuil de probabilité ML (0.65 recommandé pour français)
            use_cache: Active le cache
            language: Langue du modèle ('french', 'english', 'both')
        """
        self.heuristic_rules = HeuristicRules()
        self.ml_classifier = MLClassifier(language=language)
        self.ml_threshold = ml_threshold
        self.use_cache = use_cache
        self.language = language
        
      
        self.stats = {
            'total_processed': 0,
            'blocked_by_rules': 0,
            'blocked_by_ml': 0,
            'legitimate': 0,
            'processing_times': [],
        }
       
        if self.use_cache:
            self.cache = {}
            self.cache_hits = 0
            self.cache_misses = 0
    
    def train_ml_model(self, X_train: List[str], y_train: List[int]):
        """Entraîne le modèle ML"""
        print(f" Entraînement du modèle ML (langue: {self.language})...")
        start_time = time.time()
        self.ml_classifier.train(X_train, y_train)
        training_time = time.time() - start_time
        print(f" Modèle entraîné en {training_time:.2f}s")
    
    def load_ml_model(self, filepath: str):
        """Charge un modèle ML pré-entraîné"""
        self.ml_classifier.load_model(filepath)
    
    def classify(self, email_text: str) -> Dict:
        """
        Classifie un email (VERSION OPTIMISÉE)
        """
       
        if not email_text or not isinstance(email_text, str):
            raise ValueError("L'email doit être une chaîne non vide")
        
        email_text = email_text.strip()
        
       
        cache_key = None
        if self.use_cache:
            cache_key = hash(email_text)
            if cache_key in self.cache:
                self.cache_hits += 1
                return self.cache[cache_key]
            self.cache_misses += 1
        
       
        if len(email_text) < 10:
            result = {
                'is_spam': False,
                'method': 'heuristic',
                'reason': 'Email trop court',
                'confidence': 0.9,
                'ml_probability': 0.0,
                'processing_time_ms': 0
            }
            if self.use_cache and cache_key:
                self.cache[cache_key] = result
            return result
        
        start_time = time.time()
        self.stats['total_processed'] += 1
        
       
        is_spam_rules, reason_rules = self.heuristic_rules.apply_rules(email_text)
        
        if is_spam_rules:
            self.stats['blocked_by_rules'] += 1
            processing_time = (time.time() - start_time) * 1000
            
            result = {
                'is_spam': True,
                'method': 'heuristic',
                'reason': reason_rules,
                'confidence': 0.95,  
                'ml_probability': None,
                'processing_time_ms': processing_time
            }
            
            self.stats['processing_times'].append(processing_time)
            
            if self.use_cache and cache_key:
                self.cache[cache_key] = result
            
            return result
        
       
        if not self.ml_classifier.is_trained:
            raise Exception("Le modèle ML doit être entraîné")
        
        is_spam_ml, ml_probability = self.ml_classifier.predict(email_text)
        
        processing_time = (time.time() - start_time) * 1000
        
        if ml_probability >= self.ml_threshold:
            self.stats['blocked_by_ml'] += 1
            result = {
                'is_spam': True,
                'method': 'ml',
                'reason': f"ML détection (prob: {ml_probability:.1%}, seuil: {self.ml_threshold:.0%})",
                'confidence': ml_probability,
                'ml_probability': ml_probability,
                'processing_time_ms': processing_time
            }
        else:
            self.stats['legitimate'] += 1
            result = {
                'is_spam': False,
                'method': 'ml',
                'reason': f"Email légitime (prob spam: {ml_probability:.1%})",
                'confidence': 1 - ml_probability,
                'ml_probability': ml_probability,
                'processing_time_ms': processing_time
            }
        
        self.stats['processing_times'].append(processing_time)
        
        if self.use_cache and cache_key:
            self.cache[cache_key] = result
        
        return result
    
    def classify_batch(self, emails: List[str]) -> List[Dict]:
        """Classifie une liste d'emails"""
        results = []
        total = len(emails)
        
        print(f" Traitement de {total} emails...")
        
        for i, email in enumerate(emails, 1):
            if i % 50 == 0 or i == total:
                print(f"  {i}/{total} emails traités ({i/total*100:.1f}%)")
            
            try:
                result = self.classify(email)
                results.append(result)
            except Exception as e:
                results.append({
                    'is_spam': False,
                    'method': 'error',
                    'reason': f"Erreur: {str(e)}",
                    'confidence': 0.5,
                    'ml_probability': 0.0,
                    'processing_time_ms': 0,
                    'error': True
                })
        
        print(f" {len(results)} emails traités")
        return results
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques"""
        total = self.stats['total_processed']
        
        stats = {
            **self.stats,
            'rule_triggers': self.heuristic_rules.get_statistics(),
        }
        
        if total > 0:
            stats.update({
                'percentage_blocked_by_rules': (self.stats['blocked_by_rules'] / total) * 100,
                'percentage_blocked_by_ml': (self.stats['blocked_by_ml'] / total) * 100,
                'percentage_legitimate': (self.stats['legitimate'] / total) * 100,
            })
            
            if self.stats['processing_times']:
                stats.update({
                    'avg_processing_time_ms': sum(self.stats['processing_times']) / len(self.stats['processing_times']),
                    'min_processing_time_ms': min(self.stats['processing_times']),
                    'max_processing_time_ms': max(self.stats['processing_times']),
                })
        
        if self.use_cache:
            total_cache = self.cache_hits + self.cache_misses
            if total_cache > 0:
                stats.update({
                    'cache_hits': self.cache_hits,
                    'cache_misses': self.cache_misses,
                    'cache_hit_rate': (self.cache_hits / total_cache) * 100,
                    'cache_size': len(self.cache),
                })
        
        return stats
    
    def reset_statistics(self):
        """Réinitialise les statistiques"""
        self.stats = {
            'total_processed': 0,
            'blocked_by_rules': 0,
            'blocked_by_ml': 0,
            'legitimate': 0,
            'processing_times': [],
        }
        self.heuristic_rules.reset_statistics()
        
        if self.use_cache:
            self.cache.clear()
            self.cache_hits = 0
            self.cache_misses = 0
    
    def set_ml_threshold(self, threshold: float):
        """Modifie le seuil ML"""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Le seuil doit être entre 0.0 et 1.0")
        
        old = self.ml_threshold
        self.ml_threshold = threshold
        
        print(f" Seuil ML: {old:.2f} → {threshold:.2f}")
        
        if self.use_cache:
            self.cache.clear()
            print("  Cache effacé")



def create_spam_filter(threshold: float = 0.65, language: str = 'french') -> HybridSpamFilter:
    """
    Crée un filtre anti-spam optimisé
    
    Args:
        threshold: Seuil ML (0.65 recommandé pour français)
        language: Langue ('french', 'english', 'both')
    
    Returns:
        Instance de HybridSpamFilter
    """
    return HybridSpamFilter(ml_threshold=threshold, language=language)

def _quick_professional_check(self, email_text: str) -> Optional[Dict]:
        """
        Vérification rapide pour emails professionnels spécifiques
        AJOUTER dans la classe HybridSpamFilter (après __init__)
        """
        email_lower = email_text.lower()
        
        professional_indicators = [
            'projet ia', 'github', 'dépôt', 
            'compte rendu', 'réunion', 'points abordés',
            'modifications intégrées', 'collaboration'
        ]
        
        indicator_count = 0
        for indicator in professional_indicators:
            if indicator in email_lower:
                indicator_count += 1
        
        if indicator_count >= 2:
            if 'bonjour' in email_lower and any(end in email_lower for end in ['cordialement', 'merci']):
                return {
                    'is_spam': False,
                    'method': 'professional_detection',
                    'reason': f'Email professionnel détecté ({indicator_count} indicateurs)',
                    'confidence': 0.95,
                    'ml_probability': 0.1,
                    'processing_time_ms': 1.0
                }
        
        return None

if __name__ == "__main__":
    print(" Test du système hybride optimisé...\n")
    
    
    spam_filter = HybridSpamFilter(ml_threshold=0.65, language='french')
    
  
    test_emails = [
        "URGENT!!! Téléchargez virus.exe bit.ly/xxx",
        "Bonjour, voici le rapport demandé",
    ]
    
    print(" Tests avec règles heuristiques uniquement:\n")
    for email in test_emails:
       
        is_spam, reason = spam_filter.heuristic_rules.apply_rules(email)
        status = "🚫 SPAM" if is_spam else "✅ LÉGIT"
        print(f"{status}: {email[:50]}...")
        if reason:
            print(f"   Raison: {reason}")
        print()
