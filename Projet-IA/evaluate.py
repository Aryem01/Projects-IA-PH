"""
Évaluation du système anti-spam hybride 
Calcul des métriques: précision, faux positifs, faux négatifs, etc.
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import pandas as pd

class SpamFilterEvaluator:
    def __init__(self, spam_filter):
        """
        Initialise l'évaluateur
        
        Args:
            spam_filter: Instance de HybridSpamFilter
        """
        self.spam_filter = spam_filter
        self.results = None
    
    def evaluate(self, X_test, y_test, verbose=True):
        """
        Évalue le système sur un jeu de test
        
        Args:
            X_test: Liste d'emails de test
            y_test: Labels réels (0=légitime, 1=spam)
        
        Returns:
            Dict avec toutes les métriques
        """
        
        y_pred = []
        y_proba = []
        methods_used = []
        
        print(" Traitement des emails de test...")
        
        for i, email in enumerate(X_test):
            if verbose and i % 20 == 0:
                print(f"  {i}/{len(X_test)} emails traités")
            
            result = self.spam_filter.classify(email)
            y_pred.append(1 if result['is_spam'] else 0)
            y_proba.append(result.get('ml_probability', 1.0 if result['is_spam'] else 0.0))
            methods_used.append(result['method'])
        
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
    
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
      
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
   
        method_counts = pd.Series(methods_used).value_counts().to_dict()
        method_percentages = {
            method: (count / len(methods_used) * 100)
            for method, count in method_counts.items()
        }
        
        
        stats = self.spam_filter.get_statistics()
        
        self.results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'false_positive_rate': false_positive_rate,
            'false_negative_rate': false_negative_rate,
            'confusion_matrix': cm,
            'y_true': y_test,
            'y_pred': y_pred,
            'y_proba': y_proba,
            'methods_used': methods_used,
            'method_counts': method_counts,
            'method_percentages': method_percentages,
            'system_stats': stats,
            'test_size': len(X_test),
            'spam_ratio': sum(y_test) / len(y_test),
        }
        
        if verbose:
            self._print_results()
        
        return self.results
    
    def _print_results(self):
        """Affiche les résultats de manière lisible"""
        r = self.results
        
        print("  RÉSULTATS DE L'ÉVALUATION DU SYSTÈME ANTI-SPAM HYBRIDE")
        print("="*70 + "\n")
        
       
        print("MÉTRIQUES PRINCIPALES:")
        print(f"  • Précision globale (Accuracy): {r['accuracy']:.2%}")
        print(f"  • Précision (Precision):        {r['precision']:.2%}")
        print(f"  • Rappel (Recall):              {r['recall']:.2%}")
        print(f"  • F1-Score:                     {r['f1_score']:.2%}")
        
        
        print(f"\n OBJECTIFS DU PROJET:")
        fp_ok = "✅" if r['false_positive_rate'] < 0.01 else "❌"
        recall_ok = "✅" if r['recall'] > 0.95 else "❌"
        print(f"  {fp_ok} Faux positifs: {r['false_positive_rate']:.2%} (objectif: < 1%)")
        print(f"  {recall_ok} Détection spam: {r['recall']:.2%} (objectif: > 95%)")
        
     
        print(f"\n MATRICE DE CONFUSION:")
        print(f"  • Vrais positifs (spam détecté):      {r['true_positives']}")
        print(f"  • Vrais négatifs (légitime accepté):  {r['true_negatives']}")
        print(f"  • Faux positifs (légitime bloqué):    {r['false_positives']}")
        print(f"  • Faux négatifs (spam non détecté):   {r['false_negatives']}")
        
        
        print(f"\n DISTRIBUTION DES MÉTHODES:")
        for method, count in r['method_counts'].items():
            percentage = r['method_percentages'][method]
            print(f"  • {method.upper():<12} {count:>4} emails ({percentage:5.1f}%)")
        
        
        stats = r['system_stats']
        print(f"\n📊 STATISTIQUES DU SYSTÈME:")
        print(f"  •Total traité: {stats['total_processed']}")
        print(f"  • Bloqué par règles: {stats['blocked_by_rules']} ({stats.get('percentage_blocked_by_rules', 0):.1f}%)")
        print(f"  • Bloqué par ML: {stats['blocked_by_ml']} ({stats.get('percentage_blocked_by_ml', 0):.1f}%)")
        print(f"  • Légitime: {stats['legitimate']} ({stats.get('percentage_legitimate', 0):.1f}%)")
        
      
        if 'rule_triggers' in stats:
            print(f"\n🔧 CONTRIBUTION DES RÈGLES HEURISTIQUES:")
            total_rules = sum(stats['rule_triggers'].values())
            if total_rules > 0:
                for rule_name, count in sorted(stats['rule_triggers'].items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        percentage = (count / total_rules) * 100
                        print(f"  • {rule_name:<25} {count:>4} ({percentage:5.1f}%)")
        
        print("\n" + "="*70 + "\n")
    
    def generate_detailed_report(self, output_file='evaluation_report.txt'):
        """Génère un rapport détaillé en format texte"""
        if self.results is None:
            raise Exception("Veuillez d'abord executer evaluate()")
        
        r = self.results
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("RAPPORT D'ÉVALUATION - SYSTÈME ANTI-SPAM HYBRIDE\n")
            f.write("="*80 + "\n\n")
            
            f.write("1. RÉSUMÉ EXÉCUTIF\n")
            f.write("-" * 80 + "\n")
            f.write(f"Précision globale: {r['accuracy']:.2%}\n")
            f.write(f"Taux de faux positifs: {r['false_positive_rate']:.2%} ")
            f.write(f"({'OBJECTIF ATTEINT' if r['false_positive_rate'] < 0.01 else 'OBJECTIF NON ATTEINT'})\n")
            f.write(f"Taux de détection spam: {r['recall']:.2%} ")
            f.write(f"({'OBJECTIF ATTEINT' if r['recall'] > 0.95 else 'OBJECTIF NON ATTEINT'})\n")
            f.write(f"Taille du jeu de test: {r['test_size']} emails\n")
            f.write(f"Ratio spam dans le test: {r['spam_ratio']:.1%}\n\n")
            
            f.write("2. MÉTRIQUES DÉTAILLÉES\n")
            f.write("-" * 80 + "\n")
            f.write(f"Précision: {r['precision']:.4f}\n")
            f.write(f"Recall: {r['recall']:.4f}\n")
            f.write(f"F1-Score: {r['f1_score']:.4f}\n")
            f.write(f"Vrais positifs: {r['true_positives']}\n")
            f.write(f"Vrais négatifs: {r['true_negatives']}\n")
            f.write(f"Faux positifs: {r['false_positives']}\n")
            f.write(f"Faux négatifs: {r['false_negatives']}\n\n")
            
            f.write("3. DISTRIBUTION DES MÉTHODES\n")
            f.write("-" * 80 + "\n")
            for method, count in r['method_counts'].items():
                percentage = r['method_percentages'][method]
                f.write(f"{method.upper():<12} {count:>6} emails ({percentage:6.2f}%)\n")
            f.write("\n")
            
            f.write("4. STATISTIQUES DU SYSTÈME\n")
            f.write("-" * 80 + "\n")
            stats = r['system_stats']
            f.write(f"Total traité: {stats['total_processed']}\n")
            f.write(f"Bloqué par règles: {stats['blocked_by_rules']}\n")
            f.write(f"Bloqué par ML: {stats['blocked_by_ml']}\n")
            f.write(f"Emails légitimes: {stats['legitimate']}\n\n")
            
            if 'rule_triggers' in stats:
                f.write("5. CONTRIBUTION DES RÈGLES\n")
                f.write("-" * 80 + "\n")
                for rule_name, count in stats['rule_triggers'].items():
                    if count > 0:
                        f.write(f"{rule_name}: {count} détections\n")
            
            f.write("\n" + "="*80 + "\n")
        
        print(f" Rapport détaillé généré: {output_file}")
    
    def find_false_positives(self, X_test, y_test, max_display=5):
        """Trouve et affiche les faux positifs (légitimes bloqués)"""
        if self.results is None:
            raise Exception("Veuillez d'abord executer evaluate()")
        
        false_positives = []
        
        for i, (email, true_label, pred_label) in enumerate(zip(X_test, y_test, self.results['y_pred'])):
            if true_label == 0 and pred_label == 1:  
                result = self.spam_filter.classify(email)
                false_positives.append({
                    'email': email,
                    'method': result['method'],
                    'reason': result['reason'],
                    'confidence': result['confidence']
                })
        
        if false_positives:
            print(f"\n FAUX POSITIFS DÉTECTÉS: {len(false_positives)}")
            print("-" * 80)
            
       
            method_counts = {}
            for fp in false_positives:
                method = fp['method']
                method_counts[method] = method_counts.get(method, 0) + 1
            
            print("Distribution par méthode:")
            for method, count in method_counts.items():
                percentage = (count / len(false_positives)) * 100
                print(f"  • {method.upper()}: {count} ({percentage:.1f}%)")
            
           
            print(f"\n Exemples (max {max_display}):")
            for i, fp in enumerate(false_positives[:max_display]):
                print(f"\n{i+1}. Méthode: {fp['method'].upper()}")
                print(f"   Confiance: {fp['confidence']:.1%}")
                print(f"   Raison: {fp['reason']}")
                print(f"   Email: {fp['email'][:100]}...")
            
            if len(false_positives) > max_display:
                print(f"\n... et {len(false_positives) - max_display} autres faux positifs")
        else:
            print(f"\n AUCUN FAUX POSITIF DÉTECTÉ !")
        
        return false_positives
    
    def get_recommendations(self):
        """Retourne des recommandations basées sur les résultats"""
        if self.results is None:
            raise Exception("Exécutez evaluate() d'abord")
        
        r = self.results
        recommendations = []
        
       
        if r['false_positive_rate'] > 0.01:
            recommendations.append(
                " Augmenter le seuil ML (ex: 0.6 ou 0.7) pour réduire les faux positifs"
            )
            recommendations.append(
                " Ajouter des exceptions aux règles heuristiques pour certains domaines légitimes"
            )
            recommendations.append(
                " Analyser les faux positifs pour identifier les règles trop strictes"
            )
        
        
        if r['recall'] < 0.95:
            recommendations.append(
                " Diminuer le seuil ML (ex: 0.4) pour détecter plus de spams"
            )
            recommendations.append(
                " Ajouter de nouvelles règles heuristiques basées sur les faux négatifs"
            )
            recommendations.append(
                " Enrichir le dataset d'entraînement avec plus d'exemples de spam"
            )
        
        
        if r['method_percentages'].get('ml', 0) > 50:
            recommendations.append(
                " Optimiser les règles heuristiques pour prendre en charge plus de cas évidents"
            )
        
        recommendations.append(
            " Consulter le rapport détaillé pour une analyse complète"
        )
        
        return recommendations
    
    def print_confusion_matrix_visual(self):
        """Affiche une version visuelle de la matrice de confusion"""
        if self.results is None:
            raise Exception("Exécutez evaluate() d'abord")
        
        r = self.results
        cm = r['confusion_matrix']
        
        print("\n MATRICE DE CONFUSION (visuelle):")
        print("-" * 50)
        print("              PRÉDIT")
        print("           Légitime   Spam")
        print(f"RÉEL   Légitime  {cm[0,0]:^6}   {cm[0,1]:^6}")
        print(f"       Spam       {cm[1,0]:^6}   {cm[1,1]:^6}")
        print("-" * 50)
        
        print("\n LÉGENDE:")
        print(f"  {cm[0,0]} = Vrais négatifs (légitimes correctement acceptés)")
        print(f"  {cm[0,1]} = Faux positifs (légitimes incorrectement bloqués)")
        print(f"  {cm[1,0]} = Faux négatifs (spams manqués)")
        print(f"  {cm[1,1]} = Vrais positifs (spams correctement bloqués)")
    
    def analyze_phishing_detection(self, X_test, y_test):
   
     if self.results is None:
        raise Exception("Exécutez evaluate() d'abord")
    
     
     phishing_indices = []
     for i, email in enumerate(X_test):
        email_lower = email.lower()
       
        phishing_indicators = [
            'security review', 'vérifications régulières',
            'access my account', 'accéder à mon espace',
            'temporarily unavailable', 'limitation temporaire',
            '👉', 'click here', 'cliquez ici'
        ]
        
        if any(indicator in email_lower for indicator in phishing_indicators):
            phishing_indices.append(i)
    
     if not phishing_indices:
        print(" Aucun email de phishing identifié dans le jeu de test")
        return
    
     print(f"\n ANALYSE DÉTECTION PHISHING: {len(phishing_indices)} emails identifiés")
     print("-" * 80)
    
    
     true_positives = 0
     false_negatives = 0
    
     for idx in phishing_indices:
        is_phishing = y_test[idx] == 1
        predicted_spam = self.results['y_pred'][idx] == 1
        
        if is_phishing and predicted_spam:
            true_positives += 1
        elif is_phishing and not predicted_spam:
            false_negatives += 1
            
            if false_negatives <= 3:  
                print(f"❌ Faux négatif phishing #{false_negatives}:")
                print(f"   Email: {X_test[idx][:100]}...")
                print(f"   Méthode: {self.results['methods_used'][idx]}")
                print(f"   Probabilité ML: {self.results['y_proba'][idx]:.1%}")
                print()
  
 
     if len(phishing_indices) > 0:
        phishing_recall = true_positives / len(phishing_indices)
        print(f" PERFORMANCE PHISHING:")
        print(f"   • Vrais positifs: {true_positives}")
        print(f"   • Faux négatifs: {false_negatives}")
        print(f"   • Rappel phishing: {phishing_recall:.1%}")
        
      
        if phishing_recall < 0.9:
            print(f"\n RECOMMANDATIONS PHISHING:")
            print("   1. Ajouter plus d'exemples de phishing dans le dataset")
            print("   2. Renforcer les règles heuristiques de phishing")
            print("   3. Baisser le seuil ML pour les emails suspects")
        
        return {
            'phishing_count': len(phishing_indices),
            'true_positives': true_positives,
            'false_negatives': false_negatives,
            'recall': phishing_recall
        }


if __name__ == "__main__":
    print(" Module d'évaluation chargé.")
    print("\n Utilisation:")
    print("  evaluator = SpamFilterEvaluator(spam_filter)")
    print("  results = evaluator.evaluate(X_test, y_test)")
    print("  evaluator.generate_detailed_report('rapport.txt')")
    print("  evaluator.find_false_positives(X_test, y_test)")
    print("  evaluator.get_recommendations()")
