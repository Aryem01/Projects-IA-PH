"""
SCRIPT PRINCIPAL - PROJET ANTI-SPAM HYBRIDE
"""
from dataset_manager import DatasetManager
from hybrid_filter import HybridSpamFilter
from evaluate import SpamFilterEvaluator
import os
import sys
import time
import numpy as np
import argparse

def parse_arguments():
    """Parse les arguments pour correspondre à 5.1.pdf"""
    parser = argparse.ArgumentParser(
        description='Projet 5.1 - Anti-spam hybride (Règles + ML)',
        epilog='''Exemples:
  python main.py                    # Évaluation complète
  python main.py test              # Mode interactif
  python main.py --test-rapide     # Test rapide 100 emails
  python main.py --seuil 0.6       # Avec seuil personnalisé'''
    )
    
    parser.add_argument('--test-rapide', action='store_true',
                       help='Test rapide sur 100 emails comme 5.1.pdf')
    parser.add_argument('--seuil', type=float, default=0.5,
                       help='Seuil ML (0.0-1.0), défaut: 0.5')
    parser.add_argument('--afficher-regles', action='store_true',
                       help='Afficher détail des règles déclenchées')
    parser.add_argument('--dataset-taille', type=int, default=1000,
                       help='Taille dataset (défaut: 1000 comme 5.1.pdf)')
    

    parser.add_argument('mode', nargs='?', choices=['train', 'test'], default='train',
                       help='Mode: "train" pour évaluation, "test" pour mode interactif')
    
    return parser.parse_args()

def quick_test_100_emails(seuil=0.5): 
    """Test rapide sur 100 emails avec seuil personnalisé"""
    print("\n TEST RAPIDE SUR 100 EMAILS (5.1.pdf)")
    print("="*60)
    
    dm = DatasetManager()
    X, y, _ = dm.load_dataset()
    
   
    X_test = X[:100]
    y_test = y[:100]
    
  
    spam_filter = HybridSpamFilter(ml_threshold=seuil)
    

    print("Entraînement rapide du modèle...")
    spam_filter.train_ml_model(X[:200], y[:200])
    
    evaluator = SpamFilterEvaluator(spam_filter)
    results = evaluator.evaluate(X_test, y_test, verbose=False)
    
    print(f"\n RÉSULTATS SUR 100 EMAILS:")
    print(f"  • Emails analysés: {len(X_test)}")
    print(f"  • Faux positifs: {results['false_positive_rate']:.2%}")
    print(f"  • Détection spam: {results['recall']:.2%}")
    print(f"  • Précision globale: {results['accuracy']:.2%}")
    
    
    fp_ok = results['false_positive_rate'] < 0.01
    recall_ok = results['recall'] > 0.95
    
    print(f"\n OBJECTIFS :")
    print(f"  • Faux positifs < 1%: {' ATTEINT' if fp_ok else ' NON ATTEINT'}")
    print(f"  • Détection > 95%: {'ATTEINT' if recall_ok else ' NON ATTEINT'}")
    
    return results

def main():
    args = parse_arguments()
    
    print("="*60)
    print("PROJET 5.1 - ANTI-SPAM HYBRIDE")
    print("="*60)
    print(f"• Mode: {args.mode}")
    print(f"• Seuil ML: {args.seuil}")
    print(f"• Taille dataset: {args.dataset_taille} emails")
    print(f"• Test rapide: {' OUI' if args.test_rapide else ' NON'}")
    print("="*60)
    

    if args.test_rapide:
        return quick_test_100_emails(seuil=args.seuil)
    
 
    if args.mode == 'test':
        test_custom_emails()
        return

    print("\n   PROJET 5.1 - ANTI-SPAM HYBRIDE (Règles + Machine Learning)")
    print("="*80 + "\n")
    
    os.makedirs('./data/processed', exist_ok=True)
    os.makedirs('./models', exist_ok=True)
    os.makedirs('./results', exist_ok=True)
    
    
    print(" MÉTHODOLOGIE:")
    print("=" * 80)
    print("  • Règles heuristiques: .exe, bit.ly, mots-clés, majuscules excessives")
    print("  • Machine Learning: Naive Bayes + TF-IDF (ngram_range=(1,2))")
    print("  • Approche hybride: Règles d'abord, ML pour les cas douteux")
    print("  • Dataset: 800 emails Enron + 200 spams synthétiques")
    print("  • Objectifs: Faux positifs < 1%, Détection spam > 95%\n")
    
    print(" ÉTAPE 1: Préparation des données")
    print("-" * 80)
    
    start_time = time.time()
    
    dataset_manager = DatasetManager(data_dir='./data')
    
 
    print("\n Chargement des emails Enron (peut prendre 1-2 minutes)...")
    dataset_file = dataset_manager.download_enron_dataset()
    
    X_train, X_test, y_train, y_test = dataset_manager.get_train_test_split(
        test_size=0.2,
        random_state=42
    )
    
    data_load_time = time.time() - start_time
    print(f"\nDonnées préparées! ({data_load_time:.1f}s)")
    
   
    print("\n ANALYSE DU DATASET")
    print("-" * 80)
    
    total_emails = len(X_train) + len(X_test)
    total_spam = sum(y_train) + sum(y_test)
    total_ham = total_emails - total_spam
    
    print(f"   -Total emails: {total_emails}")
    print(f"   -Ensemble d'entraînement: {len(X_train)}")
    print(f"   -Ensemble de test: {len(X_test)}")
    print(f"   -Ratio spam/légitime: {total_spam/total_emails:.1%}/{total_ham/total_emails:.1%}")
    
 
    print(f"\nExemple légitime (Enron):")
    ham_idx = next((i for i, label in enumerate(y_train) if label == 0), 0)
    print(f"     \"{X_train[ham_idx][:80]}...\"")
    
    print(f"\n Exemple spam (synthétique):")
    spam_idx = next((i for i, label in enumerate(y_train) if label == 1), 0)
    print(f"     \"{X_train[spam_idx][:80]}...\"")
    
    print("\n ÉTAPE 2: Création du système anti-spam hybride")
    print("-" * 80)
    
    spam_filter = HybridSpamFilter(ml_threshold=args.seuil)
    
   
    print("\n Entraînement du modèle Machine Learning...")
    ml_start = time.time()
    spam_filter.train_ml_model(X_train, y_train)
    ml_time = time.time() - ml_start
    
    print(f" Système hybride prêt! ({ml_time:.1f}s)")
    
    print("\n ÉTAPE 3: Tests interactifs")
    print("-" * 80)
    
    test_examples = [
        "CLICK HERE NOW!!! Download free_money.exe to WIN $10000!!! bit.ly/scam",
        "Hi John, here is the quarterly report. Please review before Friday's meeting.",
        "CONGRATULATIONS!!! You WON the LOTTERY!!! Claim at bit.ly/winner123 NOW!!!",
        "Meeting rescheduled to next Tuesday at 2pm. Agenda attached.",
        "Urgent security update! Download virus_protection.exe immediately!!!",
        "GAGNEZ 5000€ MAINTENANT !!! Offre limitée bit.ly/gain",
        "Bonjour, pouvez-vous m'envoyer le rapport financier pour la réunion de demain?",
    ]
    
    print("\nTest de 7 emails exemples:\n")
    for i, email in enumerate(test_examples, 1):
        result = spam_filter.classify(email)
        
        prefix = "🚫 SPAM" if result['is_spam'] else "✅ LÉGITIME"
        print(f"{i}. {prefix}")
        print(f"   Méthode: {result['method'].upper()}")
        print(f"   Confiance: {result['confidence']:.0%}")
        print(f"   Email: {email[:70]}...")
        print(f"   Raison: {result['reason']}")
        print()
    
    
    spam_filter.reset_statistics()
    
    print("\n ÉTAPE 4: Évaluation complète sur jeu de test")
    print("-" * 80)
    
    evaluator = SpamFilterEvaluator(spam_filter)
    results = evaluator.evaluate(X_test, y_test, verbose=True)
    
    
    if args.afficher_regles:
        print("\n ANALYSE DÉTAILLÉE DES RÈGLES (sur demande)")
        print("-" * 80)
        stats = spam_filter.get_statistics()
        if 'rule_triggers' in stats:
            total = sum(stats['rule_triggers'].values())
            if total > 0:
                print(f"Total déclenchements règles: {total}")
                for rule, count in stats['rule_triggers'].items():
                    if count > 0:
                        pourcentage = (count / total) * 100
                        print(f"  • {rule}: {count} ({pourcentage:.1f}%)")
    
    print("\nÉTAPE 5: Analyse des erreurs")
    print("-" * 80)
    
    
    false_positives = evaluator.find_false_positives(X_test, y_test, max_display=3)
    
   
    stats = spam_filter.get_statistics()
    if 'rule_triggers' in stats:
        print(f"\n CONTRIBUTION DES RÈGLES HEURISTIQUES:")
        total_rules = sum(stats['rule_triggers'].values())
        if total_rules > 0:
            for rule_name, count in stats['rule_triggers'].items():
                if count > 0:
                    percentage = (count / total_rules) * 100
                   
                    noms_fr = {
                        'dangerous_attachment': 'Pièce jointe dangereuse',
                        'suspicious_url': 'URL suspecte',
                        'spam_keywords': 'Mots-clés spam',
                        'excessive_punctuation': 'Ponctuation excessive',
                        'excessive_caps': 'Majuscules excessives',
                        'threats': 'Menaces',
                        'money_amounts': 'Montants argent',
                        'phishing_sophisticated': 'Phishing sophistiqué'
                    }
                    nom = noms_fr.get(rule_name, rule_name)
                    print(f"  • {nom}: {count} fois ({percentage:.1f}%)")
    
    print("\n ÉTAPE 6: Génération des rapports")
    print("-" * 80)
    
   
    evaluator.generate_detailed_report('./results/evaluation_report.txt')
    
  
    model_path = './models/spam_model.pkl'
    spam_filter.ml_classifier.save_model(model_path)
    
    print(f" Modèle sauvegardé: {model_path}")
    print(f"Rapport généré: ./results/evaluation_report.txt")
    
    print("\n ÉTAPE 7: Suggestions d'optimisation")
    print("-" * 80)
    
    fp_rate = results['false_positive_rate']
    recall = results['recall']
    
    if fp_rate > 0.01:
        print(" Taux de faux positifs > 1%")
        print("   Suggestions:")
        print(f"   1. Augmenter le seuil ML: --seuil {min(args.seuil + 0.1, 0.9)}")
        print("   2. Ajouter des exceptions aux règles heuristiques")
        print("   3. Entraîner sur plus d'emails légitimes")
    else:
        print(" Taux de faux positifs < 1% - Objectif atteint!")
    
    if recall < 0.95:
        print("\n Détection de spam < 95%")
        print("   Suggestions:")
        print(f"   1. Diminuer le seuil ML: --seuil {max(args.seuil - 0.1, 0.1)}")
        print("   2. Ajouter de nouvelles règles heuristiques")
        print("   3. Augmenter le nombre de spams dans le dataset")
    else:
        print("\n Détection de spam > 95% - Objectif atteint!")
    

    
    print(" PROJET TERMINÉ AVEC SUCCÈS!")
    print("="*80)
    
    total_time = time.time() - start_time
    
    print(f"""
     TEMPS D'EXÉCUTION: {total_time:.1f} secondes
      - Chargement données: {data_load_time:.1f}s
      - Entraînement ML: {ml_time:.1f}s
      - Évaluation: {total_time - data_load_time - ml_time:.1f}s

     FICHIERS GÉNÉRÉS:
      • Dataset: ./data/processed/enron_hybrid_dataset.csv
      • Modèle: ./models/spam_model.pkl
      • Rapport: ./results/evaluation_report.txt

     RÉSULTATS FINAUX:
      • Précision globale: {results['accuracy']:.2%}
      • Faux positifs: {results['false_positive_rate']:.2%} {''if results['false_positive_rate'] < 0.01 else '❌'}
      • Détection spam: {results['recall']:.2%} {'' if results['recall'] > 0.95 else ''}
      • F1-Score: {results['f1_score']:.2%}

     OBJECTIFS 5.1:
      • Faux positifs < 1%: {'ATTEINT ' if results['false_positive_rate'] < 0.01 else 'NON ATTEINT '}
      • Détection > 95%: {'ATTEINT ' if results['recall'] > 0.95 else 'NON ATTEINT '}

     PROCHAINES ÉTAPES:
      1. Tester d'autres emails: python main.py test
      2. Test rapide 5.1: python main.py --test-rapide
      3. Ajuster le seuil: python main.py --seuil 0.6
      4. Voir rapport: cat results/evaluation_report.txt
    """)
    
   
    
    return spam_filter, evaluator, results


def test_custom_emails(seuil=0.5):
    """Fonction pour tester des emails personnalisés"""
    print("  MODE TEST INTERACTIF")
    print("="*80 + "\n")
    
    model_path = './models/spam_model.pkl'
    
    if os.path.exists(model_path):
        spam_filter = HybridSpamFilter(ml_threshold=seuil)
        try:
            spam_filter.load_ml_model(model_path)
            print(f" Modèle chargé (seuil: {seuil})")
        except Exception as e:
            print(f"  Erreur chargement: {e}")
            print("Entraînement d'un modèle rapide...")
            dm = DatasetManager()
            X, y, _ = dm.load_dataset()
            spam_filter.train_ml_model(X[:100], y[:100])
    else:
        print("  Modèle non trouvé. Entraînement rapide...")
        dm = DatasetManager()
        X, y, _ = dm.load_dataset()
        spam_filter = HybridSpamFilter(ml_threshold=seuil)
        spam_filter.train_ml_model(X[:100], y[:100])
    
    print("\n Entrez des emails à tester:")
    print("   Exemples à essayer:")
    print("   • 'GAGNEZ 1000€ GRATUIT !!! bit.ly/gain'")
    print("   • 'Bonjour, voici le rapport demandé'")
    print("   • 'URGENT: Télécharge update.exe maintenant !!!'")
    print("   • 'quit' pour quitter\n")
    
    test_count = 0
    spam_count = 0
    
    while True:
        try:
            email_text = input("\n Email à tester: ")
        except EOFError:
            break
        
        if email_text.lower() in ['quit', 'exit', 'q']:
            print(f"\n Récapitulatif:")
            print(f"   • Emails testés: {test_count}")
            print(f"   • Spams détectés: {spam_count}")
            print(f"   • Ratio spam: {spam_count/max(test_count,1):.1%}")
            print("\n Au revoir!")
            break
        
        if not email_text.strip():
            continue
        
        test_count += 1
        result = spam_filter.classify(email_text)
        
        if result['is_spam']:
            spam_count += 1
            print(f"🚫 SPAM DÉTECTÉ")
        else:
            print(f"✅ EMAIL LÉGITIME")
        
        print(f"   Méthode: {result['method'].upper()}")
        print(f"   Confiance: {result['confidence']:.1%}")
        if result['reason']:
            print(f"   Raison: {result['reason']}")

if __name__ == "__main__":
    print(" Vérification des dépendances...")
    
    missing_deps = []
    try:
        import pandas
    except ImportError:
        missing_deps.append("pandas")
    
    try:
        import sklearn
    except ImportError:
        missing_deps.append("scikit-learn")
    
    if missing_deps:
        print(f"\n Dépendances manquantes: {', '.join(missing_deps)}")
        print("\n Installation:")
        print("pip install pandas scikit-learn")
        sys.exit(1)
    
    print(" Toutes les dépendances sont installées\n")
    
   
    args = parse_arguments()
    
    try:
        if args.mode == 'test':
            test_custom_emails(seuil=args.seuil)
        elif args.test_rapide:
           
            print("\n" + "="*60)
            print(" TEST RAPIDE  100 EMAILS")
            print("="*60)
            quick_test_100_emails(seuil=args.seuil)
        else:
            
            spam_filter, evaluator, results = main()
            
            print("\n Pour d'autres modes:")
            print("  python main.py test              # Mode interactif")
            print("  python main.py --test-rapide     # Test rapide")
            print("  python main.py --seuil 0.6       # Avec seuil personnalisé")
            print("  python main.py --afficher-regles # Détail des règles")
            
    except KeyboardInterrupt:
        print("\n\n Interrompu par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
