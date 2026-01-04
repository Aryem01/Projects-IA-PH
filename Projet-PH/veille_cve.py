import requests
import json
from datetime import datetime, timedelta
import time
import logging


LOGICIELS_SURVEILLES = ['apache', 'wordpress', 'openssl']
SCORE_CVSS_MINIMUM = 9.0
FICHIER_ALERTES = 'alertes_cve.txt'
FICHIER_RAPPORT = 'rapport_mitigation.txt'



logger = logging.getLogger(__name__)

def obtenir_date_periode_30_jours():
    """Retourne la date d'il y a 30 jours au format ISO"""
    maintenant = datetime.now()
    date_debut = maintenant - timedelta(days=30)
    date_debut_formattee = date_debut.strftime('%Y-%m-%dT00:00:00.000')
    date_fin_formattee = maintenant.strftime('%Y-%m-%dT23:59:59.999')
    return date_debut_formattee, date_fin_formattee

def interroger_nvd_api():
    """Interroge l'API NVD pour récupérer les CVE critiques"""
    logger.info("Interrogation de l'API NVD en cours...")
    
    date_debut, date_fin = obtenir_date_periode_30_jours()
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    parametres_api = {
        'pubStartDate': date_debut,
        'pubEndDate': date_fin,
        'cvssV3Severity': 'CRITICAL'
    }
    
    try:
        reponse = requests.get(url, params=parametres_api, timeout=30)
        reponse.raise_for_status()
        donnees_api = reponse.json()
        logger.info("Donnees recuperees avec succes")
        return donnees_api
    except requests.exceptions.RequestException as erreur:
        logger.error("Erreur lors de la requete API: %s", erreur)
        return None

def analyser_element_cve(element_cve):
    """Analyse un item CVE et extrait les informations pertinentes"""
    donnees_cve = element_cve.get('cve', {})
    identifiant_cve = donnees_cve.get('id', 'NON_DISPONIBLE')
    
    descriptions = donnees_cve.get('descriptions', [])
    description_anglaise = next(
        (desc['value'] for desc in descriptions if desc['lang'] == 'en'),
        'NON_DISPONIBLE'
    )
    
    metriques = donnees_cve.get('metrics', {})
    
    donnees_cvss_v31 = metriques.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metriques else {}
    donnees_cvss_v30 = metriques.get('cvssMetricV30', [{}])[0] if 'cvssMetricV30' in metriques else {}
    
    donnees_cvss = {}
    if donnees_cvss_v31 and 'cvssData' in donnees_cvss_v31:
        donnees_cvss = donnees_cvss_v31.get('cvssData', {})
    elif donnees_cvss_v30 and 'cvssData' in donnees_cvss_v30:
        donnees_cvss = donnees_cvss_v30.get('cvssData', {})
    
    score_cvss = donnees_cvss.get('baseScore', 0.0)
    severite_cvss = donnees_cvss.get('baseSeverity', 'INCONNU')
    vecteur_attaque = donnees_cvss.get('vectorString', 'NON_DISPONIBLE')
    
    date_publication = donnees_cve.get('published', 'NON_DISPONIBLE')
    
    references = donnees_cve.get('references', [])
    urls_references = [ref.get('url') for ref in references[:3] if ref.get('url')]
    
    logiciels_affectes = []
    description_minuscule = description_anglaise.lower()
    for logiciel in LOGICIELS_SURVEILLES:
        if logiciel in description_minuscule:
            logiciels_affectes.append(logiciel.capitalize())
    
    return {
        'id': identifiant_cve,
        'description': description_anglaise,
        'cvss_score': score_cvss,
        'severity': severite_cvss,
        'vector': vecteur_attaque,
        'date_publiee': date_publication,
        'logiciels_affectes': logiciels_affectes,
        'references': urls_references
    }

def filtrer_cves(donnees_api):
    """Filtre les CVE selon les critères du projet"""

    if donnees_api is None:
        logger.warning("Donnees API sont None")
        return []
    
    if not isinstance(donnees_api, dict):
        logger.warning("Donnees API ne sont pas un dictionnaire")
        return []
    
    if 'vulnerabilities' not in donnees_api:
        logger.warning("Cle 'vulnerabilities' non trouvee dans les donnees")
        return []
    
    vulnerabilites = donnees_api.get('vulnerabilities', [])
    logger.info("Analyse de %d vulnerabilites...", len(vulnerabilites))
    
    cves_filtrees = []
    
    for vulnerabilite in vulnerabilites:
        info_cve = analyser_element_cve(vulnerabilite)
        
        if info_cve['cvss_score'] < SCORE_CVSS_MINIMUM:
            continue
        
        
        if not info_cve['logiciels_affectes']:
            continue
        
        cves_filtrees.append(info_cve)
    
    cves_filtrees.sort(key=lambda x: x['cvss_score'], reverse=True)
    
    logger.info("%d CVE critiques trouvees", len(cves_filtrees))
    return cves_filtrees

def generer_texte_alerte(cve_info):
    """Genere une alerte pour une CVE critique"""
    logiciels_formates = ', '.join(cve_info['logiciels_affectes'])
    description_tronquee = cve_info['description'][:500] + '...' if len(cve_info['description']) > 500 else cve_info['description']
    
    texte_alerte = f"""
{'='*70}
 ALERTE CRITIQUE - {cve_info['id']}
{'='*70}
Score CVSS    : {cve_info['cvss_score']} ({cve_info['severity']})
Logiciels     : {logiciels_formates}
Date          : {cve_info['date_publiee'][:10]}
Vecteur       : {cve_info['vector']}

DESCRIPTION:
{description_tronquee}

REFERENCES:
"""
    for reference in cve_info['references']:
        texte_alerte += f"  - {reference}\n"
    
    texte_alerte += f"\n{'='*70}\n\n"
    return texte_alerte

def generer_rapport_mitigation_detaille(cves_critiques):
    """Genere un rapport complet de mitigation"""
    horodatage = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    
    rapport = f"""
{'='*80}
                    RAPPORT DE MITIGATION - CVE CRITIQUES
                    Date: {horodatage}
{'='*80}

RESUME EXECUTIF:
----------------
Total de vulnerabilites critiques detectees : {len(cves_critiques)}
Score CVSS minimum                           : {SCORE_CVSS_MINIMUM}
Periode d'analyse                            : 30 derniers jours

LOGICIELS SURVEILLES:
---------------------"""
    
    for logiciel in LOGICIELS_SURVEILLES:
        rapport += f"\n  • {logiciel.capitalize()}"
    
    rapport += f"\n\n{'='*80}\n\n"
    

    stats_logiciels = {}
    for logiciel in LOGICIELS_SURVEILLES:
        compte = sum(1 for cve in cves_critiques 
                    if logiciel.capitalize() in cve['logiciels_affectes'])
        stats_logiciels[logiciel] = compte
    
    rapport += "STATISTIQUES PAR LOGICIEL:\n"
    rapport += "-" * 80 + "\n"
    for logiciel, nombre in stats_logiciels.items():
        rapport += f"  {logiciel.capitalize():<15} : {nombre} vulnerabilites\n"
    
    rapport += f"\n{'='*80}\n\n"
    
    rapport += "DETAIL DES VULNERABILITES:\n"
    rapport += "=" * 80 + "\n\n"
    
    for index, cve in enumerate(cves_critiques, 1):
        rapport += f"{index}. {cve['id']}\n"
        rapport += f"   {'-'*76}\n"
        rapport += f"   Score CVSS       : {cve['cvss_score']} ({cve['severity']})\n"
        rapport += f"   Logiciels affectes: {', '.join(cve['logiciels_affectes'])}\n"
        rapport += f"   Date de publication: {cve['date_publiee'][:10]}\n"
        rapport += f"   Vecteur d'attaque : {cve['vector']}\n\n"
        
        rapport += f"   DESCRIPTION:\n"
        description_tronquee = cve['description'][:400] + '...' if len(cve['description']) > 400 else cve['description']
        rapport += f"   {description_tronquee}\n\n"
        
        rapport += f"   MESURES DE MITIGATION RECOMMANDEES:\n"
        rapport += f"   ✓ Appliquer immediatement les correctifs de securite disponibles\n"
        rapport += f"   ✓ Verifier les versions des logiciels dans votre infrastructure\n"
        rapport += f"   ✓ Isoler les systemes vulnerables si les correctifs ne sont pas disponibles\n"
        rapport += f"   ✓ Augmenter la surveillance des systemes affectes\n"
        rapport += f"   ✓ Consulter les bulletins de securite officiels\n\n"
        
        if cve['references']:
            rapport += f"   REFERENCES OFFICIELLES:\n"
            for reference in cve['references']:
                rapport += f"   • {reference}\n"
        
        rapport += f"\n   {'-'*76}\n\n"
    
    rapport += f"\n{'='*80}\n"
    rapport += "FIN DU RAPPORT\n"
    rapport += f"{'='*80}\n"
    
    return rapport

def sauvegarder_alertes_cve(cves_critiques):
    """Sauvegarde les alertes dans un fichier"""
    try:
        with open(FICHIER_ALERTES, 'w', encoding='utf-8') as fichier:
            horodatage = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            fichier.write(f"ALERTES CVE - {horodatage}\n")
            fichier.write("="*70 + "\n\n")
            
            for cve in cves_critiques:
                alerte = generer_texte_alerte(cve)
                fichier.write(alerte)
        
        logger.info("Alertes sauvegardees dans: %s", FICHIER_ALERTES)
        return True
    except IOError as erreur:
        logger.error("Erreur lors de la sauvegarde des alertes: %s", erreur)
        return False

def sauvegarder_rapport_mitigation(rapport_texte):
    """Sauvegarde le rapport de mitigation"""
    try:
        with open(FICHIER_RAPPORT, 'w', encoding='utf-8') as fichier:
            fichier.write(rapport_texte)
        
        logger.info("Rapport sauvegarde dans: %s", FICHIER_RAPPORT)
        return True
    except IOError as erreur:
        logger.error("Erreur lors de la sauvegarde du rapport: %s", erreur)
        return False

def afficher_resume_execution(cves_critiques):
    """Affiche un resume dans la console"""
    print("\n" + "="*70)
    print(" RESUME DE LA VEILLE")
    print("="*70)
    print(f"Total CVE critiques trouvees : {len(cves_critiques)}")
    
    if cves_critiques:
        print("\n CVE les plus critiques:")
        for i, cve in enumerate(cves_critiques[:5], 1):
            logiciels_formates = ', '.join(cve['logiciels_affectes'])
            print(f"  {i}. {cve['id']} - Score: {cve['cvss_score']} - {logiciels_formates}")
    
    print("="*70 + "\n")

def executer_veille():
    """Fonction principale d'execution de la veille"""
    print("\n" + "="*70)
    print(" DEMARRAGE DE LA VEILLE CVE")
    print("="*70)
    
    horodatage = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    print(f" Date et heure: {horodatage}")
    
    logiciels_formates = ', '.join([logiciel.capitalize() for logiciel in LOGICIELS_SURVEILLES])
    print(f" Logiciels surveilles: {logiciels_formates}")
    print(f" Score CVSS minimum: {SCORE_CVSS_MINIMUM}")
    
    print("\n" + "-"*70 + "\n")
    
    donnees_api = interroger_nvd_api()
    if donnees_api is None:
        print(" Echec de la recuperation des donnees")
        return
    
    time.sleep(1)
    
    cves_critiques = filtrer_cves(donnees_api)
    
    if not cves_critiques:
        print(" Aucune vulnerabilite critique trouvee")
        return
    
    print("\n Generation des alertes...")
    resultat_alertes = sauvegarder_alertes_cve(cves_critiques)
    if not resultat_alertes:
        print(" Erreur lors de la sauvegarde des alertes")
        return
    
    print(" Generation du rapport de mitigation...")
    rapport = generer_rapport_mitigation_detaille(cves_critiques)
    resultat_rapport = sauvegarder_rapport_mitigation(rapport)
    if not resultat_rapport:
        print(" Erreur lors de la sauvegarde du rapport")
        return
    
    afficher_resume_execution(cves_critiques)
    
    print(" Veille terminee avec succes!\n")

if __name__ == "__main__":
    # Configuration basique du logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    executer_veille()