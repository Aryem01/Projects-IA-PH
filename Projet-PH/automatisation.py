import schedule
import time
import logging
from datetime import datetime
from veille_cve import executer_veille


def setup_logging():
    """Configure un système de logging robuste"""
    
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    
    file_handler = logging.FileHandler('veille.log', encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)  
    
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


logger = setup_logging()

def tache_quotidienne():
    """Tâche exécutée quotidiennement avec logging"""
    logger.info(" Démarrage de la veille CVE quotidienne")
    
    try:
        executer_veille()
        logger.info(" Veille terminée avec succès")
        
        
        with open('alertes_cve.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            alertes_count = len([l for l in lines if 'ALERTE CRITIQUE' in l])
        logger.info(f" {alertes_count} alertes générées")
        
    except Exception as e:
        logger.error(f" Erreur lors de la veille: {str(e)}", exc_info=True)
        
def main():
    """Fonction principale d'automatisation"""
    logger.info("="*50)
    logger.info(" SYSTÈME DE VEILLE CVE AUTOMATISÉ")
    logger.info("="*50)
    logger.info(f" Date: {datetime.now().strftime('%d/%m/%Y')}")
    logger.info(" Planification: Tous les jours à 9h00")
    logger.info(" Logiciels surveillés: Apache, WordPress, OpenSSL")
    logger.info(" Score minimum: CVSS 9.0")
    logger.info("="*50)
    
    
    logger.info(" Exécution initiale...")
    tache_quotidienne()
    
    
    schedule.every().day.at("09:00").do(tache_quotidienne)
    logger.info(" Planification configurée - prochaine exécution à 9h00")
    
    
    logger.info(" Démarrage de la boucle principale")
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(60)
            
            
            if datetime.now().minute == 0:
                logger.debug(" Heartbeat - système actif")
                
        except KeyboardInterrupt:
            logger.info(" Arrêt manuel du système")
            break
        except Exception as e:
            logger.critical(f" Erreur critique dans la boucle principale: {e}")
            time.sleep(300)  

if __name__ == "__main__":
    main()