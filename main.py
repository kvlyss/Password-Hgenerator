import getpass
import re
import hashlib
import os

def demander_mot_de_passe():
    while True:
        mot_de_passe = getpass.getpass("Veuillez entrer votre mot de passe : ")

        # Vérifier les conditions du mot de passe
        if (len(mot_de_passe) >= 8 and
            re.search(r'[A-Z]', mot_de_passe) and
            re.search(r'[a-z]', mot_de_passe) and
            re.search(r'[0-9]', mot_de_passe) and
            re.search(r'[!@#$%^&*]', mot_de_passe)):
            print("Mot de passe valide.")
            return mot_de_passe
        else:
            print("Le mot de passe doit contenir au moins 8 caractères, une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial (!, @, #, $, %, ^, &, *).")

def generer_sel():
    # Générer un sel aléatoire de 16 octets
    return os.urandom(16).hex()

def hasher_mot_de_passe(mot_de_passe, sel):
    # Concaténer le sel avec le mot de passe et hacher le résultat
    mot_de_passe_sale = sel + mot_de_passe
    hashed_mot_de_passe = hashlib.sha256(mot_de_passe_sale.encode()).hexdigest()
    return hashed_mot_de_passe

def enregistrer_mot_de_passe(mot_de_passe_hashe, sel, fichier='mots_de_passe.txt'):
    with open(fichier, 'a') as file:
        file.write(f"{sel}:{mot_de_passe_hashe}\n")

# Exemple d'utilisation des fonctions
mot_de_passe_utilisateur = demander_mot_de_passe()
sel = generer_sel()
mot_de_passe_hashe = hasher_mot_de_passe(mot_de_passe_utilisateur, sel)
enregistrer_mot_de_passe(mot_de_passe_hashe, sel)
print("Mot de passe haché et enregistré avec succès.")
