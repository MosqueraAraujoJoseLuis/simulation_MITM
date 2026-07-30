# CryptoSim Laboratory - Simulateur d'Attaques MITM

Ce module interactif est un laboratoire éducatif conçu pour simuler et analyser les vulnérabilités de sécurité face à une attaque de type **Man-in-the-Middle (MITM)**. Il permet d'étudier le rôle de différents protocoles cryptographiques et d'observer comment la configuration des paramètres de sécurité impacte directement la confidentialité, l'authenticité et l'intégrité des communications.

---

## 1. Technologies Utilisées

L'application est entièrement construite côté client (Frontend) sans base de données ni serveur requis :

- **HTML5** : Structuration de l'application et des composants interactifs.
- **CSS3 (Vanilla CSS)** : Design moderne et immersif inspiré du style *cyberpunk* et du *glassmorphism* (panneaux translucides avec flous d'arrière-plan, ombres dynamiques réactives au niveau de risque, animations fluides).
- **JavaScript (ES6+)** : Logique de l'application, gestion des états dynamiques et animations des paquets en transit.
- **Web Crypto API (`window.crypto.subtle`)** : Utilisation des fonctions cryptographiques natives du navigateur pour les opérations réelles en mémoire (génération de paires de clés RSA, dérivation de clés AES via PBKDF2 avec sel, chiffrement/déchiffrement AES-CBC et AES-GCM, hachage SHA-256, et génération/vérification de signatures numériques RSA-PSS).

---

## 2. Bibliothèques Nécessaires

Afin de simplifier le déploiement et de garantir un fonctionnement sans compilation préalable, toutes les dépendances externes sont chargées via des réseaux de diffusion de contenu (CDN) :

- **Bootstrap 5.3.3 (JS Bundle & CSS)** : Utilisé pour la structure en grille responsive, les boutons et les composants de base.
- **FontAwesome 6** : Fournit les icônes interactives de l'interface.
- *Aucun gestionnaire de paquets (npm/yarn) n'est requis.*

---

## 3. Étapes d'Installation

1. Téléchargez ou clonez le dépôt localement sur votre ordinateur.
2. Extrayez l'archive ZIP si vous avez téléchargé le projet sous ce format.
3. Assurez-vous d'avoir un navigateur récent (Firefox, Chrome, Edge ou Safari) installé.

---

## 4. Procédure pour Lancer l'Application

> [!IMPORTANT]  
> Pour des raisons de sécurité, les navigateurs modernes restreignent l'accès à la Web Crypto API (`crypto.subtle`) sur les pages chargées via le protocole `file://` (par exemple, en double-cliquant directement sur le fichier `index.html` depuis l'explorateur de fichiers).

Pour utiliser toutes les fonctionnalités de chiffrement réel, lancez l'application par l'une des deux méthodes suivantes :

### Option A : Utilisation de Mozilla Firefox (La plus simple en local)
Ouvrez simplement le fichier `index.html` (à la racine ou dans le dossier `simulation/`) avec le navigateur **Mozilla Firefox**. Ce navigateur autorise par défaut l'utilisation de la Web Crypto API sur les fichiers locaux.

### Option B : Lancement via un serveur local (Recommandé)
Démarrez un serveur Web léger dans le répertoire du projet. Si vous disposez de Python, exécutez la commande suivante dans un terminal ouvert dans le dossier racine :

```bash
python -m http.server 8000
```

Ouvrez ensuite votre navigateur et accédez à l'adresse suivante :
`http://localhost:8000/simulation/index.html` (ou `http://localhost:8000` pour accéder à la page d'accueil globale).

---

## 5. Fonctionnement des Expériences

Le simulateur permet de tester et de visualiser le comportement de quatre méthodes cryptographiques majeures : **AES**, **RSA**, **SHA-256** et la **Signature Numérique**.

### Étape 1 : Configuration
1. **Méthode** : Sélectionnez l'algorithme à tester dans la barre de filtres supérieure.
2. **Scénario** : Choisissez le scénario dans le menu déroulant (ex: canal sécurisé, vol de clé, modification active, substitution de clé publique).
3. **Options dynamiques** : Ajustez les options de sécurité (activer/désactiver le vecteur d'initialisation IV ou le tag GCM pour AES, modifier la taille de la clé ou activer l'authentification de l'empreinte pour RSA).
4. **Observation** : La description théorique et la **Fiche de Résultats** se mettent instantanément à jour pour refléter le niveau de risque (Faible, Moyen, Élevé, Critique) ainsi que les capacités théoriques d'interception d'Eve.

### Étape 2 : Communication Aller (Alice ➔ Bob)
1. Saisissez le message de votre choix dans le champ de texte d'Alice.
2. Cliquez sur **Démarrer la communication**.
3. **Transit** : Le paquet de données se déplace d'Alice vers Eve. Si Alice détecte une mauvaise empreinte (scénario avec authentification active), elle bloque l'envoi immédiatement.
4. **Interception d'Eve** : Le paquet s'arrête chez Eve. Selon le scénario :
   - *Interception passive* : Eve lit le message (si en clair ou clé connue) ou ne voit qu'un flux chiffré illisible.
   - *Interception active* : Si Eve peut modifier les données, la simulation se met en pause. Vous pouvez alors modifier le texte affiché dans la console d'Eve avant de cliquer sur **Transmettre (Eve)**.
5. **Réception de Bob** : Bob reçoit le paquet et tente de le valider/déchiffrer. Un statut de réussite ou d'erreur s'affiche sur sa carte d'acteur.

### Étape 3 : Réponse et Retour (Bob ➔ Alice)
1. Cliquez sur **Répondre (Bob)** pour démarrer le voyage retour du message.
2. La même logique de transit et d'interception (passive ou active) s'applique lors du retour vers Alice.
3. Alice reçoit et traite la réponse. Si une altération est détectée (ex: erreur de signature ou tag GCM invalide), Alice rejette le message.
4. **Consoles d'acteurs** : Tout au long de l'expérience, les terminaux individuels d'Alice, d'Eve et de Bob détaillent les opérations cryptographiques en arrière-plan (ex: hexadécimal des clés, IV générés, hachages calculés, signatures créées).
5. **Logs système** : Le terminal inférieur retrace l'historique complet de l'expérience. Une fois terminée, la simulation est prête à être relancée ou réinitialisée.
