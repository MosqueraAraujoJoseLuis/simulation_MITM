// ==========================================
// TRACÉ DÉTAILLÉ DE L'EXPÉRIENCE (CRYPTO RÉELLE)
// ==========================================
let currentSimulationTrace = {
    sender: {},
    transit: {},
    eve: {},
    receiver: {},
    isForward: true
};

function renderSimulationTrace() {
    const container = document.getElementById("trace-container");
    const emptyMsg = document.getElementById("trace-empty");
    if (!container || !emptyMsg) return;

    container.classList.remove("d-none");
    emptyMsg.classList.add("d-none");

    const contentDiv = document.getElementById("trace-results-content");
    if (!contentDiv) return;

    const method = document.getElementById("mitm-method").value;
    let html = '';
    
    const createCard = (title, value, icon, colorClass = "primary") => {
        if (!value) return '';
        let valColor = "";
        if (typeof value === "string") {
            if (value.includes("❌") || (value.includes("Oui") && colorClass==="danger") || value.includes("Vulnérabilité") || (value.includes("Non") && colorClass==="danger")) {
                valColor = "text-danger fw-bold";
            } else if (value.includes("✅") || (value.includes("Non") && colorClass==="success") || (value.includes("Oui") && colorClass==="success") || value.includes("Bloqué")) {
                valColor = "text-success fw-bold";
            }
        }
        
        let isTextarea = value.length > 35 || value.includes("\n") || value.includes("\r");
        let inputHtml = '';
        
        let colorStyle = "";
        if (valColor.includes("text-danger")) colorStyle = "color: #ff4d4d !important;";
        else if (valColor.includes("text-success")) colorStyle = "color: #28a745 !important;";

        if (isTextarea) {
            inputHtml = `<textarea class="form-control text-monospace bg-dark border-secondary fw-bold" style="font-size: 0.72rem; height: 65px; resize: none; font-family: var(--font-mono); padding: 4px 6px; line-height: 1.25; ${colorStyle ? colorStyle : 'color: white;'}" readonly>${value}</textarea>`;
        } else {
            inputHtml = `<input type="text" class="form-control text-monospace bg-dark border-secondary fw-bold" style="font-size: 0.75rem; height: 28px; font-family: var(--font-mono); padding: 2px 6px; ${colorStyle ? colorStyle : 'color: white;'}" value="${value}" readonly>`;
        }

        return `
        <div class="col-12 col-md-6 col-lg-4">
            <div class="glass-panel-inner p-3 h-100 border-start border-3 border-${colorClass}">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0 fw-bold"><i class="fa-solid ${icon} me-2 text-${colorClass}"></i>${title}</h6>
                    <button class="btn btn-secondary btn-copy btn-xs-copy py-0 px-2" type="button" onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.value)">
                        <i class="fa-solid fa-copy me-1"></i>Copier
                    </button>
                </div>
                ${inputHtml}
            </div>
        </div>`;
    };

    const s = currentSimulationTrace.sender || {};
    const t = currentSimulationTrace.transit || {};
    const e = currentSimulationTrace.eve || {};
    const r = currentSimulationTrace.receiver || {};
    
    const plaintext = s["Message Original"] || s["Message Réponse"] || "(Vide)";
    
    // Eve Action Format
    let eveContent = "";
    if (Object.keys(e).length > 0) {
        eveContent = Object.entries(e).map(([k, v]) => `<strong>${k}:</strong> ${v}`).join('<br>');
    } else {
        eveContent = "Aucune altération cryptographique.";
    }

    if (method === "aes") {
        html += createCard("Message en clair", plaintext, "fa-align-left", "info");
        html += createCard("Message chiffré", t["Ciphertext (Base64)"], "fa-lock", "warning");
        html += createCard("Clé secrète", document.getElementById("aes-enc-key") ? (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)") : null, "fa-key", "primary");
        html += createCard("Salt", s["Salt PBKDF2 (Base64)"], "fa-cubes", "secondary");
        html += createCard("IV / Nonce", s["IV / Nonce (Base64)"], "fa-random", "secondary");
        html += createCard("Tag d'authentification", s["Tag GCM (Base64)"], "fa-check-double", "success");
        html += createCard("Bloc encapsulé (Base64)", t["Bloque Empaquetado"], "fa-box-open", "primary");
        html += createCard("MITM : Ce qu'obtient Eve", eveContent, "fa-user-ninja", "danger");
    } 
    else if (method === "rsa") {
        const size = document.getElementById("mitm-rsa-size") ? document.getElementById("mitm-rsa-size").value : "N/A";
        const rxPub = document.getElementById("rsa-enc-bob-pub") ? document.getElementById("rsa-enc-bob-pub").value : "";
        const rxPriv = document.getElementById("rsa-enc-bob-priv") ? document.getElementById("rsa-enc-bob-priv").value : "";
        const txPub = document.getElementById("rsa-enc-alice-pub") ? (document.getElementById("rsa-enc-alice-pub") ? document.getElementById("rsa-enc-alice-pub").value : "(non disponible)") : "";
        const txPriv = document.getElementById("rsa-enc-alice-priv") ? (document.getElementById("rsa-enc-alice-priv") ? document.getElementById("rsa-enc-alice-priv").value : "(non disponible)") : "";
        
        let rxKeys = "Publique: " + (rxPub ? "..." + rxPub.slice(-40) : "N/A") + "\\nPrivée: " + (rxPriv ? "..." + rxPriv.slice(-40) : "N/A");
        let txKeys = "Publique: " + (txPub ? "..." + txPub.slice(-40) : "N/A") + "\\nPrivée: " + (txPriv ? "..." + txPriv.slice(-40) : "N/A");

        html += createCard("Message en clair", plaintext, "fa-align-left", "info");
        html += createCard("Message chiffré", t["Ciphertext RSA (Base64)"], "fa-lock", "warning");
        html += createCard("Taille de la clé", size + " bits", "fa-ruler", "secondary");
        html += createCard("Clés du destinataire (Bob)", rxKeys, "fa-key", "primary");
        html += createCard("Clés de l'émetteur (Alice)", txKeys, "fa-key", "primary");
        html += createCard("Empreinte de la clé publique", s["Fingerprint"] || "Empreinte non générée / Intégrée au certificat", "fa-fingerprint", "success");
        html += createCard("MITM : Ce qu'obtient Eve", eveContent, "fa-user-ninja", "danger");
    }
    else if (method === "sha") {
        html += createCard("Message en clair", plaintext, "fa-align-left", "info");
        html += createCard("Empreinte SHA-256 (Hexadécimal)", s["Hash SHA-256 (Hex)"], "fa-hashtag", "warning");
        html += createCard("MITM : Ce qu'obtient Eve", eveContent, "fa-user-ninja", "danger");
    }
    else if (method === "sig") {
        const txPub = document.getElementById("sign-pub-key") ? (document.getElementById("sign-pub-key") ? document.getElementById("sign-pub-key").value : "(non disponible)") : "";
        const txPriv = document.getElementById("sign-priv-key") ? (document.getElementById("sign-priv-key") ? document.getElementById("sign-priv-key").value : "(non disponible)") : "";
        let txKeys = "Publique: " + (txPub ? "..." + txPub.slice(-40) : "N/A") + "\\nPrivée: " + (txPriv ? "..." + txPriv.slice(-40) : "N/A");

        html += createCard("Message en clair", plaintext, "fa-align-left", "info");
        html += createCard("Clés de l'émetteur", txKeys, "fa-key", "primary");
        html += createCard("Signature numérique", t["Signature (Base64)"], "fa-signature", "warning");
        html += createCard("MITM : Ce qu'obtient Eve", eveContent, "fa-user-ninja", "danger");
    }

    if (r["Validation"]) {
        html += createCard("Résultat Destinataire", r["Validation"], "fa-clipboard-check", r["Validation"].includes("❌") ? "danger" : "success");
    } else if (r["Message Déchiffré"]) {
        html += createCard("Message déchiffré (Destinataire)", r["Message Déchiffré"], "fa-unlock", "success");
    }

    // --- NEW Q&A RISK ANALYSIS ---
    // In MITM scenarios, Eve always intercepts
    const isIntercepted = "Oui"; 
    
    // Check if there's any modification in the trace
    let isModified = false;
    if (e["Action"] && (e["Action"].includes("Altération") || e["Action"].includes("Modification") || e["Action"].includes("Substitution") || e["Action"].includes("Création d'un faux"))) isModified = true;
    if (e["Ciphertext Altéré (Base64)"] || e["Bloque Empaquetado Altéré"] || e["Signature (Base64)"] || e["Message en clair Altéré"]) isModified = true;
    
    // Check if Eve changed the text during pause (canModify check)
    const methodEl = document.getElementById("mitm-method");
    const scenarioIdEl = document.getElementById("mitm-scenario");
    let currentSc = null;
    if (methodEl && scenarioIdEl) {
        currentSc = getDynamicState(methodEl.value, scenarioIdEl.value);
    }
    if (currentSc && currentSc.canModify === "Oui") {
        const eveMsg = document.getElementById("mitm-message-input") ? document.getElementById("mitm-message-input").value : "";
        if (plaintext && eveMsg !== plaintext) isModified = true;
    }

    let isDetected = false;
    if (r["Validation"] && (r["Validation"].includes("❌") || r["Validation"].includes("Erreur"))) {
        isDetected = true;
    }
    const aliceCard = document.getElementById("card-alice");
    const bobCard = document.getElementById("card-bob");
    if (aliceCard && aliceCard.classList.contains("border-danger")) isDetected = true;
    if (bobCard && bobCard.classList.contains("border-danger")) isDetected = true;

    html += `<div class="col-12 mt-4 mb-2"><h6 class="text-info border-bottom border-secondary pb-1"><i class="fa-solid fa-shield-halved me-2"></i>Analyse des Risques</h6></div>`;
    
    // Interception
    html += createCard("Message intercepté par Eve ?", "Oui", "fa-user-secret", "danger");
    
    // Modification
    if (isModified) {
        html += createCard("Modification en transit ?", "Oui", "fa-user-edit", "danger");
        
        if (isDetected) {
            html += createCard("Modification détectée par le destinataire ?", "Oui (Bloqué)", "fa-shield-virus", "success");
        } else {
            html += createCard("Modification détectée par le destinataire ?", "Non (Vulnérabilité !)", "fa-biohazard", "danger");
        }
    } else {
        html += createCard("Modification en transit ?", "Non", "fa-check", "success");
    }

    contentDiv.innerHTML = html;
}

// Helpers
function buf2base64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
function base642buf(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

// Overwrite startSimulation
window.startSimulation = async function() {
    isSimulationRunning = true;
    currentDirection = "forward";
    currentSimulationTrace = { sender: {}, transit: {}, eve: {}, receiver: {}, isForward: true };
    renderSimulationTrace();

    const track = document.querySelector(".animation-track-container");
    if (track) track.scrollIntoView({ behavior: "smooth", block: "center" });

    const method = document.getElementById("mitm-method").value;
    const scenarioId = document.getElementById("mitm-scenario").value;
    const sc = getDynamicState(method, scenarioId);
    updateAvatarShadows(sc.risk);

    document.getElementById("mitm-btn-start").disabled = true;
    document.getElementById("mitm-btn-stop").disabled = false;
    document.getElementById("mitm-method").disabled = true;
    document.getElementById("mitm-scenario").disabled = true;

    if (simulationStepCount === 1) {
        document.getElementById("mitm-logs").innerHTML = "";
        clearActorConsoles();
        updateResultsCard(null, true);
    }
    resetActorCards();

    setMitMInputAuthor("Alice", true);
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";

    addLog("system", `Démarrage de la simulation (Étape ${simulationStepCount}) : ${sc.name}`);
    addActorConsoleLog("alice", "Création et préparation du message.", "console-header");
    addActorConsoleLog("alice", `Texte: "${messageText}"`);

    // --- CHAT: Alice envoie ---
    try {
        if (window.addChatMessage) {
            window.addChatMessage("Alice", messageText, "Envoyé");
        }
    } catch (e) {
        console.error("Chat message error (Alice): ", e);
    }

    // --- REAL CRYPTO ALICE ---
    try {
        currentSimulationTrace.sender["Message Original"] = messageText;
        const msgUint8 = new TextEncoder().encode(messageText);

        if (method === "aes") {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;
            const rawKeyBase64 = (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)") || "secret";
            
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            currentSimulationTrace.sender["Salt PBKDF2 (Base64)"] = buf2base64(salt);
            
            const aesKey = await deriveAesKey(rawKeyBase64, salt, isGcm ? "AES-GCM" : "AES-CBC");
            currentSimulationTrace.sender["Clé AES Derivée"] = "Générée en mémoire via PBKDF2";
            
            const ivLen = isGcm ? 12 : 16;
            const iv = isIv ? window.crypto.getRandomValues(new Uint8Array(ivLen)) : new Uint8Array(ivLen);
            currentSimulationTrace.sender["IV / Nonce (Base64)"] = buf2base64(iv);
            
            const algoName = isGcm ? "AES-GCM" : "AES-CBC";
            const algoObj = isGcm ? { name: "AES-GCM", iv: iv, tagLength: 128 } : { name: "AES-CBC", iv: iv };
            
            const encryptedBuffer = await window.crypto.subtle.encrypt(algoObj, aesKey, msgUint8);
            
            let ciphertextBuf, tagBuf;
            if (isGcm) {
                ciphertextBuf = encryptedBuffer.slice(0, encryptedBuffer.byteLength - 16);
                tagBuf = encryptedBuffer.slice(encryptedBuffer.byteLength - 16);
                currentSimulationTrace.sender["Tag GCM (Base64)"] = buf2base64(tagBuf);
            } else {
                ciphertextBuf = encryptedBuffer;
            }
            
            const cipherBase64 = buf2base64(ciphertextBuf);
            currentSimulationTrace.transit["Ciphertext (Base64)"] = cipherBase64;
            
            // Packed
            const totalLen = salt.length + iv.length + ciphertextBuf.byteLength + (isGcm ? tagBuf.byteLength : 0);
            const packed = new Uint8Array(totalLen);
            let offset = 0;
            packed.set(salt, offset); offset += salt.length;
            packed.set(iv, offset); offset += iv.length;
            packed.set(new Uint8Array(ciphertextBuf), offset); offset += ciphertextBuf.byteLength;
            if (isGcm) packed.set(new Uint8Array(tagBuf), offset);
            
            currentSimulationTrace.transit["Bloque Empaquetado"] = buf2base64(packed);
            
        } else if (method === "rsa") {
            const pubPem = document.getElementById("rsa-enc-bob-pub").value;
            if (pubPem) {
                currentSimulationTrace.sender["Clé Publique Bob (PEM)"] = pubPem;
                const pubKey = await importKeyFromPem(pubPem, "encrypt");
                const encryptedBuffer = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, msgUint8);
                currentSimulationTrace.transit["Ciphertext RSA (Base64)"] = buf2base64(encryptedBuffer);
            } else {
                currentSimulationTrace.transit["Erreur"] = "Clé publique de Bob manquante.";
            }
        } else if (method === "sha") {
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            currentSimulationTrace.sender["Hash SHA-256 (Hex)"] = hashHex;
            currentSimulationTrace.transit["Message + Hash"] = `Msg: ${messageText}\nHash: ${hashHex}`;
        } else if (method === "sig") {
            const privPem = (document.getElementById("sign-priv-key") ? document.getElementById("sign-priv-key").value : "(non disponible)");
            if (privPem) {
                currentSimulationTrace.sender["Clé Privée Alice (Extrait)"] = "..." + privPem.slice(-40);
                const privKey = await importKeyFromPem(privPem, "sign");
                const sigBuffer = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, privKey, msgUint8);
                currentSimulationTrace.transit["Signature (Base64)"] = buf2base64(sigBuffer);
                currentSimulationTrace.transit["Message en clair"] = messageText;
            } else {
                currentSimulationTrace.transit["Erreur"] = "Clé privée manquante.";
            }
        }
    } catch (e) {
        console.error(e);
        currentSimulationTrace.sender["Erreur Crypto"] = e.message;
    }
    renderSimulationTrace();

    const packet = document.getElementById("packet");
    packet.style.display = "flex";
    packet.className = "data-packet";
    packet.style.left = "16.66%";
    setActiveNode("node-alice");

    addLog("alice", "Création et préparation du message (Crypto Réelle générée).");
    document.getElementById("state-alice").textContent = "Envoi en cours...";
    document.getElementById("card-alice").classList.add("border-primary");

    let isSecurePacket = (sc.risk === "Faible");
    let isWarningPacket = (sc.risk === "Moyen");

    if (isSecurePacket) {
        packet.classList.add("secure");
    } else if (isWarningPacket) {
        packet.classList.add("warning");
    } else {
        packet.classList.add("compromised");
    }

    if (sc.intercepted && sc.intercepted.includes("Non")) {
        setTimeout(() => {
            if (!isSimulationRunning) return;
            addLog("alice", "⚠️ Vérification de l'empreinte de la clé reçue.");
            addLog("alice", "❌ L'empreinte ne correspond pas ! Risque d'attaque MITM détecté.");
            addLog("alice", "Alice bloque immédiatement la communication.");
            document.getElementById("state-alice").textContent = "Envoi Bloqué ❌";
            document.getElementById("card-alice").classList.remove("border-primary");
            document.getElementById("card-alice").classList.add("border-danger");
            packet.style.display = "none";
            
            currentSimulationTrace.transit["Status"] = "Bloqué - Empreinte invalide";
            renderSimulationTrace();

            setTimeout(() => {
                if (!isSimulationRunning) return;
                addLog("system", "Simulation terminée. L'attaque MITM a été déjouée.");
                updateResultsCard(sc);
                stopSimulationState();
            }, 1500);
        }, 1500);
        return;
    }

    animatePacket("16.66%", "50%", 1500, () => {
        if (!isSimulationRunning) return;
        setActiveNode("node-eve");
        document.getElementById("state-alice").textContent = "Message envoyé";
        document.getElementById("state-eve").textContent = "Interception...";
        document.getElementById("card-eve").classList.add("active-eve");

        addLog("eve", "Message intercepté en transit.");
        addActorConsoleLog("eve", "Interception du message d'Alice.", "console-header");
        simulateEveBehavior(sc, "forward", () => {
            if (!isSimulationRunning) return;
            resumeFromEveForward(sc);
        });
    });
};

window.simulateEveBehavior = async function(sc, direction, callback) {
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    setTimeout(async () => {
        // EXACT ORIGINAL LOGS WITH TRACE UPDATES
        if (sc.id.startsWith("aes")) {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;

            if (sc.id === "aes-a") {
                addLog("eve", `Texte intercepté : cryptogramme AES Base64 en mode ${isGcm ? "GCM" : "CBC"}.`);
                if (!isIv) {
                    addLog("eve", "Eve remarque l'absence d'un IV aléatoire (IV fixe/vide). Elle peut identifier la répétition de messages identiques.");
                } else {
                    addLog("eve", "L'utilisation d'un IV aléatoire garantit le caractère unique du cryptogramme intercepté.");
                }
                addLog("eve", "Impossible de déchiffrer sans la clé secrète partagée.");
                
                currentSimulationTrace.eve["Action"] = "Lecture impossible, données chiffrées.";
            } else if (sc.id === "aes-b") {
                addLog("eve", `Clé secrète obtenue ! Déchiffrement AES-${isGcm ? "GCM" : "CBC"} du message en clair réussi.`);
                addLog("eve", `Text: ${messageText}`);
                
                currentSimulationTrace.eve["Clé secrète Volée"] = (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)");
                currentSimulationTrace.eve["Action"] = "Déchiffrement réussi, copie envoyée à Bob.";
            } else if (sc.id === "aes-c") {
                addLog("eve", "Altération arbitraire de quelques bits dans le texte chiffré intercepté.");
                if (isGcm) {
                    addLog("eve", "Eve ne peut pas forger un tag d'authentification GCM valide sans la clé secrète.");
                } else {
                    addLog("eve", "Comme le mode est CBC (sans tag), Eve espère que l'altération passera inaperçue.");
                }

                if (currentSimulationTrace.transit["Ciphertext (Base64)"]) {
                    const ct = base642buf(currentSimulationTrace.transit["Ciphertext (Base64)"]);
                    if (ct.length > 0) ct[0] ^= 0x01; // Flip 1 bit
                    currentSimulationTrace.eve["Ciphertext Altéré (Base64)"] = buf2base64(ct);
                    currentSimulationTrace.eve["Action"] = "Altération d'un bit dans le Ciphertext.";
                    
                    // Repack for transit
                    if (currentSimulationTrace.transit["Bloque Empaquetado"]) {
                        const packed = base642buf(currentSimulationTrace.transit["Bloque Empaquetado"]);
                        const offset = 16 + (isGcm ? 12 : 16);
                        if (packed.length > offset) packed[offset] ^= 0x01;
                        currentSimulationTrace.eve["Bloque Empaquetado Altéré"] = buf2base64(packed);
                    }
                }
            }
        }
        else if (sc.id.startsWith("rsa")) {
            const keySize = document.getElementById("mitm-rsa-size").value;
            if (sc.id === "rsa-a") {
                addLog("eve", `Copie de la clé publique de Bob (${keySize} bits) interceptée.`);
                if (keySize === "1024") {
                    addLog("eve", "⚠️ Clé de 1024 bits interceptée ! Eve pourrait tenter une attaque par factorisation mathématique avec des supercalculateurs.");
                } else {
                    addLog("eve", `Clé robuste de ${keySize} bits interceptée. La factorisation de la clé publique est impossible.`);
                }
                addLog("eve", "Cryptogramme intercepté, mais la clé privée de Bob reste secrète. Lecture impossible.");
                currentSimulationTrace.eve["Action"] = "Interception passive.";
            } else if (sc.id === "rsa-b" || sc.id === "rsa-c") {
                addLog("eve", "Interception de la clé publique de Bob en transit.");
                addLog("eve", `Substitution de clé : Eve transmet sa propre clé publique (${keySize} bits) à Alice.`);
                addLog("eve", "Message d'Alice chiffré sous la clé d'Eve reçu. Déchiffrement avec la clé privée d'Eve : Lecture et modification.");
                addLog("eve", `Text: ${messageText}`);
                addLog("eve", `Re-chiffrement du message modifié avec la vraie clé publique de Bob (${keySize} bits).`);
                currentSimulationTrace.eve["Action"] = "Substitution de clé publique !";
            }
        }
        else if (sc.id.startsWith("sha")) {
            if (sc.id === "sha-a") {
                addLog("eve", "Copie du message et de son empreinte SHA-256. Passage passif.");
            } else if (sc.id === "sha-b") {
                addLog("eve", "Modification du contenu du message intercepté.");
            } else if (sc.id === "sha-c") {
                addLog("eve", "Lancement d'une recherche d'attaque par dictionnaire sur l'empreinte SHA-256 interceptée.");
            } else if (sc.id === "sha-d") {
                addLog("eve", "Modification du message intercepté ET calcul d'une nouvelle empreinte SHA-256 correspondante.");
            }
        }
        else if (sc.id.startsWith("sig")) {
            if (sc.id === "sig-a") {
                addLog("eve", "Lecture du message en clair. Interception de la signature d'Alice. Aucun pouvoir de modification sans la clé privée d'Alice.");
            } else if (sc.id === "sig-b") {
                addLog("eve", "Altération du message en clair mais conservation de la signature originale.");
                currentSimulationTrace.eve["Action"] = "Modification du message, signature originale conservée.";
                currentSimulationTrace.eve["Message en clair Altéré"] = currentSimulationTrace.transit["Message en clair"] + " (modifié)";
            } else if (sc.id === "sig-c") {
                addLog("eve", "Création d'un faux message et d'une signature forgée de toutes pièces par Eve.");
            } else if (sc.id === "sig-d") {
                addLog("eve", "Substitution de la clé publique de signature d'Alice par celle d'Eve chez Bob.");
                addLog("eve", "Envoi d'un message malveillant signé avec la clé privée d'Eve.");
            }
        }
        renderSimulationTrace();

        let canPause = false;
        if (sc.id === "aes-c" || sc.id === "rsa-b" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
            canPause = true;
        }

        if (canPause) {
            isSimulationRunning = false;
            currentDirection = (direction === "forward") ? "eve_forward" : "eve_backward";
            const btnStart = document.getElementById("mitm-btn-start");
            btnStart.innerHTML = `<i class="fa-solid fa-paper-plane me-2"></i> Transmettre (Eve)`;
            btnStart.disabled = false;
            setMitMInputAuthor("Eve", false);
            addActorConsoleLog("eve", "Simulation en pause : Eve peut modifier le message avant de le transmettre.", "console-line text-warning");
        } else {
            callback();
        }
    }, 1800);
};

window.simulateBobBehavior = async function(sc, direction, callback) {
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    
    // --- REAL CRYPTO BOB ---
    try {
        const method = document.getElementById("mitm-method").value;
        if (method === "aes") {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;
            const rawKeyBase64 = (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)") || "secret";
            
            // Decrypt logic
            const packedB64 = currentSimulationTrace.eve["Bloque Empaquetado Altéré"] || currentSimulationTrace.transit["Bloque Empaquetado"];
            if (packedB64) {
                const packed = base642buf(packedB64);
                const salt = packed.slice(0, 16);
                const ivLen = isGcm ? 12 : 16;
                const iv = packed.slice(16, 16 + ivLen);
                
                const aesKey = await deriveAesKey(rawKeyBase64, salt, isGcm ? "AES-GCM" : "AES-CBC");
                
                let cipherBuf, tagBuf, dataToDecrypt;
                if (isGcm) {
                    cipherBuf = packed.slice(16 + ivLen, packed.length - 16);
                    tagBuf = packed.slice(packed.length - 16);
                    
                    dataToDecrypt = new Uint8Array(cipherBuf.length + tagBuf.length);
                    dataToDecrypt.set(cipherBuf, 0);
                    dataToDecrypt.set(tagBuf, cipherBuf.length);
                } else {
                    dataToDecrypt = packed.slice(16 + ivLen);
                }
                
                const algoObj = isGcm ? { name: "AES-GCM", iv: iv, tagLength: 128 } : { name: "AES-CBC", iv: iv };
                
                try {
                    const decrypted = await window.crypto.subtle.decrypt(algoObj, aesKey, dataToDecrypt);
                    currentSimulationTrace.receiver["Message Déchiffré"] = bufToStr(decrypted);
                    currentSimulationTrace.receiver["Validation"] = "✅ Déchiffrement Réussi";
                    if(isGcm) currentSimulationTrace.receiver["Validation"] += " (Tag GCM valide)";
                } catch (e) {
                    currentSimulationTrace.receiver["Validation"] = "❌ Échec (" + e.message + ")";
                    if(isGcm) currentSimulationTrace.receiver["Validation"] = "❌ Échec de l'authentification GCM (" + e.message + ").";
                }
            }
        }
        else if (method === "sig") {
            const pubPem = (document.getElementById("sign-pub-key") ? document.getElementById("sign-pub-key").value : "(non disponible)");
            const msgToVerify = currentSimulationTrace.eve["Message en clair Altéré"] || currentSimulationTrace.transit["Message en clair"];
            const sigB64 = currentSimulationTrace.eve["Signature (Base64)"] || currentSimulationTrace.transit["Signature (Base64)"];
            if (pubPem && sigB64 && msgToVerify) {
                const pubKey = await importKeyFromPem(pubPem, "verify");
                const sigBuf = base642buf(sigB64);
                try {
                    const isValid = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pubKey, sigBuf, new TextEncoder().encode(msgToVerify));
                    currentSimulationTrace.receiver["Validation"] = isValid ? "✅ Signature Valide" : "❌ Signature Invalide !";
                } catch (e) {
                    currentSimulationTrace.receiver["Validation"] = "❌ Erreur de vérification";
                }
            }
        }
    } catch (e) {
        console.error(e);
        currentSimulationTrace.receiver["Erreur Crypto"] = e.message;
    }
    renderSimulationTrace();

    setTimeout(() => {
        let showMessageText = true;
        let isRejected = false;

        // EXACT ORIGINAL LOGS
        if (sc.id.startsWith("aes")) {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;

            if (sc.id === "aes-a") {
                if (isGcm) {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-GCM réussi. Message intègre reçu.");
                } else {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-CBC réussi. Attention : Pas de validation d'intégrité (GCM inactif).");
                }
            } else if (sc.id === "aes-b") {
                if (isGcm) {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-GCM réussi. Bob reçoit le message original d'Alice, ignorant qu'Eve l'a également intercepté et lu.");
                } else {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-CBC réussi. Bob reçoit le message original d'Alice, ignorant qu'Eve l'a également intercepté et lu.");
                }
            } else if (sc.id === "aes-c") {
                addLog("bob", "Tentative de déchiffrement...");
                if (isGcm) {
                    addLog("bob", "❌ Échec de l'authentification GCM (tag de contrôle invalide) ! Le message a été altéré et a été REJETÉ.");
                    showMessageText = false;
                    isRejected = true;
                } else {
                    addLog("bob", "Mode AES-CBC alternatif : Le déchiffrement s'opère mais le texte es corrompu (garbage text). Aucune alerte d'intégrité levée !");
                }
            }
        }
        else if (sc.id.startsWith("rsa")) {
            const keySize = document.getElementById("mitm-rsa-size").value;
            if (sc.id === "rsa-a") {
                addLog("bob", `Déchiffrement réussi avec la clé privée de Bob (${keySize} bits). Message confidentiel reçu.`);
            } else if (sc.id === "rsa-b" || sc.id === "rsa-c") {
                addLog("bob", `Déchiffrement avec la clé privée de Bob (${keySize} bits) réussi.`);
                addLog("bob", "Le message semble techniquement correct, mais l'expéditeur a été usurpé en transit par substitution de clé publique !");
            }
        }
        else if (sc.id.startsWith("sha")) {
            if (sc.id === "sha-a") {
                addLog("bob", "Empreinte calculée sur le document = empreinte d'Alice. Intégrité validée.");
            } else if (sc.id === "sha-b") {
                addLog("bob", "❌ Empreinte calculée ne correspond pas à l'empreinte reçue. Le message a été altéré !");
                showMessageText = false;
                isRejected = true;
            } else if (sc.id === "sha-c") {
                addLog("bob", "Réception de l'empreinte de contrôle.");
            } else if (sc.id === "sha-d") {
                addLog("bob", "Empreinte calculée correspond à l'empreinte reçue par le même canal. Bob accepte le message falsificado.");
            }
        }
        else if (sc.id.startsWith("sig")) {
            if (sc.id === "sig-a") {
                addLog("bob", "Vérification de la signature d'Alice avec sa clé publique. Signature valide. Identité authentifiée.");
            } else if (sc.id === "sig-b") {
                addLog("bob", "Vérification de la signature d'Alice... ❌ Échec : la signature ne correspond pas au contenu modifié !");
                showMessageText = false;
                isRejected = true;
            } else if (sc.id === "sig-c") {
                addLog("bob", "Vérification de la signature... ❌ Échec : la signature d'Alice a été falsifiée par Eve !");
                showMessageText = false;
                isRejected = true;
            } else if (sc.id === "sig-d") {
                addLog("bob", "Vérification de la signature avec la clé publique (qui es celle d'Eve chez Bob). Signature valide. Bob accepte le message usurpé !");
            }
        }

        if (showMessageText) {
            addActorConsoleLog("bob", `Texte: "${messageText}"`);
        }

        if (isRejected) {
            document.getElementById("card-bob").classList.remove("border-success");
            document.getElementById("card-bob").classList.add("border-danger");
            document.getElementById("state-bob").textContent = "Message rejeté ❌";
            
            // --- CHAT: Bob (Rejeté) ---
            try {
                if (window.addChatMessage) window.addChatMessage("Bob", "Message rejeté ❌", "Rejeté");
            } catch (e) { console.error(e); }
        } else {
            document.getElementById("state-bob").textContent = "Message reçu ✅";
            
            // --- CHAT: Bob (Reçu) ---
            try {
                if (window.addChatMessage) window.addChatMessage("Bob", messageText, "Reçu");
            } catch (e) { console.error(e); }
        }

        callback();
    }, 1800);
};
window.resumeFromEveForward = async function(sc = null) {
    isSimulationRunning = true;
    currentDirection = "forward";
    if (!sc) sc = getDynamicState(document.getElementById("mitm-method").value, document.getElementById("mitm-scenario").value);
    
    document.getElementById("mitm-btn-start").disabled = true;
    setMitMInputAuthor("Eve", true);

    if (sc.id === "aes-c" || sc.id === "rsa-b" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
        document.getElementById("packet").className = "data-packet compromised";
        
        // --- CHAT: Eve (Forward) ---
        try {
            if (window.addChatMessage) {
                const eveMsg = document.getElementById("mitm-message-input").value;
                const originalMsg = currentSimulationTrace.sender && currentSimulationTrace.sender["Message Original"];
                if (eveMsg !== originalMsg) {
                    window.addChatMessage("Eve", eveMsg, "Suplantado");
                }
            }
        } catch (e) {
            console.error("Chat message error (Eve forward): ", e);
        }
    }

    animatePacket("50%", "83.33%", 1500, () => {
        if (!isSimulationRunning) return;
        setActiveNode("node-bob");
        document.getElementById("state-eve").textContent = "Transmis";
        document.getElementById("state-bob").textContent = "Traitement...";
        document.getElementById("card-bob").classList.add("border-success");

        simulateBobBehavior(sc, "forward", () => {
            if (!isSimulationRunning) return;
            
            setTimeout(() => {
                if (!isSimulationRunning) return;
                const logsPanel = document.getElementById("mitm-logs-panel");
                if (logsPanel) {
                    logsPanel.scrollIntoView({ behavior: "smooth", block: "center" });
                }

                setTimeout(() => {
                    if (!isSimulationRunning) return;
                    const method = document.getElementById("mitm-method").value;
                    const scenarioId = document.getElementById("mitm-scenario").value;
                    addInteractionSummaryLog("forward", method, scenarioId);

                    addLog("system", "Étape Alice ➔ Bob terminée.");
                    updateResultsCard(sc);
                    
                    const btnStart = document.getElementById("mitm-btn-start");
                    btnStart.innerHTML = `<i class="fa-solid fa-reply me-2"></i> Répondre (Bob)`;
                    btnStart.disabled = false;
                    setMitMInputAuthor("Bob", false, "");
                    document.getElementById("mitm-method").disabled = false;
                    document.getElementById("mitm-scenario").disabled = false;
                    isSimulationRunning = false;
                    currentDirection = "backward";
                }, 800);
            }, 3000);
        });
    });
};

// Start Reply Simulation logic (simplified logic for response)
window.startReplySimulation = async function() {
    isSimulationRunning = true;
    currentDirection = "backward";
    currentSimulationTrace = { sender: {}, transit: {}, eve: {}, receiver: {}, isForward: false };
    renderSimulationTrace();

    const track = document.querySelector(".animation-track-container");
    if (track) track.scrollIntoView({ behavior: "smooth", block: "center" });

    document.getElementById("mitm-btn-start").disabled = true;
    document.getElementById("mitm-btn-stop").disabled = false;

    const method = document.getElementById("mitm-method").value;
    const scenarioId = document.getElementById("mitm-scenario").value;
    const sc = getDynamicState(method, scenarioId);
    
    // Log the start of the reply
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    addLog("system", `Lancement de la communication de retour (Étape ${simulationStepCount} : Bob ➔ Alice).`);
    addActorConsoleLog("bob", "Création et préparation de la réponse.", "console-header");
    addActorConsoleLog("bob", `Texte: "${messageText}"`);

    // --- CHAT: Bob envoie ---
    try {
        if (window.addChatMessage) {
            window.addChatMessage("Bob", messageText, "Envoyé");
        }
    } catch (e) {
        console.error("Chat message error (Bob): ", e);
    }

    // --- REAL CRYPTO BOB (REPLY) ---
    try {
        currentSimulationTrace.sender["Message Original"] = messageText;
        const msgUint8 = new TextEncoder().encode(messageText);

        if (method === "aes") {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;
            const rawKeyBase64 = (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)") || "secret";
            
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            currentSimulationTrace.sender["Salt PBKDF2 (Base64)"] = buf2base64(salt);
            
            const aesKey = await deriveAesKey(rawKeyBase64, salt, isGcm ? "AES-GCM" : "AES-CBC");
            currentSimulationTrace.sender["Clé AES Derivée"] = "Générée en mémoire via PBKDF2";
            
            const ivLen = isGcm ? 12 : 16;
            const iv = isIv ? window.crypto.getRandomValues(new Uint8Array(ivLen)) : new Uint8Array(ivLen);
            currentSimulationTrace.sender["IV / Nonce (Base64)"] = buf2base64(iv);
            
            const algoObj = isGcm ? { name: "AES-GCM", iv: iv, tagLength: 128 } : { name: "AES-CBC", iv: iv };
            
            const encryptedBuffer = await window.crypto.subtle.encrypt(algoObj, aesKey, msgUint8);
            
            let ciphertextBuf, tagBuf;
            if (isGcm) {
                ciphertextBuf = encryptedBuffer.slice(0, encryptedBuffer.byteLength - 16);
                tagBuf = encryptedBuffer.slice(encryptedBuffer.byteLength - 16);
                currentSimulationTrace.sender["Tag GCM (Base64)"] = buf2base64(tagBuf);
            } else {
                ciphertextBuf = encryptedBuffer;
            }
            
            const cipherBase64 = buf2base64(ciphertextBuf);
            currentSimulationTrace.transit["Ciphertext (Base64)"] = cipherBase64;
            
            // Packed
            const totalLen = salt.length + iv.length + ciphertextBuf.byteLength + (isGcm ? tagBuf.byteLength : 0);
            const packed = new Uint8Array(totalLen);
            let offset = 0;
            packed.set(salt, offset); offset += salt.length;
            packed.set(iv, offset); offset += iv.length;
            packed.set(new Uint8Array(ciphertextBuf), offset); offset += ciphertextBuf.byteLength;
            if (isGcm) packed.set(new Uint8Array(tagBuf), offset);
            
            currentSimulationTrace.transit["Bloque Empaquetado"] = buf2base64(packed);
            
        } else if (method === "rsa") {
            const pubPem = (document.getElementById("rsa-enc-alice-pub") ? document.getElementById("rsa-enc-alice-pub").value : "(non disponible)");
            if (pubPem) {
                currentSimulationTrace.sender["Clé Publique Alice (PEM)"] = pubPem;
                const pubKey = await importKeyFromPem(pubPem, "encrypt");
                const encryptedBuffer = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, msgUint8);
                currentSimulationTrace.transit["Ciphertext RSA (Base64)"] = buf2base64(encryptedBuffer);
            } else {
                currentSimulationTrace.transit["Erreur"] = "Clé publique de Alice manquante.";
            }
        } else if (method === "sha") {
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            currentSimulationTrace.sender["Hash SHA-256 (Hex)"] = hashHex;
            currentSimulationTrace.transit["Message + Hash"] = `Msg: ${messageText}\nHash: ${hashHex}`;
        } else if (method === "sig") {
            const privPem = (document.getElementById("sign-priv-key") ? document.getElementById("sign-priv-key").value : "(non disponible)");
            if (privPem) {
                currentSimulationTrace.sender["Clé Privée Bob (Extrait)"] = "..." + privPem.slice(-40);
                const privKey = await importKeyFromPem(privPem, "sign");
                const sigBuffer = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, privKey, msgUint8);
                currentSimulationTrace.transit["Signature (Base64)"] = buf2base64(sigBuffer);
            }
        }
    } catch (err) {
        console.error("Error generating Bob's crypto: ", err);
    }
    renderSimulationTrace();

    resetActorCards();
    document.getElementById("card-bob").classList.add("border-success");
    document.getElementById("state-bob").textContent = "Réponse en cours...";
    setMitMInputAuthor("Bob", true);

    const packet = document.getElementById("packet");
    packet.style.display = "flex";
    packet.className = "data-packet secure";
    packet.style.left = "83.33%";
    setActiveNode("node-bob");

    let isSecurePacket = (sc.risk === "Faible");
    let isWarningPacket = (sc.risk === "Moyen");
    if (isSecurePacket) {
        packet.classList.add("secure");
    } else if (isWarningPacket) {
        packet.classList.add("warning");
    } else {
        packet.classList.add("compromised");
    }

    animatePacket("83.33%", "50%", 1500, () => {
        if (!isSimulationRunning) return;
        setActiveNode("node-eve");
        document.getElementById("state-bob").textContent = "Réponse envoyée";
        document.getElementById("state-eve").textContent = "Interception de retour...";
        document.getElementById("card-eve").classList.add("active-eve");
        
        setTimeout(() => {
            let canPause = false;
            if (sc.id === "aes-c" || sc.id === "rsa-b" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
                canPause = true;
            }

            if (canPause) {
                isSimulationRunning = false;
                currentDirection = "eve_backward";
                const btnStart = document.getElementById("mitm-btn-start");
                btnStart.innerHTML = `<i class="fa-solid fa-paper-plane me-2"></i> Transmettre (Eve)`;
                btnStart.disabled = false;
                setMitMInputAuthor("Eve", false);
                addActorConsoleLog("eve", "Simulation en pause : Eve peut modifier la réponse avant de la transmettre.", "console-line text-warning");
            } else {
                resumeFromEveBackward(sc);
            }
        }, 1800);
    });
}

window.resumeFromEveBackward = async function(sc = null) {
    isSimulationRunning = true;
    currentDirection = "backward";
    if (!sc) {
        const method = document.getElementById("mitm-method").value;
        const scenarioId = document.getElementById("mitm-scenario").value;
        sc = getDynamicState(method, scenarioId);
    }
    
    document.getElementById("mitm-btn-start").disabled = true;
    setMitMInputAuthor("Eve", true);
    
    const packet = document.getElementById("packet");
    
    if (sc.id === "rsa-b" || sc.id === "rsa-c" || sc.id === "aes-c" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
        addLog("eve", "Eve transmet la réponse (éventuellement modifiée).");
        packet.className = "data-packet compromised";
        
        // --- CHAT: Eve (Backward) ---
        try {
            if (window.addChatMessage) {
                const eveMsg = document.getElementById("mitm-message-input").value;
                const originalMsg = currentSimulationTrace.sender && currentSimulationTrace.sender["Message Original"];
                if (eveMsg !== originalMsg) {
                    window.addChatMessage("Eve", eveMsg, "Suplantado");
                }
            }
        } catch (e) {
            console.error("Chat message error (Eve backward): ", e);
        }
    } else {
        addLog("eve", "Interception passive du flux chiffré de retour.");
    }

    addLog("eve", "Reroutage de la réponse vers Alice.");
    document.getElementById("state-eve").textContent = "Transmis";
    document.getElementById("state-alice").textContent = "Réception réponse...";

    animatePacket("50%", "16.66%", 1500, () => {
        if (!isSimulationRunning) return;
        setActiveNode("node-alice");
        
        document.getElementById("state-alice").textContent = "Traitement...";
        document.getElementById("card-alice").classList.add("border-primary");
        
        setTimeout(async () => {
            const method = document.getElementById("mitm-method").value;
            currentSimulationTrace.receiver["Action"] = "Réception terminée";
            
            // --- REAL DECRYPTION ALICE (BACKWARD) ---
            try {
                if (method === "aes") {
                    const isIv = document.getElementById("mitm-aes-iv-check").checked;
                    const isGcm = document.getElementById("mitm-aes-tag-check").checked;
                    const rawKeyBase64 = (document.getElementById("aes-enc-key") ? document.getElementById("aes-enc-key").value : "(non disponible)") || "secret";
                    
                    const packedB64 = currentSimulationTrace.eve["Bloque Empaquetado Altéré"] || currentSimulationTrace.transit["Bloque Empaquetado"];
                    if (packedB64) {
                        const packed = base642buf(packedB64);
                        const salt = packed.slice(0, 16);
                        const ivLen = isGcm ? 12 : 16;
                        const iv = packed.slice(16, 16 + ivLen);
                        
                        const aesKey = await deriveAesKey(rawKeyBase64, salt, isGcm ? "AES-GCM" : "AES-CBC");
                        
                        let cipherBuf, tagBuf, dataToDecrypt;
                        if (isGcm) {
                            cipherBuf = packed.slice(16 + ivLen, packed.length - 16);
                            tagBuf = packed.slice(packed.length - 16);
                            
                            dataToDecrypt = new Uint8Array(cipherBuf.length + tagBuf.length);
                            dataToDecrypt.set(cipherBuf, 0);
                            dataToDecrypt.set(tagBuf, cipherBuf.length);
                        } else {
                            dataToDecrypt = packed.slice(16 + ivLen);
                        }
                        
                        const algoObj = isGcm ? { name: "AES-GCM", iv: iv, tagLength: 128 } : { name: "AES-CBC", iv: iv };
                        
                        try {
                            const decrypted = await window.crypto.subtle.decrypt(algoObj, aesKey, dataToDecrypt);
                            currentSimulationTrace.receiver["Message Déchiffré"] = bufToStr(decrypted);
                            currentSimulationTrace.receiver["Validation"] = "✅ Déchiffrement Réussi";
                            if(isGcm) currentSimulationTrace.receiver["Validation"] += " (Tag GCM valide)";
                        } catch (e) {
                            currentSimulationTrace.receiver["Validation"] = "❌ Échec (" + e.message + ")";
                            if(isGcm) currentSimulationTrace.receiver["Validation"] = "❌ Échec de l'authentification GCM (" + e.message + ").";
                        }
                    }
                } else if (method === "rsa") {
                    const privPem = (document.getElementById("rsa-enc-alice-priv") ? document.getElementById("rsa-enc-alice-priv").value : "(non disponible)");
                    const cipherB64 = currentSimulationTrace.eve["Ciphertext RSA (Base64)"] || currentSimulationTrace.transit["Ciphertext RSA (Base64)"];
                    if (privPem && cipherB64) {
                        try {
                            const privKey = await importKeyFromPem(privPem, "decrypt");
                            const decrypted = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, base642buf(cipherB64));
                            currentSimulationTrace.receiver["Message Déchiffré"] = bufToStr(decrypted);
                            currentSimulationTrace.receiver["Validation"] = "✅ Déchiffrement Réussi";
                        } catch (e) {
                            currentSimulationTrace.receiver["Validation"] = "❌ Échec du déchiffrement RSA";
                        }
                    }
                } else if (method === "sig") {
                    const pubPem = (document.getElementById("sign-pub-key") ? document.getElementById("sign-pub-key").value : "(non disponible)");
                    const msgToVerify = currentSimulationTrace.eve["Message en clair Altéré"] || currentSimulationTrace.transit["Message en clair"];
                    const sigB64 = currentSimulationTrace.eve["Signature (Base64)"] || currentSimulationTrace.transit["Signature (Base64)"];
                    if (pubPem && sigB64 && msgToVerify) {
                        try {
                            const pubKey = await importKeyFromPem(pubPem, "verify");
                            const sigBuf = base642buf(sigB64);
                            const isValid = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pubKey, sigBuf, new TextEncoder().encode(msgToVerify));
                            currentSimulationTrace.receiver["Validation"] = isValid ? "✅ Signature Valide" : "❌ Signature Invalide";
                        } catch (e) {
                            currentSimulationTrace.receiver["Validation"] = "❌ Échec de la vérification";
                        }
                    }
                }
            } catch (err) {
                console.error("Error decrypting for Alice: ", err);
            }
            renderSimulationTrace();
            
            const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
            let showMessageText = true;

            // RESTORED ALICE LOGIC FOR BACKWARD DIRECTION
            if (sc.id === "aes-a" || sc.id === "rsa-a" || sc.id === "aes-b") {
                if (method === "aes") {
                    const isGcm = document.getElementById("mitm-aes-tag-check").checked;
                    if (isGcm) {
                        addLog("alice", "Déchiffrement AES-GCM de la réponse réussi. Communication bidirectionnelle confidentielle et intègre.");
                    } else {
                        addLog("alice", "Déchiffrement AES-CBC de la réponse réussi. Confidentialité préservée mais sans contrôle d'intégrité.");
                    }
                } else {
                    addLog("alice", "Déchiffrement de la réponse réussi. Communication bidirectionnelle confidentielle.");
                }
            } else if (sc.id === "rsa-b" || sc.id === "rsa-c") {
                const isAuth = document.getElementById("mitm-rsa-auth-check").checked;
                if (isAuth) {
                    addLog("alice", "⚠️ Vérification de l'empreinte de la clé reçue.");
                    addLog("alice", "❌ L'empreinte ne correspond pas ! Substitution de clé détectée.");
                    addLog("alice", "Alice rejette la réponse chiffrée de Bob par manque d'authenticité.");
                    showMessageText = false;
                } else {
                    addLog("alice", "Déchiffrement de la réponse modifiée par Eve. Alice est trompée.");
                }
            } else if (sc.id === "aes-c") {
                if (method === "aes") {
                    const isGcm = document.getElementById("mitm-aes-tag-check").checked;
                    if (isGcm) {
                        addLog("alice", "❌ Échec de l'authentification GCM sur la réponse ! Alice détecte l'altération et rejette le message.");
                        showMessageText = false;
                    } else {
                        addLog("alice", "Déchiffrement AES-CBC réussi sur la réponse modifiée. Alice obtient des données corrompues et est trompée.");
                    }
                } else {
                    addLog("alice", "Réception de la réponse.");
                }
            } else if (sc.id.startsWith("sha")) {
                if (sc.id === "sha-a" || sc.id === "sha-c") {
                    addLog("alice", "Calcul de l'empreinte SHA-256 de la réponse.");
                    addLog("alice", "Empreinte calculée = empreinte reçue. Intégrité de la réponse validée.");
                } else if (sc.id === "sha-b") {
                    addLog("alice", "Calcul de l'empreinte SHA-256 de la réponse...");
                    addLog("alice", "❌ Empreinte calculée ne correspond pas à l'empreinte reçue. Le message a été altéré !");
                    showMessageText = false;
                } else if (sc.id === "sha-d") {
                    addLog("alice", "Calcul de l'empreinte SHA-256 de la réponse.");
                    addLog("alice", "L'empreinte calculée correspond à l'empreinte reçue (recalculée par Eve). Alice accepte la réponse falsifiée.");
                }
            } else if (sc.id.startsWith("sig")) {
                if (sc.id === "sig-a") {
                    addLog("alice", "Vérification de la signature de Bob avec sa clé publique. Signature valide. Identité authentifiée.");
                } else if (sc.id === "sig-b") {
                    addLog("alice", "Vérification de la signature de Bob... ❌ Échec : la signature ne correspond pas au contenu de la réponse modifiée !");
                    showMessageText = false;
                } else if (sc.id === "sig-c") {
                    addLog("alice", "Vérification de la signature... ❌ Échec : la signature de Bob a été falsifiée par Eve !");
                    showMessageText = false;
                } else if (sc.id === "sig-d") {
                    addLog("alice", "Vérification de la signature avec la clé publique (qui est celle d'Eve chez Alice). Signature valide. Alice accepte la réponse usurpée !");
                }
            } else {
                addLog("alice", "Réception de la réponse.");
            }

            if (showMessageText) {
                addActorConsoleLog("alice", `Texte: "${messageText}"`);
                document.getElementById("state-alice").textContent = "Réponse reçue ✅";
                
                // --- CHAT: Alice (Reçu) ---
                try {
                    if (window.addChatMessage) window.addChatMessage("Alice", messageText, "Reçu");
                } catch (e) { console.error(e); }
            } else {
                document.getElementById("card-alice").classList.remove("border-primary");
                document.getElementById("card-alice").classList.add("border-danger");
                document.getElementById("state-alice").textContent = "Réponse rejetée ❌";
                
                // --- CHAT: Alice (Rejeté) ---
                try {
                    if (window.addChatMessage) window.addChatMessage("Alice", "Réponse rejetée ❌", "Rejeté");
                } catch (e) { console.error(e); }
            }
            
            setTimeout(() => {
                const logsPanel = document.getElementById("mitm-logs-panel");
                if (logsPanel) {
                    logsPanel.scrollIntoView({ behavior: "smooth", block: "center" });
                }

                setTimeout(() => {
                    // Summary log for backward interaction
                    addInteractionSummaryLog("backward", method, sc.id);

                    addLog("system", "Étape Bob ➔ Alice (Réponse) terminée. Prêt pour le message suivant.");
                    
                    const btnStart = document.getElementById("mitm-btn-start");
                    btnStart.innerHTML = `<i class="fa-solid fa-play me-2"></i> Démarrer la communication (Alice)`;
                    btnStart.disabled = false;
                    setMitMInputAuthor("Alice", false, "");
                    isSimulationRunning = false;
                    currentDirection = "forward";
                }, 800);
            }, 3000);
        }, 1500);
    });
}

// Function to add dynamic summarized logs with icon in reverse chronological order
window.addInteractionSummaryLog = function(direction, method, scenarioId) {
    const logsContainer = document.getElementById("mitm-logs");
    if (!logsContainer) return;

    const isGcm = document.getElementById("mitm-aes-tag-check") ? document.getElementById("mitm-aes-tag-check").checked : false;
    const isAuth = document.getElementById("mitm-rsa-auth-check") ? document.getElementById("mitm-rsa-auth-check").checked : false;

    let text = "";
    let icon = "";
    
    if (direction === "forward") {
        if (method === "aes") {
            if (scenarioId === "aes-a") {
                text = "Alice ➔ Bob : Message reçu et déchiffré avec succès. Communication confidentielle et intègre.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "aes-b") {
                text = "Alice ➔ Bob : Clé secrète compromise ! Eve a lu le message en clair, Bob a reçu l\'original.";
                icon = '<i class="fa-solid fa-eye text-warning fs-5 me-2"></i>';
            } else if (scenarioId === "aes-c") {
                if (isGcm) {
                    text = "Alice ➔ Bob : Tentative de modification détectée ! Bob rejette le message suite à l\'échec d\'authentification GCM.";
                    icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
                } else {
                    text = "Alice ➔ Bob : Modification réussie ! En l\'absence de tag GCM (CBC), Bob accepte le message altéré sans s\'en apercevoir.";
                    icon = '<i class="fa-solid fa-triangle-exclamation text-danger fs-5 me-2"></i>';
                }
            }
        } else if (method === "rsa") {
            if (scenarioId === "rsa-a") {
                text = "Alice ➔ Bob : Message chiffré reçu et déchiffré. Interception passive inefficace pour Eve.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "rsa-b" || scenarioId === "rsa-c") {
                if (isAuth) {
                    text = "Alice ➔ Bob : Communication bloquée par Alice ! La substitution de la clé publique de Bob a été détectée.";
                    icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
                } else {
                    text = "Alice ➔ Bob : Attaque MITM réussie ! Eve a intercepté, déchiffré, modifié et re-chiffré le message pour Bob.";
                    icon = '<i class="fa-solid fa-skull text-danger fs-5 me-2"></i>';
                }
            }
        } else if (method === "sha") {
            if (scenarioId === "sha-a") {
                text = "Alice ➔ Bob : Message et hash SHA-256 reçus. Intégrité validée par correspondances d\'empreintes.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "sha-b") {
                text = "Alice ➔ Bob : Altération détectée ! L\'empreinte reçue ne correspond pas au message modifié. Message rejeté.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sha-c") {
                text = "Alice ➔ Bob : Message reçu. Eve a retrouvé le message en clair via une attaque par dictionnaire sur le hash.";
                icon = '<i class="fa-solid fa-eye text-warning fs-5 me-2"></i>';
            } else if (scenarioId === "sha-d") {
                text = "Alice ➔ Bob : Hash recalculé par Eve ! Bob accepte le message altéré car l\'empreinte correspond à celle de la modification.";
                icon = '<i class="fa-solid fa-triangle-exclamation text-danger fs-5 me-2"></i>';
            }
        } else if (method === "sig") {
            if (scenarioId === "sig-a") {
                text = "Alice ➔ Bob : Message reçu et signature d\'Alice validée. Authenticité et intégrité confirmées.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "sig-b") {
                text = "Alice ➔ Bob : Modification détectée ! La signature originale d\'Alice ne correspond pas au message altéré.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sig-c") {
                text = "Alice ➔ Bob : Falsification de signature détectée ! Bob rejette la fausse signature générée par Eve.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sig-d") {
                text = "Alice ➔ Bob : Usurpation réussie ! Eve a substitué la clé d\'Alice par la sienne, Bob accepte le faux message.";
                icon = '<i class="fa-solid fa-user-secret text-danger fs-5 me-2"></i>';
            }
        }
    } else {
        // backward direction (Bob ➔ Alice)
        if (method === "aes") {
            if (scenarioId === "aes-a") {
                text = "Bob ➔ Alice : Réponse reçue et déchiffrée avec succès. Communication bidirectionnelle confidentielle et intègre.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "aes-b") {
                text = "Bob ➔ Alice : Clé secrète compromise ! Eve a intercepté la réponse de Bob et l\'a lue en clair.";
                icon = '<i class="fa-solid fa-eye text-warning fs-5 me-2"></i>';
            } else if (scenarioId === "aes-c") {
                if (isGcm) {
                    text = "Bob ➔ Alice : Tentative de modification de la réponse détectée ! Alice rejette la réponse via GCM.";
                    icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
                } else {
                    text = "Bob ➔ Alice : Modification réussie de la réponse ! En l\'absence de tag GCM, Alice accepte la réponse altérée.";
                    icon = '<i class="fa-solid fa-triangle-exclamation text-danger fs-5 me-2"></i>';
                }
            }
        } else if (method === "rsa") {
            if (scenarioId === "rsa-a") {
                text = "Bob ➔ Alice : Réponse chiffrée reçue et déchiffrée par Alice. Interception d\'Eve inefficace.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "rsa-b" || scenarioId === "rsa-c") {
                if (isAuth) {
                    text = "Bob ➔ Alice : Réponse rejetée par Alice ! La substitution de la clé publique de Bob en retour a été détectée.";
                    icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
                } else {
                    text = "Bob ➔ Alice : Attaque MITM réussie en retour ! Eve a intercepté et modifié la réponse de Bob pour Alice.";
                    icon = '<i class="fa-solid fa-skull text-danger fs-5 me-2"></i>';
                }
            }
        } else if (method === "sha") {
            if (scenarioId === "sha-a") {
                text = "Bob ➔ Alice : Réponse et hash SHA-256 reçus. Intégrité validée par correspondances d\'empreintes.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "sha-b") {
                text = "Bob ➔ Alice : Altération de réponse détectée ! L\'empreinte reçue ne correspond pas à celle de la réponse altérée. Réponse rejetée.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sha-c") {
                text = "Bob ➔ Alice : Réponse reçue. Eve a déchiffré le hash de la réponse via dictionnaire.";
                icon = '<i class="fa-solid fa-eye text-warning fs-5 me-2"></i>';
            } else if (scenarioId === "sha-d") {
                text = "Bob ➔ Alice : Hash de la réponse recalculé par Eve ! Alice accepte la réponse falsifiée sans le savoir.";
                icon = '<i class="fa-solid fa-triangle-exclamation text-danger fs-5 me-2"></i>';
            }
        } else if (method === "sig") {
            if (scenarioId === "sig-a") {
                text = "Bob ➔ Alice : Réponse reçue et signature de Bob validée. Authenticité et intégrité confirmées.";
                icon = '<i class="fa-solid fa-circle-check text-success fs-5 me-2"></i>';
            } else if (scenarioId === "sig-b") {
                text = "Bob ➔ Alice : Altération détectée ! La signature de Bob ne correspond pas à la réponse modifiée par Eve.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sig-c") {
                text = "Bob ➔ Alice : Signature forgée de Bob détectée ! Alice rejette la fausse signature créée par Eve.";
                icon = '<i class="fa-solid fa-circle-xmark text-danger fs-5 me-2"></i>';
            } else if (scenarioId === "sig-d") {
                text = "Bob ➔ Alice : Usurpation d\'identité ! Eve a substitué la clé de Bob par la sienne, Alice accepte la fausse réponse.";
                icon = '<i class="fa-solid fa-user-secret text-danger fs-5 me-2"></i>';
            }
        }
    }

    if (!text) {
        text = `${direction === "forward" ? "Alice ➔ Bob" : "Bob ➔ Alice"} : Interaction terminée.`;
        icon = '<i class="fa-solid fa-info-circle text-primary fs-5 me-2"></i>';
    }

    const now = new Date();
    const timeStr = `[${now.toTimeString().split(' ')[0]}]`;

    const logEl = document.createElement("div");
    logEl.className = "log-entry text-start d-flex align-items-baseline mb-2";
    logEl.style.fontFamily = "'Fira Code', 'Courier New', Courier, monospace";
    logEl.style.fontSize = "0.84rem";
    logEl.style.lineHeight = "1.5";
    logEl.innerHTML = `
        <span class="text-muted me-2" style="font-size: 0.76rem;">${timeStr}</span>
        <span class="text-info me-2 fw-bold" style="text-shadow: 0 0 5px rgba(0, 242, 254, 0.4);">cryptosim@admin:~$</span>
        <span class="me-2 d-inline-flex align-items-center" style="transform: translateY(1.5px);">${icon}</span>
        <span class="text-light">${text}</span>
    `;

    // Prepend to the container! (Always show the latest log on the first line)
    logsContainer.insertBefore(logEl, logsContainer.firstChild);
    logsContainer.scrollTop = 0; // Make sure it stays at the top
};

// Overwrite window.addLog to only write logs to individual actor consoles and not pollute the main horizontal summary panel
window.addLog = function(actor, message) {
    if (["alice", "bob", "eve"].includes(actor)) {
        addActorConsoleLog(actor, message);
    }
    console.log(`[${actor.toUpperCase()}] ${message}`);
};

// Override resetSimulation to style the console reset message like a CLI terminal
const originalResetSimulation = window.resetSimulation;
window.resetSimulation = function() {
    if (typeof originalResetSimulation === "function") {
        originalResetSimulation();
    }
    const timeStr = `[${new Date().toTimeString().split(' ')[0]}]`;
    const logsContainer = document.getElementById("mitm-logs");
    if (logsContainer) {
        logsContainer.innerHTML = `
            <div class="log-entry text-start d-flex align-items-baseline mb-2" style="font-family: 'Fira Code', 'Courier New', Courier, monospace; font-size: 0.84rem; line-height: 1.5;">
                <span class="text-muted me-2" style="font-size: 0.76rem;">${timeStr}</span>
                <span class="text-info me-2 fw-bold" style="text-shadow: 0 0 5px rgba(0, 242, 254, 0.4);">cryptosim@admin:~$</span>
                <span class="me-2 d-inline-flex align-items-center" style="transform: translateY(1.5px);"><i class="fa-solid fa-terminal text-primary"></i></span>
                <span class="text-light">Console réinitialisée. Prêt.</span>
            </div>
        `;
    }
};

// ==========================================
// CHAT MESSAGES LOGIC
// ==========================================
window.addChatMessage = function(sender, message, status = "Envoyé") {
    const chatContainer = document.getElementById("chat-messages");
    if (!chatContainer) return;
    
    // Remove the "empty" placeholder if it exists
    const emptyPlaceholder = document.getElementById("chat-placeholder");
    if (emptyPlaceholder) {
        emptyPlaceholder.remove();
    }

    const isAlice = sender.toLowerCase() === "alice";
    const isBob = sender.toLowerCase() === "bob";
    const isEve = sender.toLowerCase() === "eve";
    
    let bubbleAlign = "align-self-center";
    let bubbleBg = "bg-secondary text-white";
    
    if (isAlice) {
        bubbleAlign = "align-self-start";
        bubbleBg = "bg-primary text-white";
    } else if (isBob) {
        bubbleAlign = "align-self-end";
        bubbleBg = "bg-success text-white";
    } else if (isEve) {
        bubbleAlign = "align-self-center";
        bubbleBg = "bg-danger text-white border border-warning";
    }

    if (status === "Rejeté") {
        bubbleBg = "bg-dark text-danger border border-danger";
    }

    let badgeHtml = '';
    if (status === "Envoyé") {
        badgeHtml = '<span class="badge bg-secondary ms-2 opacity-75" style="font-size: 0.65em;"><i class="fa-solid fa-paper-plane me-1"></i>Envoyé</span>';
    } else if (status === "Suplantado") {
        badgeHtml = '<span class="badge bg-danger ms-2" style="font-size: 0.65em;"><i class="fa-solid fa-user-ninja me-1"></i>Usurpé</span>';
    } else if (status === "Reçu") {
        badgeHtml = '<span class="badge bg-success ms-2" style="font-size: 0.65em;"><i class="fa-solid fa-check-double me-1"></i>Reçu</span>';
    } else if (status === "Rejeté") {
        badgeHtml = '<span class="badge bg-danger ms-2" style="font-size: 0.65em;"><i class="fa-solid fa-xmark me-1"></i>Rejeté</span>';
    }

    const timeString = new Date().toTimeString().split(' ')[0];
    const senderName = isAlice ? "Alice" : (isBob ? "Bob" : (isEve ? "Eve" : sender));

    const messageHtml = `
        <div class="chat-bubble ${bubbleAlign} p-2 rounded mb-2 ${bubbleBg}" style="max-width: 80%; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <small class="fw-bold me-3">${senderName}</small>
                <small class="opacity-75" style="font-size: 0.7em;">${timeString}</small>
            </div>
            <div class="d-flex justify-content-between align-items-end gap-2">
                <div class="message-text text-break mb-0" style="font-size: 0.9em; line-height: 1.4;">${message}</div>
                <div class="text-end flex-shrink-0">${badgeHtml}</div>
            </div>
        </div>
    `;

    chatContainer.insertAdjacentHTML('beforeend', messageHtml);
    chatContainer.scrollTop = chatContainer.scrollHeight;
};

// Override updateResultsCard to style and translate the "Modification détectée" badge correctly
const originalUpdateResultsCard = window.updateResultsCard;
window.updateResultsCard = function(sc, showEmpty = false) {
    if (typeof originalUpdateResultsCard === "function") {
        originalUpdateResultsCard(sc, showEmpty);
    }

    if (showEmpty || !sc) {
        return;
    }

    const detectEl = document.getElementById("res-detect");
    if (!detectEl) return;

    const isGcm = document.getElementById("mitm-aes-tag-check") ? document.getElementById("mitm-aes-tag-check").checked : false;

    let text = sc.detect;
    
    // Scenarios with no attack/modification
    const noAttackScenarios = ["aes-a", "aes-b", "rsa-a", "sha-a", "sha-c", "sig-a"];
    
    if (noAttackScenarios.includes(sc.id)) {
        text = "Pas d'attaque";
        detectEl.textContent = text;
        detectEl.className = "badge bg-success text-white";
    } else {
        if (sc.id === "aes-c") {
            if (isGcm) {
                text = "Oui (GCM)";
                detectEl.textContent = text;
                detectEl.className = "badge bg-success text-white";
            } else {
                text = "Non (CBC)";
                detectEl.textContent = text;
                detectEl.className = "badge bg-danger text-white";
            }
        } else {
            detectEl.textContent = text;
            if (text.startsWith("Oui")) {
                detectEl.className = "badge bg-success text-white";
            } else if (text.startsWith("Non")) {
                detectEl.className = "badge bg-danger text-white";
            } else {
                detectEl.className = "badge bg-secondary text-white";
            }
        }
    }
};

// Event listener for the blinking details button and filter scroll behavior with navbar offset
document.addEventListener("DOMContentLoaded", () => {
    const scrollBtn = document.getElementById("mitm-btn-scroll-details");
    if (scrollBtn) {
        scrollBtn.addEventListener("click", () => {
            const nextPanel = document.getElementById("chat-fiche-panel");
            if (nextPanel) {
                const yOffset = -90;
                const y = nextPanel.getBoundingClientRect().top + window.scrollY + yOffset;
                window.scrollTo({ top: y, behavior: "smooth" });
            }
        });
    }

    // Scroll to mitm-flow-panel when method, scenario or dynamic inputs change
    const filterIds = ["mitm-method", "mitm-scenario", "mitm-aes-iv-check", "mitm-aes-tag-check", "mitm-rsa-size", "mitm-rsa-auth-check"];
    filterIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener("change", () => {
                const flowPanel = document.getElementById("mitm-flow-panel");
                if (flowPanel) {
                    const yOffset = -90;
                    const y = flowPanel.getBoundingClientRect().top + window.scrollY + yOffset;
                    window.scrollTo({ top: y, behavior: "smooth" });
                }
            });
        }
    });
});
