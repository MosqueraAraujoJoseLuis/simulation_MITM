/* ====================================================================
   LOGIQUE APPLICATIVE - SIMULATION DE CRYPTOGRAPHIE & MITM
   Technologie : JavaScript Vanilla, Web Crypto API
   Langue : Français (Interface, logs, commentaires)
   ==================================================================== */

// Force scroll to top and disable automatic browser scroll restoration
if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}
window.scrollTo(0, 0);

document?.addEventListener("DOMContentLoaded", () => {
    window.scrollTo(0, 0);
    // Vérification de la disponibilité de la Web Crypto API (sécurité du contexte)
    if (!window.crypto || !window.crypto.subtle) {
        const warningDiv = document.createElement("div");
        warningDiv.className = "container-fluid mt-3";
        warningDiv.innerHTML = `
            <div class="alert alert-danger border-danger glass-card p-4" style="background: rgba(220, 38, 38, 0.15);">
                <h4 class="alert-heading fw-bold"><i class="bi bi-exclamation-octagon-fill me-2 text-danger"></i> Contexte Non Sécurisé Détecté (Web Crypto API restreinte)</h4>
                <p class="mb-2">Les navigateurs modernes désactivent les fonctions cryptographiques (<code>crypto.subtle</code>) lorsqu'un fichier HTML est ouvert localement en double-cliquant (protocole <code>file://</code>) sur Chrome/Edge.</p>
                <hr class="border-secondary">
                <p class="mb-0 fw-semibold text-info"><i class="bi bi-lightbulb-fill"></i> Pour résoudre ce problème et exécuter les fonctions de chiffrement :</p>
                <ul class="mb-0 mt-1">
                    <li>Utilisez le navigateur <strong>Mozilla Firefox</strong> qui autorise nativement la Web Crypto API en local.</li>
                    <li>Ou lancez un mini-serveur local dans ce dossier en ouvrant un terminal et en tapant : <code>python -m http.server 8000</code> puis visitez <code>http://localhost:8000</code>.</li>
                </ul>
            </div>
        `;
        document.body.prepend(warningDiv);
    }

    // Initialisation des onglets et composants
    initCryptoHelpers();
    // initAesSection();
    // initRsaSection();
    // initHashSection();
    // initSignatureSection();
    initMitmSimulation();
});

/* ====================================================================
   SECTION 0 : UTILITAIRES ET CONVERSIONS CRYPTOGRAPHIQUES
   ==================================================================== */

// Encode un buffer binaire (ArrayBuffer) en chaîne Hexadécimale
function bufToHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Décode une chaîne Hexadécimale en ArrayBuffer
function hexToBuf(hex) {
    hex = hex.replace(/\s+/g, '');
    if (hex.length % 2 !== 0) return new ArrayBuffer(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

// Encode un buffer binaire en chaîne Base64
function bufToBase64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Décode une chaîne Base64 en ArrayBuffer
function base64ToBuf(base64) {
    try {
        const binary_string = window.atob(base64.trim());
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (e) {
        console.error("Échec du décodage Base64:", e);
        return null;
    }
}

// Convertit une chaîne de caractères UTF-8 en ArrayBuffer
function strToBuf(str) {
    return new TextEncoder().encode(str);
}

// Convertit un ArrayBuffer en chaîne UTF-8
function bufToStr(buf) {
    return new TextDecoder().decode(buf);
}

// Exporte une CryptoKey (Web Crypto) au format PEM standard
async function exportKeyToPem(cryptoKey, type) {
    const format = type === 'public' ? 'spki' : 'pkcs8';
    const header = type === 'public' ? 'PUBLIC KEY' : 'PRIVATE KEY';

    try {
        const exported = await window.crypto.subtle.exportKey(format, cryptoKey);
        const b64 = bufToBase64(exported);
        const b64Lines = b64.match(/.{1,64}/g).join('\n');
        return `-----BEGIN ${header}-----\n${b64Lines}\n-----END ${header}-----`;
    } catch (err) {
        console.error("Erreur lors de l'export de la clé :", err);
        return "";
    }
}

// Importe une clé au format PEM (spki/pkcs8) vers une CryptoKey
async function importKeyFromPem(pemStr, algName, type, usages) {
    const format = type === 'public' ? 'spki' : 'pkcs8';

    try {
        // Nettoyer les en-têtes PEM (peu importe le type exact pour être flexible), les retours à la ligne et les espaces
        const cleanPem = pemStr
            .replace(/-----BEGIN [^-]+-----/, "")
            .replace(/-----END [^-]+-----/, "")
            .replace(/\s/g, "");

        const buf = base64ToBuf(cleanPem);
        if (!buf) throw new Error("Base64 invalide");

        let algorithm;
        if (algName === "RSA-OAEP") {
            algorithm = { name: "RSA-OAEP", hash: "SHA-256" };
        } else if (algName === "RSA-PSS") {
            algorithm = { name: "RSA-PSS", hash: "SHA-256" };
        } else {
            throw new Error("Algorithme non supporté");
        }

        return await window.crypto.subtle.importKey(
            format,
            buf,
            algorithm,
            true, // Clé exportable
            usages
        );
    } catch (err) {
        console.error("Erreur lors de l'import PEM :", err);
        throw new Error("Clé PEM invalide ou format incorrect.");
    }
}

// Derive une clé AES via PBKDF2 (100k itérations, SHA-256)
async function deriveAesKey(keyStr, saltBuf, algName = "AES-GCM") {
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        strToBuf(keyStr),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuf,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: algName, length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Initialise le bouton d'action globale pour copier dans le presse-papier
function initCryptoHelpers() {
    document.querySelectorAll(".btn-copy").forEach(btn => {
        btn?.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-copy-target");
            const element = document.getElementById(targetId);
            if (element) {
                const textToCopy = element.getAttribute("data-copy-value") || element.value || element.textContent;
                navigator.clipboard.writeText(textToCopy)
                    .then(() => {
                        const toastEl = document.getElementById("copy-toast");
                        const toast = new bootstrap.Toast(toastEl);
                        toast.show();
                    })
                    .catch(err => console.error("Erreur copie :", err));
            }
        });
    });
}

/* ====================================================================
   SECTION 1 : AES-GCM (Chiffrement et Déchiffrement)
   ==================================================================== */

function initAesSection() {
    const encForm = document.getElementById("encrypt-aes-form");
    const encIvCheck = document.getElementById("aes-enc-iv-check");
    const encTagCheck = document.getElementById("aes-enc-tag-check");
    const encIvInput = document.getElementById("aes-enc-iv");
    const encGenIvBtn = document.getElementById("aes-enc-gen-iv");
    const tagEncGroup = document.getElementById("aes-enc-tag-group");
    const encTagInput = document.getElementById("aes-enc-tag");

    const decIvCheck = document.getElementById("aes-dec-iv-check");
    const decTagCheck = document.getElementById("aes-dec-tag-check");
    const decIvInput = document.getElementById("aes-dec-iv");
    const tagDecGroup = document.getElementById("aes-dec-tag-group");
    const decTagInput = document.getElementById("aes-dec-tag");

    function updateAesEncInputs() {
        const isIv = encIvCheck.checked;
        const isTag = encTagCheck.checked;

        encIvInput.disabled = !isIv;
        encGenIvBtn.disabled = !isIv;
        if (!isIv) {
            encIvInput.value = "";
        }

        tagEncGroup.style.display = isTag ? "block" : "none";
        encTagInput.disabled = !isTag;
        if (!isTag) {
            encTagInput.value = "";
        }
    }

    function updateAesDecInputs() {
        const isIv = decIvCheck.checked;
        const isTag = decTagCheck.checked;

        decIvInput.disabled = !isIv;
        if (!isIv) {
            decIvInput.value = "";
        }

        tagDecGroup.style.display = isTag ? "block" : "none";
        decTagInput.disabled = !isTag;
        if (!isTag) {
            decTagInput.value = "";
        }
    }

    // Attach listeners
    encIvCheck?.addEventListener("change", updateAesEncInputs);
    encTagCheck?.addEventListener("change", updateAesEncInputs);
    decIvCheck?.addEventListener("change", updateAesDecInputs);
    decTagCheck?.addEventListener("change", updateAesDecInputs);

    // Initial state setup
    updateAesEncInputs();
    updateAesDecInputs();

    // Génération automatique de clé AES secrète
    document.getElementById("aes-enc-gen-key")?.addEventListener("click", () => {
        const randomBytes = new Uint8Array(16);
        window.crypto.getRandomValues(randomBytes);
        // Conversion en chaîne hexadécimale lisible pour simplifier
        document.getElementById("aes-enc-key").value = bufToHex(randomBytes).toUpperCase();
    });

    // Génération automatique de l'IV (96 bits/12 octets pour GCM, 16 octets pour CBC)
    document.getElementById("aes-enc-gen-iv")?.addEventListener("click", () => {
        if (!encIvCheck.checked) return;
        const isGcm = encTagCheck.checked;
        const size = isGcm ? 12 : 16;
        const ivBytes = new Uint8Array(size);
        window.crypto.getRandomValues(ivBytes);
        encIvInput.value = bufToBase64(ivBytes);
    });

    // Action Chiffrer AES
    document.getElementById("aes-enc-btn")?.addEventListener("click", async () => {
        const message = document.getElementById("aes-enc-msg").value;
        const keyStr = document.getElementById("aes-enc-key").value;
        const isIv = encIvCheck.checked;
        const isGcm = encTagCheck.checked;
        const ivB64 = encIvInput.value;

        if (!message) return alert("Veuillez saisir un message à chiffrer.");
        if (!keyStr) return alert("Veuillez saisir ou générer une clé secrète.");
        if (isIv && !ivB64) return alert("Veuillez générer ou saisir un IV (Base64).");

        try {
            // Generar o recuperar Salt
            let saltBuf = new Uint8Array(16);
            window.crypto.getRandomValues(saltBuf);
            document.getElementById("aes-enc-salt").value = bufToBase64(saltBuf.buffer);

            const aesKey = await deriveAesKey(keyStr, saltBuf, isGcm ? "AES-GCM" : "AES-CBC");
            const dataBuf = strToBuf(message);

            let ivBuf;
            if (isIv) {
                ivBuf = base64ToBuf(ivB64);
                if (!ivBuf) return alert("Format de l'IV (Base64) invalide.");
            } else {
                const ivSize = isGcm ? 12 : 16;
                ivBuf = new Uint8Array(ivSize).buffer;
            }

            let cipherBytes, tagBytes, packedBuf;

            if (isGcm) {
                const encrypted = await window.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: ivBuf, tagLength: 128 },
                    aesKey,
                    dataBuf
                );

                const fullBytes = new Uint8Array(encrypted);
                cipherBytes = fullBytes.slice(0, fullBytes.byteLength - 16);
                tagBytes = fullBytes.slice(fullBytes.byteLength - 16);

                document.getElementById("aes-enc-cipher").value = bufToBase64(cipherBytes.buffer);
                document.getElementById("aes-enc-tag").value = bufToBase64(tagBytes.buffer);
                
                // Pack: salt(16) || IV(12) || cipher || tag(16)
                packedBuf = new Uint8Array(16 + ivBuf.byteLength + cipherBytes.byteLength + tagBytes.byteLength);
                packedBuf.set(new Uint8Array(saltBuf), 0);
                packedBuf.set(new Uint8Array(ivBuf), 16);
                packedBuf.set(cipherBytes, 16 + ivBuf.byteLength);
                packedBuf.set(tagBytes, 16 + ivBuf.byteLength + cipherBytes.byteLength);

            } else {
                let finalIvBuf = ivBuf;
                if (ivBuf.byteLength < 16) {
                    const padded = new Uint8Array(16);
                    padded.set(new Uint8Array(ivBuf));
                    finalIvBuf = padded.buffer;
                }

                const encrypted = await window.crypto.subtle.encrypt(
                    { name: "AES-CBC", iv: finalIvBuf },
                    aesKey,
                    dataBuf
                );
                cipherBytes = new Uint8Array(encrypted);

                document.getElementById("aes-enc-cipher").value = bufToBase64(cipherBytes.buffer);
                document.getElementById("aes-enc-tag").value = "";
                
                // Pack: salt(16) || IV(16) || cipher
                packedBuf = new Uint8Array(16 + finalIvBuf.byteLength + cipherBytes.byteLength);
                packedBuf.set(new Uint8Array(saltBuf), 0);
                packedBuf.set(new Uint8Array(finalIvBuf), 16);
                packedBuf.set(cipherBytes, 16 + finalIvBuf.byteLength);
            }
            
            if (document.getElementById("aes-enc-packed")) {
                document.getElementById("aes-enc-packed").value = bufToBase64(packedBuf.buffer);
            }

        } catch (err) {
            console.error(err);
            alert("Erreur de chiffrement AES. Vérifiez les formats et tailles d'IV.");
        }
    });

    // Action Réinitialiser AES-Chiffrement
    document.getElementById("aes-enc-reset")?.addEventListener("click", () => {
        encForm.reset();
        document.getElementById("aes-enc-cipher").value = "";
        document.getElementById("aes-enc-tag").value = "";
        document.getElementById("aes-enc-salt").value = "";
        if (document.getElementById("aes-enc-packed")) document.getElementById("aes-enc-packed").value = "";
        encIvCheck.checked = true;
        encTagCheck.checked = true;
        updateAesEncInputs();
    });

    // Auto-fill from packed block
    const decPackedInput = document.getElementById("aes-dec-packed");
    if (decPackedInput) {
        decPackedInput?.addEventListener("input", () => {
            const packedB64 = decPackedInput.value.trim();
            if (!packedB64) return;
            const packedBuf = base64ToBuf(packedB64);
            if (!packedBuf) return;
            const bytes = new Uint8Array(packedBuf);
            if (bytes.length < 16) return;
            
            const isGcm = decTagCheck.checked;
            const ivSize = isGcm ? 12 : 16;
            
            if (bytes.length < 16 + ivSize) return;
            
            const saltBytes = bytes.slice(0, 16);
            const ivBytes = bytes.slice(16, 16 + ivSize);
            
            document.getElementById("aes-dec-salt").value = bufToBase64(saltBytes.buffer);
            document.getElementById("aes-dec-iv").value = bufToBase64(ivBytes.buffer);
            
            if (isGcm) {
                if (bytes.length < 16 + ivSize + 16) return;
                const tagBytes = bytes.slice(bytes.length - 16);
                const cipherBytes = bytes.slice(16 + ivSize, bytes.length - 16);
                document.getElementById("aes-dec-tag").value = bufToBase64(tagBytes.buffer);
                document.getElementById("aes-dec-cipher").value = bufToBase64(cipherBytes.buffer);
            } else {
                const cipherBytes = bytes.slice(16 + ivSize);
                document.getElementById("aes-dec-cipher").value = bufToBase64(cipherBytes.buffer);
                document.getElementById("aes-dec-tag").value = "";
            }
        });
    }

    // Action Déchiffrer AES
    document.getElementById("aes-dec-btn")?.addEventListener("click", async () => {
        const cipherB64 = document.getElementById("aes-dec-cipher").value;
        const saltB64 = document.getElementById("aes-dec-salt").value;
        const keyStr = document.getElementById("aes-dec-key").value;
        const isIv = decIvCheck.checked;
        const isGcm = decTagCheck.checked;
        const ivB64 = decIvInput.value;
        const tagB64 = decTagInput.value;
        const statusDiv = document.getElementById("aes-dec-status");
        const plainArea = document.getElementById("aes-dec-plain");

        statusDiv.className = "alert d-none";
        plainArea.value = "";

        if (!cipherB64) return alert("Veuillez saisir le texte chiffré.");
        if (!keyStr) return alert("Veuillez saisir la clé secrète.");
        if (!saltB64) return alert("Veuillez saisir le Salt (Base64).");
        if (isIv && !ivB64) return alert("Veuillez saisir l'IV (Base64).");
        if (isGcm && !tagB64) return alert("Veuillez saisir le tag d'authentification pour AES-GCM.");

        try {
            const cipherBuf = base64ToBuf(cipherB64);
            const saltBuf = base64ToBuf(saltB64);
            if (!cipherBuf) throw new Error("Format d'entrée Base64 incorrect pour le texte chiffré.");
            if (!saltBuf) throw new Error("Format du Salt Base64 invalide.");

            let ivBuf;
            if (isIv) {
                ivBuf = base64ToBuf(ivB64);
                if (!ivBuf) return alert("Format de l'IV (Base64) invalide.");
            } else {
                const ivSize = isGcm ? 12 : 16;
                ivBuf = new Uint8Array(ivSize).buffer;
            }

            const aesKey = await deriveAesKey(keyStr, saltBuf, isGcm ? "AES-GCM" : "AES-CBC");

            if (isGcm) {
                const tagBuf = base64ToBuf(tagB64);
                if (!tagBuf || tagBuf.byteLength !== 16) throw new Error("Tag GCM invalide (doit faire 16 octets / 128 bits).");

                // Concaténation ciphertext + tag pour la Web Crypto API
                const mergedBuf = new Uint8Array(cipherBuf.byteLength + tagBuf.byteLength);
                mergedBuf.set(new Uint8Array(cipherBuf), 0);
                mergedBuf.set(new Uint8Array(tagBuf), cipherBuf.byteLength);

                const decrypted = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: ivBuf, tagLength: 128 },
                    aesKey,
                    mergedBuf.buffer
                );

                plainArea.value = bufToStr(decrypted);
                statusDiv.className = "alert alert-success mt-2";
                statusDiv.innerHTML = "<i class='bi bi-check-circle-fill'></i> Déchiffrement réussi. Intégrité validée par tag GCM !";
            } else {
                // Mode non-authentifié AES-CBC
                let finalIvBuf = ivBuf;
                if (ivBuf.byteLength < 16) {
                    const padded = new Uint8Array(16);
                    padded.set(new Uint8Array(ivBuf));
                    finalIvBuf = padded.buffer;
                }

                const decrypted = await window.crypto.subtle.decrypt(
                    { name: "AES-CBC", iv: finalIvBuf },
                    aesKey,
                    cipherBuf
                );

                plainArea.value = bufToStr(decrypted);
                statusDiv.className = "alert alert-warning mt-2";
                statusDiv.innerHTML = "<i class='bi bi-exclamation-triangle-fill'></i> Déchiffrement réussi. Attention : Pas de validation d'intégrité (AES-CBC).";
            }
        } catch (err) {
            console.error(err);
            statusDiv.className = "alert alert-danger mt-2";
            statusDiv.innerHTML = "<i class='bi bi-shield-x'></i> <strong>Modification détectée, clé/IV invalide ou tag incorrect</strong> – le message est refusé.";
        }
    });
}

/* ====================================================================
   SECTION 2 : RSA-OAEP (Chiffrement et Déchiffrement)
   ==================================================================== */

// Calcule l'empreinte SHA-256 d'une clé publique au format PEM (pairs de hex séparés par deux points)
async function calculateFingerprint(pemStr) {
    try {
        const cleanPem = pemStr
            .replace(/-----BEGIN PUBLIC KEY-----/, "")
            .replace(/-----END PUBLIC KEY-----/, "")
            .replace(/\s/g, "");
        const buf = base64ToBuf(cleanPem);
        if (!buf) return "";
        const hashBuf = await window.crypto.subtle.digest("SHA-256", buf);
        const hashArray = new Uint8Array(hashBuf);
        const hex = Array.prototype.map.call(hashArray, x => ('00' + x.toString(16)).slice(-2)).join(':').toUpperCase();
        return hex;
    } catch (err) {
        console.error("Erreur lors du calcul de l'empreinte:", err);
        return "";
    }
}

function initRsaSection() {
    const encForm = document.getElementById("encrypt-rsa-form");
    const decForm = document.getElementById("decrypt-rsa-form");

    const encAuthCheck = document.getElementById("rsa-enc-auth-check");
    const encFingerprintGroup = document.getElementById("rsa-enc-fingerprint-group");
    const encFingerprintInput = document.getElementById("rsa-enc-fingerprint");
    const encCalcFingerprintBtn = document.getElementById("rsa-enc-calc-fingerprint");

    const decAuthCheck = document.getElementById("rsa-dec-auth-check");
    const decFingerprintGroup = document.getElementById("rsa-dec-fingerprint-group");
    const decFingerprintInput = document.getElementById("rsa-dec-fingerprint");

    function updateRsaEncInputs() {
        const isAuth = encAuthCheck.checked;
        encFingerprintGroup.style.display = isAuth ? "block" : "none";
        encFingerprintInput.disabled = !isAuth;
        if (!isAuth) {
            encFingerprintInput.value = "";
        }
    }

    function updateRsaDecInputs() {
        const isAuth = decAuthCheck.checked;
        decFingerprintGroup.style.display = isAuth ? "block" : "none";
        decFingerprintInput.disabled = !isAuth;
        if (!isAuth) {
            decFingerprintInput.value = "";
        }
    }

    encAuthCheck?.addEventListener("change", updateRsaEncInputs);
    decAuthCheck?.addEventListener("change", updateRsaDecInputs);

    // Configuración inicial
    updateRsaEncInputs();
    updateRsaDecInputs();

    // Calculer l'empreinte automatiquement dans l'onglet de chiffrement
    encCalcFingerprintBtn?.addEventListener("click", async () => {
        const bobPubPem = document.getElementById("rsa-enc-bob-pub").value;
        if (!bobPubPem) {
            return alert("Veuillez saisir ou générer la clé publique de Bob d'abord.");
        }
        const fingerprint = await calculateFingerprint(bobPubPem);
        if (!fingerprint) {
            return alert("Format de la clé publique de Bob invalide.");
        }
        encFingerprintInput.value = fingerprint;
    });

    // Générer clés Alice
    document.getElementById("rsa-enc-gen-alice")?.addEventListener("click", async () => {
        const size = parseInt(document.getElementById("rsa-enc-size").value);
        const btn = document.getElementById("rsa-enc-gen-alice");
        btn.disabled = true;
        btn.textContent = "Génération...";

        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: size,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );

            const privPem = await exportKeyToPem(keyPair.privateKey, 'private');
            const pubPem = await exportKeyToPem(keyPair.publicKey, 'public');

            document.getElementById("rsa-enc-alice-priv").value = privPem;
            document.getElementById("rsa-enc-alice-pub").value = pubPem;
        } catch (err) {
            console.error(err);
            alert("Erreur de génération des clés d'Alice.");
        } finally {
            btn.disabled = false;
            btn.textContent = "Générer les clés d'Alice";
        }
    });

    // Générer clés Bob
    document.getElementById("rsa-enc-gen-bob")?.addEventListener("click", async () => {
        const size = parseInt(document.getElementById("rsa-enc-size").value);
        const btn = document.getElementById("rsa-enc-gen-bob");
        btn.disabled = true;
        btn.textContent = "Génération...";

        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: size,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );

            const privPem = await exportKeyToPem(keyPair.privateKey, 'private');
            const pubPem = await exportKeyToPem(keyPair.publicKey, 'public');

            document.getElementById("rsa-enc-bob-pub").value = pubPem;
            const bobPrivArea = document.getElementById("rsa-enc-bob-priv");
            bobPrivArea.value = "⚠️ Clé privée de Bob non partagée.";
            bobPrivArea.setAttribute("data-copy-value", privPem);

            const copyBtn = document.getElementById("btn-copy-bob-priv");
            if (copyBtn) {
                copyBtn.innerHTML = `<i class="fa-solid fa-copy me-1"></i> Copier la clé secrète de Bob`;
            }
        } catch (err) {
            console.error(err);
            alert("Erreur de génération des clés de Bob.");
        } finally {
            btn.disabled = false;
            btn.textContent = "Générer les clés de Bob";
        }
    });

    // Chiffrer RSA
    document.getElementById("rsa-enc-btn")?.addEventListener("click", async () => {
        const msg = document.getElementById("rsa-enc-msg").value;
        const bobPubPem = document.getElementById("rsa-enc-bob-pub").value;
        const isAuth = encAuthCheck.checked;
        const fingerprint = encFingerprintInput.value.trim();

        if (!msg) return alert("Veuillez saisir un message à chiffrer.");
        if (!bobPubPem) return alert("Veuillez saisir ou générer la clé publique du destinataire Bob.");
        if (isAuth && !fingerprint) return alert("Veuillez calculer ou saisir l'empreinte de la clé publique.");

        try {
            const pubKey = await importKeyFromPem(bobPubPem, "RSA-OAEP", "public", ["encrypt"]);
            const encrypted = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                pubKey,
                strToBuf(msg)
            );
            document.getElementById("rsa-enc-cipher").value = bufToBase64(encrypted);
        } catch (err) {
            console.error(err);
            alert("Erreur lors du chiffrement RSA : clé publique invalide ou texte trop long pour la taille de clé.");
        }
    });

    // Réinitialiser RSA-Chiffrement
    document.getElementById("rsa-enc-reset")?.addEventListener("click", () => {
        encForm.reset();
        document.getElementById("rsa-enc-alice-priv").value = "";
        document.getElementById("rsa-enc-alice-pub").value = "";
        document.getElementById("rsa-enc-bob-pub").value = "";

        const bobPrivArea = document.getElementById("rsa-enc-bob-priv");
        bobPrivArea.value = "";
        bobPrivArea.removeAttribute("data-copy-value");

        const copyBtn = document.getElementById("btn-copy-bob-priv");
        if (copyBtn) {
            copyBtn.innerHTML = `<i class="fa-solid fa-copy me-1"></i> Copier`;
        }

        document.getElementById("rsa-enc-cipher").value = "";
        encAuthCheck.checked = false;
        updateRsaEncInputs();
    });

    // Déchiffrer RSA
    document.getElementById("rsa-dec-btn")?.addEventListener("click", async () => {
        const cipherB64 = document.getElementById("rsa-dec-cipher").value;
        const bobPrivPem = document.getElementById("rsa-dec-priv").value;
        const isAuth = decAuthCheck.checked;
        const expectedFingerprint = decFingerprintInput.value.trim().toUpperCase();
        const statusDiv = document.getElementById("rsa-dec-status");
        const plainArea = document.getElementById("rsa-dec-plain");

        statusDiv.className = "alert d-none";
        plainArea.value = "";

        if (!cipherB64) return alert("Veuillez coller le texte chiffré (Base64).");
        if (!bobPrivPem) return alert("Veuillez coller la clé privée de Bob.");
        if (isAuth && !expectedFingerprint) return alert("Veuillez saisir l'empreinte attendue de la clé publique.");

        try {
            // Si la autenticación está activa, comparamos la impronta esperada con la real de Bob
            if (isAuth) {
                const bobPubPem = document.getElementById("rsa-enc-bob-pub").value;
                if (!bobPubPem) {
                    throw new Error("Clé publique de Bob manquante dans l'onglet de chiffrement pour vérification.");
                }
                const actualFingerprint = await calculateFingerprint(bobPubPem);
                if (actualFingerprint !== expectedFingerprint) {
                    statusDiv.className = "alert alert-danger mt-2";
                    statusDiv.innerHTML = "<i class='bi bi-shield-x'></i> <strong>Échec de l'authentification de la clé publique !</strong> L'empreinte ne correspond pas. Risque d'attaque MITM détecté !";
                    return;
                }
            }

            const privKey = await importKeyFromPem(bobPrivPem, "RSA-OAEP", "private", ["decrypt"]);
            const cipherBuf = base64ToBuf(cipherB64);
            if (!cipherBuf) throw new Error("Base64 invalide");

            const decrypted = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privKey,
                cipherBuf
            );

            plainArea.value = bufToStr(decrypted);

            if (isAuth) {
                statusDiv.className = "alert alert-success mt-2";
                statusDiv.innerHTML = "<i class='bi bi-check-circle-fill'></i> Déchiffrement réussi. <strong>Authentification de la clé publique OK !</strong> L'empreinte correspond, la communication est sécurisée.";
            } else {
                statusDiv.className = "alert alert-success mt-2";
                statusDiv.innerHTML = "<i class='bi bi-check-circle-fill'></i> Déchiffrement RSA-OAEP réussi !";
            }
        } catch (err) {
            console.error(err);
            statusDiv.className = "alert alert-danger mt-2";
            statusDiv.innerHTML = `<i class='bi bi-shield-x'></i> ${err.message.includes("manquante") ? err.message : "Échec du déchiffrement. La clé privée ne correspond pas ou le ciphertext est corrompu."}`;
        }
    });
}

/* ====================================================================
   SECTION 3 : HACHAGE (SHA-256)
   ==================================================================== */

function initHashSection() {
    // Calculer SHA-256
    document.getElementById("hash-calc-btn")?.addEventListener("click", async () => {
        const msg = document.getElementById("hash-msg").value;
        if (!msg) return alert("Veuillez saisir un message à hacher.");

        try {
            const buf = strToBuf(msg);
            const hash = await window.crypto.subtle.digest("SHA-256", buf);
            document.getElementById("hash-result").value = bufToHex(hash);
        } catch (err) {
            console.error(err);
            alert("Erreur lors du calcul du hash SHA-256.");
        }
    });

    // Comparateur
    document.getElementById("hash-compare-btn")?.addEventListener("click", () => {
        const hash1 = document.getElementById("hash-result").value.trim().toLowerCase();
        const hash2 = document.getElementById("hash-compare-input").value.trim().toLowerCase();
        const statusDiv = document.getElementById("hash-compare-status");

        statusDiv.className = "alert d-none";

        if (!hash1) return alert("Veuillez d'abord calculer l'empreinte du message d'origine.");
        if (!hash2) return alert("Veuillez coller l'autre empreinte à comparer.");

        statusDiv.classList.remove("d-none");
        if (hash1 === hash2) {
            statusDiv.className = "alert alert-success mt-2";
            statusDiv.innerHTML = "<i class='bi bi-check-circle-fill'></i> Message authentique (empreintes identiques, intégrité vérifiée !)";
        } else {
            statusDiv.className = "alert alert-danger mt-2";
            statusDiv.innerHTML = "<i class='bi bi-shield-x'></i> Message modifié (empreintes différentes, le message a été altéré !)";
        }
    });

    // Attaque de dictionnaire sur SHA-256
    document.getElementById("hash-dict-btn")?.addEventListener("click", async () => {
        const targetHash = document.getElementById("hash-result").value.trim().toLowerCase();
        if (!targetHash) return alert("Veuillez d'abord calculer l'empreinte d'un message pour lancer l'attaque.");

        const dictPanel = document.getElementById("hash-dict-pane");
        const progContainer = document.getElementById("hash-dict-progress-container");
        const progBar = document.getElementById("hash-dict-progress");
        const wordsStatus = document.getElementById("hash-dict-words-status");
        const resultDiv = document.getElementById("hash-dict-result");

        dictPanel.classList.remove("d-none");
        progContainer.classList.remove("d-none");
        progBar.style.width = "0%";
        wordsStatus.innerHTML = "";
        resultDiv.innerHTML = "Démarrage de l'attaque...";

        // Dictionnaire de valeurs faibles prédéfinies
        const dictionary = ["1234", "0000", "ADMIN", "SECRET", "2026", "password", "crypto", "123456", "bonjour", "cyber"];

        let step = 0;
        let found = false;
        let foundValue = "";

        // Animation séquentielle
        for (const word of dictionary) {
            await new Promise(r => setTimeout(r, 600)); // Pause pédagogique

            step++;
            const pct = Math.round((step / dictionary.length) * 100);
            progBar.style.width = pct + "%";

            // Calcul du hash du mot courant
            const wordBuf = strToBuf(word);
            const wordHashBuf = await window.crypto.subtle.digest("SHA-256", wordBuf);
            const wordHash = bufToHex(wordHashBuf);

            const isMatch = wordHash === targetHash;

            const badgeClass = isMatch ? "dict-word-check matched" : "dict-word-check failed";
            const icon = isMatch ? "bi-check-circle-fill" : "bi-x-circle";
            wordsStatus.innerHTML += `<span class="${badgeClass}"><i class="bi ${icon}"></i> ${word}</span>`;

            if (isMatch) {
                found = true;
                foundValue = word;
                break;
            }
        }

        progContainer.classList.add("d-none");
        if (found) {
            resultDiv.className = "alert alert-danger p-2 small mt-2";
            resultDiv.innerHTML = `<i class="bi bi-unlock-fill"></i> <strong>Attaque réussie !</strong> Eve a retrouvé le message d'origine : <strong>"${foundValue}"</strong>.<br>Raison : Le message était trop faible et présent dans son dictionnaire.`;
        } else {
            resultDiv.className = "alert alert-success p-2 small mt-2";
            resultDiv.innerHTML = `<i class="bi bi-shield-lock-fill"></i> <strong>Attaque échouée.</strong> Eve n'a pas retrouvé le message d'origine parmi ses valeurs faibles.<br>Raison : Le message est complexe ou absent du dictionnaire prédéfini.`;
        }
    });

    // Déchiffrement : Vérification
    document.getElementById("hash-verify-btn")?.addEventListener("click", async () => {
        const msg = document.getElementById("hash-verify-msg").value;
        const expected = document.getElementById("hash-verify-expected").value.trim().toLowerCase();
        const statusDiv = document.getElementById("hash-verify-status");

        statusDiv.className = "alert d-none";

        if (!msg) return alert("Veuillez saisir le message à vérifier.");
        if (!expected) return alert("Veuillez saisir l'empreinte de contrôle attendue.");

        try {
            const buf = strToBuf(msg);
            const hash = await window.crypto.subtle.digest("SHA-256", buf);
            const hex = bufToHex(hash);

            statusDiv.classList.remove("d-none");
            if (hex === expected) {
                statusDiv.className = "alert alert-success mt-2";
                statusDiv.innerHTML = "<i class='bi bi-check-circle-fill'></i> <strong>Empreintes identiques – message intact</strong>. L'intégrité du document est garantie !";
            } else {
                statusDiv.className = "alert alert-danger mt-2";
                statusDiv.innerHTML = "<i class='bi bi-shield-x'></i> <strong>Empreintes différentes – message modifié</strong> ! Le contenu a été altéré pendant le transit.";
            }
        } catch (err) {
            console.error(err);
            alert("Erreur lors de la vérification.");
        }
    });

    document.getElementById("hash-verify-reset")?.addEventListener("click", () => {
        document.getElementById("verify-hash-form").reset();
        document.getElementById("hash-verify-status").className = "alert d-none";
    });
}

/* ====================================================================
   SECTION 4 : SIGNATURE NUMÉRIQUE (Génération et validation)
   ==================================================================== */

function initSignatureSection() {
    const signForm = document.getElementById("sign-form");

    // Générer clé de signature
    document.getElementById("sign-gen-key-btn")?.addEventListener("click", async () => {
        const btn = document.getElementById("sign-gen-key-btn");
        btn.disabled = true;
        btn.textContent = "...";

        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["sign", "verify"]
            );

            const privPem = await exportKeyToPem(keyPair.privateKey, 'private');
            const pubPem = await exportKeyToPem(keyPair.publicKey, 'public');

            document.getElementById("sign-priv-key").value = privPem;
            document.getElementById("sign-pub-key").value = pubPem;
        } catch (err) {
            console.error(err);
            alert("Erreur lors de la génération de la paire de clés de signature.");
        } finally {
            btn.disabled = false;
            btn.textContent = "Générer";
        }
    });

    // Générer Signature
    document.getElementById("sign-btn")?.addEventListener("click", async () => {
        const msg = document.getElementById("sign-msg").value;
        const privPem = document.getElementById("sign-priv-key").value;

        if (!msg) return alert("Veuillez écrire un message à signer.");
        if (!privPem) return alert("Veuillez saisir ou générer votre clé privée de signature.");

        try {
            const privKey = await importKeyFromPem(privPem, "RSA-PSS", "private", ["sign"]);
            const signature = await window.crypto.subtle.sign(
                { name: "RSA-PSS", saltLength: 32 },
                privKey,
                strToBuf(msg)
            );
            document.getElementById("sign-signature").value = bufToBase64(signature);
        } catch (err) {
            console.error(err);
            alert("Erreur de génération de signature : clé privée invalide.");
        }
    });

    document.getElementById("sign-reset")?.addEventListener("click", () => {
        signForm.reset();
        document.getElementById("sign-signature").value = "";
        document.getElementById("sign-pub-key").value = "";
    });

    // Valider Signature
    document.getElementById("sign-verify-btn")?.addEventListener("click", async () => {
        const msg = document.getElementById("sign-verify-msg").value;
        const sigB64 = document.getElementById("sign-verify-sig").value;
        const pubPem = document.getElementById("sign-verify-pub").value;
        const statusDiv = document.getElementById("sign-verify-status");

        statusDiv.className = "alert d-none";

        if (!msg) return alert("Veuillez saisir le message signé.");
        if (!sigB64) return alert("Veuillez saisir la signature en Base64.");
        if (!pubPem) return alert("Veuillez saisir la clé publique du signataire.");

        try {
            const pubKey = await importKeyFromPem(pubPem, "RSA-PSS", "public", ["verify"]);
            const sigBuf = base64ToBuf(sigB64);
            if (!sigBuf) throw new Error("Base64 de la signature invalide");

            const isValid = await window.crypto.subtle.verify(
                { name: "RSA-PSS", saltLength: 32 },
                pubKey,
                sigBuf,
                strToBuf(msg)
            );

            statusDiv.classList.remove("d-none");
            if (isValid) {
                statusDiv.className = "alert alert-success mt-2";
                statusDiv.innerHTML = "<i class='bi bi-patch-check-fill'></i> <strong>Signature valide – identité authentifiée</strong> ! Le message provient bien d'Alice et n'a subi aucune modification.";
            } else {
                statusDiv.className = "alert alert-danger mt-2";
                statusDiv.innerHTML = "<i class='bi bi-shield-exclamation'></i> <strong>Signature invalide – identité supplantée ou message modifié</strong> ! La clé de signature ou l'intégrité du message est en cause.";
            }
        } catch (err) {
            console.error(err);
            statusDiv.classList.remove("d-none");
            statusDiv.className = "alert alert-danger mt-2";
            statusDiv.innerHTML = "<i class='bi bi-shield-x'></i> <strong>Erreur de validation</strong> : Clé publique corrompue ou format de signature invalide.";
        }
    });

    document.getElementById("sign-verify-reset")?.addEventListener("click", () => {
        document.getElementById("verify-sign-form").reset();
        document.getElementById("sign-verify-status").className = "alert d-none";
    });
}

/* ====================================================================
   SECTION 5 : MOTEUR DE SIMULATION D'ATTAQUE MITM
   ==================================================================== */

let isSimulationRunning = false;
let isSimulationActive = false; // Indique si la session de simulation est en cours (à travers les cycles)
let simulationStepCount = 0;    // Compte le nombre d'étapes de communication
let currentDirection = "forward"; // forward (Alice -> Bob) ou backward (Bob -> Alice)
let simulationTimeout = null;

// Données des scénarios
const SCENARIOS = {
    aes: [
        {
            id: "aes-a",
            name: "Essai A : Clé inconnue d'Eve",
            desc: "Alice chiffre son message avec une clé secrète partagée. Eve intercepte le texte chiffré mais n'a pas la clé. Bob déchiffre le message intact.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Non",
            canDecrypt: "Non",
            canModify: "Non",
            detect: "Non (Pas d'attaque)",
            justification: "Le message est chiffré symétriquement avec AES. N'ayant pas accès à la clé secrète partagée, Eve ne peut ni le lire ni le déchiffrer. Bob reçoit le message original sans altération."
        },
        {
            id: "aes-b",
            name: "Essai B : Clé obtenue par Eve",
            desc: "Eve a dérobé la clé secrète partagée via un canal non sécurisé. Elle intercepte le flux, lit le message en clair et peut le modifier avant de le renvoyer.",
            risk: "critical",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Oui",
            canRead: "Oui",
            canDecrypt: "Oui",
            canModify: "Oui",
            detect: "Non (Si CBC ou si tag recalculé par Eve)",
            justification: "Puisqu'elle dispose de la clé secrète, le chiffrement n'offre plus aucune confidentialité. Eve peut déchiffrer, lire, altérer le message, puis le rechiffrer. Pour Bob, le message semblera provenir d'Alice."
        },
        {
            id: "aes-c",
            name: "Essai C : Message modifié par Eve (GCM vs CBC)",
            desc: "Eve intercepte la communication cryptée et modifie des bits au hasard. Si AES-GCM est utilisé, la modification est détectée grâce au tag d'authentification. Si AES-CBC (non-authentifié) est utilisé, Bob déchiffre un message corrompu sans lever d'alerte.",
            risk: "critical", // Le risque est élevé en soi, critique en cas de non détection
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Non",
            canDecrypt: "Non",
            canModify: "Oui",
            detect: "Oui (GCM) / Non (CBC)",
            justification: "Avec AES-GCM, le tag d'authentification garantit l'intégrité. Toute modification par Eve provoque un rejet immédiat. En AES-CBC, l'intégrité n'est pas vérifiée : Bob obtient un message déchiffré incompréhensible sans savoir qu'il a été altéré par Eve."
        }
    ],
    rsa: [
        {
            id: "rsa-a",
            name: "Essai A : Communication normale",
            desc: "Bob envoie sa clé publique à Alice. Alice chiffre avec cette clé. Bob déchiffre avec sa clé privée. Eve intercepte le texte chiffré mais n'a pas la clé privée de Bob.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Non",
            canDecrypt: "Non",
            canModify: "Non",
            detect: "Non",
            justification: "Le chiffrement asymétrique RSA-OAEP protège la confidentialité. Bien qu'Eve intercepte le message chiffré, seul Bob possède la clé privée correspondante nécessaire pour le déchiffrer."
        },
        {
            id: "rsa-b",
            name: "Essai B : Attaque MITM (Remplacement de clé publique)",
            desc: "Bob envoie sa clé publique. Eve l'intercepte et transmet sa propre clé publique à Alice. Alice chiffre son message pour Eve. Eve le déchiffre, le lit, le modifie, puis le rechiffre avec la vraie clé de Bob.",
            risk: "critical",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Oui (Eve utilise sa propre clé privée)",
            canRead: "Oui",
            canDecrypt: "Oui",
            canModify: "Oui",
            detect: "Non (Bob déchiffre avec sa clé privée)",
            justification: "Alice n'a aucun moyen de vérifier à qui appartient la clé publique reçue. Eve s'interpose en générant un double jeu de clés. Elle déchiffre le message d'Alice et le renvoie rechiffré à Bob sans qu'aucun ne s'en rende compte."
        },
        {
            id: "rsa-c",
            name: "Essai C : Authentification de la clé publique",
            desc: "Alice vérifie l'empreinte de la clé publique de Bob via un canal alternatif de confiance (téléphone, certificat). Elle s'aperçoit que la clé transmise par Eve ne correspond pas à celle de Bob et refuse d'envoyer le message.",
            risk: "low",
            intercepted: "Non (Communication bloquée)",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Non",
            canDecrypt: "Non",
            canModify: "Non",
            detect: "Oui (L'attaque est contrée dès le départ)",
            justification: "L'authentification de la clé publique par empreinte ou certificat évite l'attaque MITM. Alice détecte la falsification de clé opérée par Eve et suspend la transmission."
        }
    ],
    sha: [
        {
            id: "sha-a",
            name: "Essai A : Message non modifié",
            desc: "Alice envoie un document et son empreinte SHA-256. Bob recalcule l'empreinte et constate qu'elle est identique. L'intégrité est prouvée.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Sans objet",
            canRead: "Oui (Le message n'est pas chiffré)",
            canDecrypt: "Sans objet",
            canModify: "Non",
            detect: "Non (Aucune modification)",
            justification: "Le hachage ne protège pas la confidentialité (le message est transmis en clair). Néanmoins, comme aucune modification n'a été effectuée, Bob calcule le même hash et valide l'intégrité."
        },
        {
            id: "sha-b",
            name: "Essai B : Message modifié par Eve",
            desc: "Eve intercepte le message et en modifie le contenu. L'empreinte d'origine ayant été transmise de manière sécurisée, Bob calcule l'empreinte du message reçu et constate qu'elle diffère.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Sans objet",
            canRead: "Oui",
            canDecrypt: "Sans objet",
            canModify: "Oui",
            detect: "Oui (Les empreintes ne correspondent pas)",
            justification: "Toute modification du message en transit altère son empreinte. Si l'empreinte originale d'Alice est transmise de manière intègre, Bob verra instantanément que le document a été modifié."
        },
        {
            id: "sha-c",
            name: "Essai C : Message faible (Attaque par dictionnaire)",
            desc: "Alice envoie uniquement l'empreinte d'un message très court (ex: '1234'). Eve intercepte l'empreinte et utilise un dictionnaire de valeurs communes pour retrouver le message en clair.",
            risk: "high",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Sans objet",
            canRead: "Non (Initialement), puis Oui après attaque",
            canDecrypt: "Sans objet",
            canModify: "Non",
            detect: "Non",
            justification: "Bien que le hachage soit à sens unique, si la valeur hachée est faible ou prévisible (mot de passe standard, code pin), Eve peut pré-calculer des millions d'empreintes (attaque de dictionnaire) et retrouver la valeur initiale."
        },
        {
            id: "sha-d",
            name: "Scénario : Limite de l'empreinte seule",
            desc: "Eve intercepte à la fois le message et l'empreinte sur le même canal. Elle modifie le message, calcule la nouvelle empreinte SHA-256 et transmet le tout à Bob qui n'y voit que du feu.",
            risk: "critical",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Sans objet",
            canRead: "Oui",
            canDecrypt: "Sans objet",
            canModify: "Oui",
            detect: "Non (Bob valide une empreinte pourtant falsifiée)",
            justification: "C'est la limite du hachage simple : il ne garantit pas l'AUTHENTICITÉ. Si Eve remplace le message ET le hachage associé, Bob calcule l'empreinte du message d'Eve et la compare au hachage d'Eve. La comparaison réussit mais l'expéditeur a été usurpé."
        }
    ],
    sig: [
        {
            id: "sig-a",
            name: "Essai A : Signature valide",
            desc: "Alice signe son message avec sa clé privée de signature. Bob valide la signature avec la clé publique d'Alice. Le message est authentique et intact.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non (Clé privée d'Alice secrète)",
            canRead: "Oui (Pas de chiffrement)",
            canDecrypt: "Sans objet",
            canModify: "Non",
            detect: "Non (Pas de modification)",
            justification: "La signature numérique prouve l'authenticité de l'auteur et l'intégrité du message. Eve peut lire le message (car non chiffré), mais ne peut pas altérer la communication sans invalider la signature d'Alice."
        },
        {
            id: "sig-b",
            name: "Essai B : Message modifié par Eve (MITM)",
            desc: "Alice signe le message. Eve intercepte le tout et modifie le message. À la réception, Bob vérifie la signature d'Alice sur le message modifié et la rejette.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Oui",
            canDecrypt: "Sans objet",
            canModify: "Oui",
            detect: "Oui (La signature est invalidée par la modification)",
            justification: "Puisque le message a été altéré, son hash ne correspond plus à celui chiffré dans la signature. Bob détecte immédiatement que l'intégrité est compromise."
        },
        {
            id: "sig-c",
            name: "Essai C : Fausse signature",
            desc: "Eve tente d'usurper l'identité d'Alice. Elle écrit un message et génère une fausse signature. N'ayant pas la clé privée d'Alice, sa signature est rejetée par Bob lors du contrôle.",
            risk: "low",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Non",
            canRead: "Oui",
            canDecrypt: "Sans objet",
            canModify: "Oui",
            detect: "Oui (Signature invalide)",
            justification: "Eve ne peut pas forger la signature d'Alice sans posséder sa clé privée. Bob applique la clé publique d'Alice sur la signature reçue et s'aperçoit que la validation échoue."
        },
        {
            id: "sig-d",
            name: "Essai D : Clé publique d'Alice remplacée (MITM)",
            desc: "Eve intercepte la clé publique de signature d'Alice et la remplace par sa propre clé publique auprès de Bob. Elle envoie ensuite un message signé avec sa propre clé privée. Bob croit que la signature est valide et qu'elle provient d'Alice.",
            risk: "critical",
            intercepted: "Oui",
            algoKnown: "Oui",
            keyKnown: "Oui (Eve utilise sa propre clé privée)",
            canRead: "Oui",
            canDecrypt: "Sans objet",
            canModify: "Oui",
            detect: "Non (Bob valide avec la fausse clé publique d'Eve)",
            justification: "C'est l'analogue de l'attaque MITM sur RSA. Si Bob n'a pas vérifié l'authenticité de la clé publique de signature d'Alice, il va utiliser la clé d'Eve pour valider les messages signés par Eve, validant ainsi l'usurpation."
        }
    ]
};

// Initialisation du module MITM
function initMitmSimulation() {
    const methodSelect = document.getElementById("mitm-method");
    const scenarioSelect = document.getElementById("mitm-scenario");
    const scenarioDesc = document.getElementById("mitm-scenario-desc");

    const btnStart = document.getElementById("mitm-btn-start");
    const btnStop = document.getElementById("mitm-btn-stop");
    const btnReset = document.getElementById("mitm-btn-reset");
    const warningInProgress = document.getElementById("mitm-warning-in-progress");

    // Événement changement de méthode cryptographique
    methodSelect?.addEventListener("change", () => {
        populateScenarios(methodSelect.value);
        updateDynamicControlsVisibility(methodSelect.value);
    });

    // Événement changement de scénario
    scenarioSelect?.addEventListener("change", () => {
        updateScenarioDescription();
    });

    // Événements de changement des options dynamiques pour recalculer la description
    ["mitm-aes-iv-check", "mitm-aes-tag-check", "mitm-rsa-size", "mitm-rsa-auth-check"].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el?.addEventListener("change", () => {
                updateScenarioDescription();
            });
        }
    });

    // Événement démarrage ou continuation de la simulation
    btnStart?.addEventListener("click", () => {
        if (isSimulationRunning) return;

        if (currentDirection === "eve_forward") {
            resumeFromEveForward();
        } else if (currentDirection === "eve_backward") {
            resumeFromEveBackward();
        } else if (!isSimulationActive) {
            // Premier lancement de la session
            isSimulationActive = true;
            simulationStepCount = 1;
            currentDirection = "forward";
            startSimulation();
        } else {
            // Étape suivante (continuation)
            simulationStepCount++;
            if (currentDirection === "forward") {
                startSimulation();
            } else {
                startReplySimulation();
            }
        }
    });

    // Événement arrêt de la simulation
    btnStop?.addEventListener("click", () => {
        stopSimulation();
    });

    // Événement réinitialisation
    btnReset?.addEventListener("click", () => {
        resetSimulation();
    });

    // Bloquer les modifications si simulation en cours
    [methodSelect, scenarioSelect].forEach(select => {
        select?.addEventListener("mousedown", (e) => {
            if (isSimulationRunning) {
                e.preventDefault();
                warningInProgress.classList.remove("d-none");
                setTimeout(() => warningInProgress.classList.add("d-none"), 3000);
            }
        });
    });

    // Bloquer aussi les contrôles dynamiques si simulation en cours
    const dynamicInputs = [
        "mitm-aes-iv-check", "mitm-aes-tag-check",
        "mitm-rsa-size", "mitm-rsa-auth-check"
    ];
    dynamicInputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el?.addEventListener("mousedown", (e) => {
                if (isSimulationRunning) {
                    e.preventDefault();
                    warningInProgress.classList.remove("d-none");
                    setTimeout(() => warningInProgress.classList.add("d-none"), 3000);
                }
            });
            el?.addEventListener("click", (e) => {
                if (isSimulationRunning) {
                    e.preventDefault();
                }
            });
        }
    });

    // Écouteur pour l'auto-expansion de la zone de texte
    const messageInput = document.getElementById("mitm-message-input");
    if (messageInput) {
        messageInput?.addEventListener("input", function () {
            this.style.height = "auto";
            this.style.height = (this.scrollHeight) + "px";
        });
    }

    // Remplissage initial
    populateScenarios("aes");
    updateDynamicControlsVisibility("aes");
}

// Gère la visibilité des contrôles de simulation spécifiques AES/RSA
function updateDynamicControlsVisibility(method) {
    const aesControls = document.getElementById("mitm-aes-controls");
    const rsaControls = document.getElementById("mitm-rsa-controls");
    if (aesControls) {
        if (method === "aes") {
            aesControls.classList.remove("d-none");
        } else {
            aesControls.classList.add("d-none");
        }
    }
    if (rsaControls) {
        if (method === "rsa") {
            rsaControls.classList.remove("d-none");
        } else {
            rsaControls.classList.add("d-none");
        }
    }
}

// Évalue dynamiquement le scénario choisi en fonction des cases cochées
function getDynamicState(method, scenarioId) {
    const originalSc = SCENARIOS[method].find(s => s.id === scenarioId);
    if (!originalSc) return null;

    // Clone profond pour ne pas altérer les données de base
    let sc = JSON.parse(JSON.stringify(originalSc));

    if (method === "aes") {
        const isIv = document.getElementById("mitm-aes-iv-check").checked;
        const isGcm = document.getElementById("mitm-aes-tag-check").checked;

        if (scenarioId === "aes-a") {
            sc.algoKnown = "Oui";
            sc.keyKnown = "Non";
            sc.canRead = "Non";
            sc.canDecrypt = "Non";
            sc.canModify = "Non";
            sc.detect = "Non (Pas d'attaque)";

            if (isIv && isGcm) {
                sc.risk = "Faible";
                sc.justification = "Le message est chiffré symétriquement avec AES. N'ayant pas accès à la clé secrète partagée, Eve ne peut ni le lire ni le déchiffrer. Bob reçoit le message original sans altération.";
            } else if (!isGcm && isIv) {
                sc.risk = "Moyen";
                sc.justification = "Le message est chiffré en mode AES-CBC (non authentifié). Eve n'ayant pas la clé ne peut pas lire le message, mais l'absence de tag GCM rend le canal vulnérable aux attaques par modification active.";
            } else if (isGcm && !isIv) {
                sc.risk = "Moyen";
                sc.justification = "Le message est chiffré sans IV unique (ou IV fixe). Si Alice renvoie le même message, Eve observera le même texte chiffré, ce qui affaiblit gravement la sécurité en révélant des motifs (patterns).";
            } else {
                sc.risk = "Élevé";
                sc.justification = "Le message est chiffré en AES-CBC sans IV unique ni tag d'authentification. C'est le niveau de sécurité le plus faible pour AES: Eve peut effectuer des analyses de motifs et aucune intégrité n'est garantie.";
            }
        } else if (scenarioId === "aes-b") {
            sc.risk = "Critique";
            sc.algoKnown = "Oui";
            sc.keyKnown = "Oui";
            sc.canRead = "Oui";
            sc.canDecrypt = "Oui";
            sc.canModify = "Non";

            if (isGcm) {
                sc.detect = "Non";
                sc.justification = "Puisqu'elle dispose de la clé secrète, le chiffrement n'offre plus aucune confidentialité. En AES-GCM, Eve intercepte le message et le déchiffre/traduit en clair pour le lire. Le message original est transmis sans altération à Bob.";
            } else {
                sc.detect = "Non";
                sc.justification = "Puisqu'elle dispose de la clé secrète, le chiffrement n'offre plus aucune confidentialité. En AES-CBC, Eve intercepte le message, le déchiffre/traduit en clair pour el lire, puis le transmet à Bob sans modification.";
            }
        } else if (scenarioId === "aes-c") {
            sc.algoKnown = "Oui";
            sc.keyKnown = "Non";
            sc.canRead = "Non";
            sc.canDecrypt = "Non";

            if (isGcm) {
                sc.risk = "Faible"; // Bloqué et détecté
                sc.detect = "Oui (GCM)";
                sc.canModify = "Oui (Tentative)";
                sc.justification = "Grâce au mode AES-GCM (authentifié), toute modification du texte chiffré par Eve invalide le tag d'authentification. Bob détecte immédiatement l'altération et rejette le message, préservant l'intégrité.";
            } else {
                sc.risk = "Critique"; // Modifié sans alerte
                sc.detect = "Non (CBC)";
                sc.canModify = "Oui";
                sc.justification = "En mode AES-CBC (non authentifié), il n'y a pas de validation d'intégrité. Eve altère la communication et Bob déchiffre des données corrompues sans s'apercevoir de l'interposition active d'Eve.";
            }
        }
    }
    else if (method === "rsa") {
        const keySize = document.getElementById("mitm-rsa-size").value;
        const isAuth = document.getElementById("mitm-rsa-auth-check").checked;

        if (scenarioId === "rsa-a") {
            sc.algoKnown = "Oui";
            sc.keyKnown = "Non";
            sc.canRead = "Non";
            sc.canDecrypt = "Non";
            sc.canModify = "Non";
            sc.detect = "Non";

            if (keySize === "1024") {
                sc.risk = "Moyen";
                sc.justification = "Le chiffrement RSA est utilisé avec une taille de clé historique de 1024 bits. Bien qu'Eve n'ait pas la clé privée, cette clé est aujourd'hui vulnérable à la factorisation par des acteurs disposant de gros moyens de calcul.";
            } else if (keySize === "2048") {
                sc.risk = "Faible";
                sc.justification = "Le chiffrement RSA-OAEP avec une clé standard de 2048 bits protège efficacement la confidentialité. Seul Bob, détenteur de la clé privée, peut déchiffrer le message.";
            } else {
                sc.risk = "Faible";
                sc.justification = "Le chiffrement utilise une clé RSA de 4096 bits, offrant un niveau de sécurité maximal et à long terme, bien que les calculs soient plus lents.";
            }
        }
        else if (scenarioId === "rsa-b" || scenarioId === "rsa-c") {
            if (isAuth) {
                sc.risk = "Faible";
                sc.intercepted = "Non (Bloqué)";
                sc.detect = "Oui (Fingerprint incorrect)";
                sc.canRead = "Non";
                sc.canDecrypt = "Non";
                sc.canModify = "Non";
                sc.justification = `L'authentification de la clé publique est activée (${keySize} bits) ! Alice compare l'empreinte de la clé reçue avec celle de Bob. L'empreinte ne correspondant pas, Alice bloque l'envoi du message, déjouant le MITM.`;
            } else {
                sc.risk = "Critique";
                sc.intercepted = "Oui";
                sc.detect = "Non";
                sc.canRead = "Oui";
                sc.canDecrypt = "Oui (Clé d'Eve)";
                sc.canModify = "Oui";
                if (keySize === "1024") {
                    sc.justification = "L'authentification de la clé est inactive et la clé de substitution est de 1024 bits (clé faible). Eve réalise son MITM avec succès. Elle lit et modifie le message sans qu'Alice ni Bob ne le détectent.";
                } else {
                    sc.justification = "L'authentification de la clé publique est inactive. Alice fait aveuglément confiance à la clé reçue. Eve intercepte la communication, la déchiffre avec sa propre clé privée, la lit, la modifie et la transmet à Bob.";
                }
            }
        }
    }

    return sc;
}

// Remplit le menu des scénarios en fonction de la méthode sélectionnée
function populateScenarios(method) {
    const scenarioSelect = document.getElementById("mitm-scenario");
    scenarioSelect.innerHTML = "";

    const list = SCENARIOS[method] || [];
    list.forEach(sc => {
        const opt = document.createElement("option");
        opt.value = sc.id;
        opt.textContent = sc.name;
        scenarioSelect.appendChild(opt);
    });

    updateScenarioDescription();
}

// Met à jour la description textuelle du scénario courant de manière dynamique
function updateScenarioDescription() {
    const method = document.getElementById("mitm-method").value;
    const scenarioId = document.getElementById("mitm-scenario").value;
    const descDiv = document.getElementById("mitm-scenario-desc");
    if (!descDiv) return;

    const sc = getDynamicState(method, scenarioId);
    if (sc) {
        // 1. Descripción del método criptográfico escogido avec/sin options
        let methodDesc = "";
        if (method === "aes") {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;
            methodDesc = `<strong>Méthode :</strong> AES (Chiffrement Symétrique) configuré en mode <strong>${isGcm ? "GCM (authentifié)" : "CBC (non-authentifié)"}</strong>${isIv ? " avec vecteur d'initialisation (IV) aléatoire" : " sans IV (IV fixe/vide)"}.`;
        } else if (method === "rsa") {
            const keySize = document.getElementById("mitm-rsa-size").value;
            const isAuth = document.getElementById("mitm-rsa-auth-check").checked;
            methodDesc = `<strong>Méthode :</strong> RSA (Chiffrement Asymétrique) utilisant des clés de <strong>${keySize} bits</strong>, avec l'authentification de clé publique <strong>${isAuth ? "activée" : "désactivée"}</strong>.`;
        } else if (method === "sha") {
            methodDesc = `<strong>Méthode :</strong> Hachage cryptographique SHA-256 pour le calcul des empreintes d'intégrité (aucun chiffrement ni confidentialité appliqués aux données).`;
        } else if (method === "sig") {
            methodDesc = `<strong>Méthode :</strong> Signature Numérique basée sur RSA et SHA-256 pour prouver l'authenticité de l'émetteur et protéger l'intégrité de la transmission.`;
        }

        // 2. Descripción del escenario escogido
        let scenarioDesc = `<strong>Scénario :</strong> ${sc.desc}`;

        // 3. Resultado esperado de la simulación
        let expectedResult = "";
        if (method === "aes") {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;
            if (scenarioId === "aes-a") {
                if (!isIv) {
                    expectedResult = "En l'absence d'IV aléatoire, la répétition de messages identiques produira le même cryptogramme, permettant à Eve d'identifier des patterns de communication.";
                } else {
                    expectedResult = "Grâce à l'IV aléatoire, le texte chiffré intercepté change à chaque envoi. Eve ne peut identifier aucun pattern ou répéter des messages.";
                }
            } else if (scenarioId === "aes-b") {
                if (isGcm) {
                    expectedResult = "Puisqu'elle a dérobé la clé, Eve déchiffre et lit le message d'Alice en clair (le traduit), puis le transmet inchangé à Bob.";
                } else {
                    expectedResult = "Eve déchiffre et lit le message d'Alice en clair (le traduit) en utilisant la clé volée, puis le reroute vers Bob sans modification.";
                }
            } else if (scenarioId === "aes-c") {
                if (isGcm) {
                    expectedResult = "La modification d'Eve sera détectée par Bob lors de la validation du tag GCM. Bob rejettera immédiatement la transmission corrompue.";
                } else {
                    expectedResult = "Bob recevra le message altéré, le déchiffrera en CBC et obtiendra des données corrompues sans s'en rendre compte ni lever d'alerte.";
                }
            }
        } else if (method === "rsa") {
            const keySize = document.getElementById("mitm-rsa-size").value;
            const isAuth = document.getElementById("mitm-rsa-auth-check").checked;
            if (scenarioId === "rsa-a") {
                if (keySize === "1024") {
                    expectedResult = "La clé de 1024 bits est trop faible. Bien qu'Eve ne lise pas le message directement, la clé publique peut être factorisée mathématiquement.";
                } else {
                    expectedResult = "Avec une taille de clé robuste de 2048 ou 4096 bits, Eve ne peut pas casser la clé par factorisation mathématique. La confidentialité est préservée.";
                }
            } else if (scenarioId === "rsa-b" || scenarioId === "rsa-c") {
                if (isAuth) {
                    expectedResult = "Alice détectera l'attaque de substitution de clé en comparant l'empreinte de la clé publique reçue. Elle bloquera le transfert.";
                } else {
                    expectedResult = "Eve interceptera la clé publique de Bob et enverra la sienne à Alice. Eve interceptera ensuite le message, le lira et le modifiera.";
                }
            }
        } else if (method === "sha") {
            if (scenarioId === "sha-a") {
                expectedResult = "Le message et son empreinte arrivent intacts. Bob calcule l'empreinte de son côté et valide sa parfaite intégrité.";
            } else if (scenarioId === "sha-b") {
                expectedResult = "Eve modifie le contenu du message. Bob recalcule l'empreinte du document reçu, constate qu'elle diffère de l'originale et rejette la modification.";
            } else if (scenarioId === "sha-c") {
                expectedResult = "Le message étant trop faible (court/prévisible), Eve utilise un dictionnaire de hachages précalculés pour inverser el hash et lire le message d'origine.";
            } else if (scenarioId === "sha-d") {
                expectedResult = "Eve modifie le message et recalcule son propre hash SHA-256. Bob validera la correspondance mais ignore qu'il a été berné par un usurpateur.";
            }
        } else if (method === "sig") {
            if (scenarioId === "sig-a") {
                expectedResult = "Bob valide la signature numérique d'Alice à l'aide de sa clé publique de confiance. L'authenticité de l'expéditeur et l'intégrité sont prouvées.";
            } else if (scenarioId === "sig-b") {
                expectedResult = "Eve modifie le message en transit. Lors de la vérification, la signature d'Alice ne correspond plus au contenu altéré. Bob rejette le message.";
            } else if (scenarioId === "sig-c") {
                expectedResult = "Eve usurpe l'identité d'Alice en signant avec sa propre clé privée. La validation de Bob avec la clé publique d'Alice échoue.";
            } else if (scenarioId === "sig-d") {
                expectedResult = "Eve substitue la clé publique d'Alice par la sienne chez Bob. Bob validera la signature d'Eve en croyant qu'elle provient d'Alice.";
            }
        }

        let expectedResultHtml = `<strong>Résultat attendu :</strong> ${expectedResult}`;

        // 4. Alerta de nivel de riesgo (se mantiene dinámica según la configuración)
        let riskColorClass = "";
        let riskLabel = sc.risk;
        if (sc.risk === "Faible" || sc.risk === "low") {
            riskColorClass = "text-success border border-success bg-success-transparent";
            riskLabel = "Faible";
        } else if (sc.risk === "Moyen" || sc.risk === "medium") {
            riskColorClass = "text-warning border border-warning bg-warning-transparent";
            riskLabel = "Moyen";
        } else if (sc.risk === "Élevé" || sc.risk === "high") {
            riskColorClass = "text-orange border border-orange bg-orange-transparent";
            riskLabel = "Élevé";
        } else if (sc.risk === "Critique" || sc.risk === "critical") {
            riskColorClass = "text-danger border border-danger bg-danger-transparent";
            riskLabel = "Critique";
        }

        let riskHtml = `<div class="d-flex align-items-center gap-2 mt-2">
            <strong>Niveau de risque de la simulation :</strong>
            <span class="badge ${riskColorClass} px-2 py-1">${riskLabel}</span>
        </div>`;

        // Assemblage des sections
        descDiv.innerHTML = `
            <div class="mb-1">${methodDesc}</div>
            <div class="mb-1">${scenarioDesc}</div>
            <div class="mb-1">${expectedResultHtml}</div>
            ${riskHtml}
        `;
        if (typeof updateResultsCard === "function") {
            updateResultsCard(sc);
        }
    }
}

// Écrit une ligne dans la console de logs
function addLog(actor, message) {
    const logsContainer = document.getElementById("mitm-logs");
    const now = new Date();
    const timeStr = `[${now.toTimeString().split(' ')[0]}]`;

    let actorClass = "log-system";
    let prefix = "[Système]";

    if (actor === "alice") {
        actorClass = "log-alice";
        prefix = "[Alice]";
    } else if (actor === "eve") {
        actorClass = "log-eve";
        prefix = "[Eve]";
    } else if (actor === "bob") {
        actorClass = "log-bob";
        prefix = "[Bob]";
    }

    const logEl = document.createElement("div");
    logEl.className = `log-entry ${actorClass}`;
    logEl.innerHTML = `<span class="log-time">${timeStr}</span> <span class="fw-bold">${prefix}</span> ${message}`;

    logsContainer.appendChild(logEl);
    logsContainer.scrollTop = logsContainer.scrollHeight;

    // Relay to individual actor console if applicable
    if (["alice", "bob", "eve"].includes(actor)) {
        addActorConsoleLog(actor, message);
    }
}

// Remplit la fiche de résultats dynamique
function updateResultsCard(sc, showEmpty = false) {
    const methodEl = document.getElementById("res-method");
    const interceptEl = document.getElementById("res-intercept");
    const algoEl = document.getElementById("res-algo");
    const keyEl = document.getElementById("res-key");
    const readEl = document.getElementById("res-read");
    const decryptEl = document.getElementById("res-decrypt");
    const modifyEl = document.getElementById("res-modify");
    const detectEl = document.getElementById("res-detect");
    const riskEl = document.getElementById("res-risk");
    const justificationEl = document.getElementById("res-justification");

    if (showEmpty || !sc) {
        methodEl.textContent = "-";
        [interceptEl, algoEl, keyEl, readEl, decryptEl, modifyEl, detectEl].forEach(el => {
            el.textContent = "-";
            el.className = "badge bg-secondary";
        });
        riskEl.textContent = "-";
        riskEl.className = "risk-badge";
        riskEl.style.color = "";
        justificationEl.textContent = "Lancez une simulation pour analyser l'impact du scénario sur la sécurité des communications.";
        return;
    }

    const methodNames = { aes: "AES (Symétrique)", rsa: "RSA (Asymétrique)", sha: "SHA-256 (Hachage)", sig: "Signature Numérique" };
    const methodKey = document.getElementById("mitm-method").value;

    methodEl.textContent = methodNames[methodKey];

    // Remplissage des badges Oui/Non
    formatBadge(interceptEl, sc.intercepted);
    formatBadge(algoEl, sc.algoKnown);
    formatBadge(keyEl, sc.keyKnown);
    formatBadge(readEl, sc.canRead);
    formatBadge(decryptEl, sc.canDecrypt);
    formatBadge(modifyEl, sc.canModify);
    formatBadge(detectEl, sc.detect);

    // Risque
    riskEl.textContent = sc.risk;
    riskEl.className = `risk-badge risk-${sc.risk}`;

    // Justification
    justificationEl.textContent = sc.justification;
}

function formatBadge(element, text) {
    element.textContent = text;
    if (text.startsWith("Oui")) {
        element.className = "badge bg-danger text-white";
    } else if (text.startsWith("Non")) {
        element.className = "badge bg-success text-white";
    } else if (text.includes("détecte") || text.includes("recalculé") || text.includes("contrée")) {
        element.className = "badge bg-warning text-dark";
    } else {
        element.className = "badge bg-secondary text-white";
    }
}

// Lance la simulation du transfert Alice -> Eve -> Bob
function startSimulation() {
    isSimulationRunning = true;
    currentDirection = "forward";

    // Auto-scroll window to place the animation track in the center
    const track = document.querySelector(".animation-track-container");
    if (track) {
        track.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    const method = document.getElementById("mitm-method").value;
    const scenarioId = document.getElementById("mitm-scenario").value;
    const sc = getDynamicState(method, scenarioId);
    updateAvatarShadows(sc.risk);

    // Ajustement de l'état des boutons
    document.getElementById("mitm-btn-start").disabled = true;
    document.getElementById("mitm-btn-stop").disabled = false;
    document.getElementById("mitm-method").disabled = true;
    document.getElementById("mitm-scenario").disabled = true;

    // Desactivar controles opcionales
    const optIv = document.getElementById("mitm-aes-iv-check");
    const optTag = document.getElementById("mitm-aes-tag-check");
    const optSize = document.getElementById("mitm-rsa-size");
    const optAuth = document.getElementById("mitm-rsa-auth-check");
    if (optIv) optIv.disabled = true;
    if (optTag) optTag.disabled = true;
    if (optSize) optSize.disabled = true;
    if (optAuth) optAuth.disabled = true;

    // Réinitialisation de l'affichage (seulement au début)
    if (simulationStepCount === 1) {
        document.getElementById("mitm-logs").innerHTML = "";
        clearActorConsoles();
    }
    resetActorCards();

    // Verrouiller l'input pendant l'envoi
    setMitMInputAuthor("Alice", true);
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";

    addLog("system", `Démarrage de la simulation (Étape ${simulationStepCount}) : ${sc.name}`);
    addActorConsoleLog("alice", "Création et préparation du message.", "console-header");
    addActorConsoleLog("alice", `Texte: "${messageText}"`);

    // Gestion du paquet
    const packet = document.getElementById("packet");
    packet.style.display = "flex";
    packet.className = "data-packet";
    packet.style.left = "16.66%"; // Position d'Alice
    setActiveNode("node-alice");

    // Étape 1 : Alice prépare et envoie le message
    addLog("alice", "Création et préparation du message.");
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

    // SI LA COMMUNICATION EST BLOQUÉE (Autenticación de RSA activa en MITM)
    if (sc.intercepted && sc.intercepted.includes("Non")) {
        setTimeout(() => {
            if (!isSimulationRunning) return;
            addLog("alice", "⚠️ Vérification de l'empreinte de la clé reçue.");
            addLog("alice", "❌ L'empreinte ne correspond pas ! Risque d'attaque MITM détecté.");
            addLog("alice", "Alice bloque immédiatement la communication et n'envoie pas le message.");
            document.getElementById("state-alice").textContent = "Envoi Bloqué ❌";
            document.getElementById("card-alice").classList.remove("border-primary");
            document.getElementById("card-alice").classList.add("border-danger");
            packet.style.display = "none";

            setTimeout(() => {
                if (!isSimulationRunning) return;
                addLog("system", "Simulation terminée. L'attaque MITM a été déjouée grâce à l'authentification.");
                updateResultsCard(sc);
                stopSimulationState();
            }, 1500);
        }, 1500);
        return;
    }

    // Animation Alice -> Eve
    animatePacket("16.66%", "50%", 1500, () => {
        if (!isSimulationRunning) return;

        setActiveNode("node-eve");

        document.getElementById("state-alice").textContent = "Message envoyé";
        document.getElementById("state-eve").textContent = "Interception...";
        document.getElementById("card-eve").classList.add("active-eve");

        // Étape 2 : Eve intercepte et analyse
        addLog("eve", "Message intercepté en transit.");
        addActorConsoleLog("eve", "Interception du message d'Alice.", "console-header");

        // Logs de simulation d'analyse cryptographique par Eve
        simulateEveBehavior(sc, "forward", () => {
            if (!isSimulationRunning) return;
            resumeFromEveForward(sc);
        });
    });
}

function resumeFromEveForward(sc = null) {
    isSimulationRunning = true;
    currentDirection = "forward";

    if (!sc) {
        const method = document.getElementById("mitm-method").value;
        const scenarioId = document.getElementById("mitm-scenario").value;
        sc = getDynamicState(method, scenarioId);
    }

    const packet = document.getElementById("packet");

    // Boutons ajustés
    document.getElementById("mitm-btn-start").disabled = true;
    setMitMInputAuthor("Eve", true); // Bloquer pendant l'animation

    // Animation Eve -> Bob
    addLog("eve", "Transmission du message (éventuellement modifié/rechiffré) vers Bob.");
    addActorConsoleLog("eve", "Reroutage du message vers Bob.");
    document.getElementById("state-eve").textContent = "Transmis";
    document.getElementById("state-bob").textContent = "Réception...";

    // Si Eve a modifié le message
    if (sc.id === "aes-c" || sc.id === "rsa-b" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
        packet.className = "data-packet compromised";
    }

    animatePacket("50%", "83.33%", 1500, () => {
        if (!isSimulationRunning) return;

        setActiveNode("node-bob");

        document.getElementById("state-bob").textContent = "Traitement...";
        document.getElementById("card-bob").classList.add("border-success");

        // Étape 3 : Bob déchiffre/vérifie
        simulateBobBehavior(sc, "forward", () => {
            if (!isSimulationRunning) return;

            addLog("system", "Étape Alice ➔ Bob terminée. Prêt pour la réponse.");
            updateResultsCard(sc);

            // Add Chat Message
            try {
                let isSpoofed = false;
                const trace = typeof currentSimulationTrace !== 'undefined' ? currentSimulationTrace : null;
                if (trace && trace.eve && (trace.eve["Action"] === "Modification" || trace.eve["Message en clair Altéré"] || trace.eve["Signature (Base64)"])) {
                    isSpoofed = true;
                }
                
                let msgTxt = "(Vide)";
                if (trace) {
                    if (trace.receiver && trace.receiver["Message Déchiffré"]) {
                        msgTxt = trace.receiver["Message Déchiffré"];
                    } else if (trace.sender && trace.sender["Message Original"]) {
                        msgTxt = trace.sender["Message Original"];
                    }
                    
                    if (trace.eve && trace.eve["Message en clair Altéré"]) {
                        msgTxt = trace.eve["Message en clair Altéré"];
                    }
                }
                
                if (window.addChatMessage) {
                    window.addChatMessage("Alice", msgTxt, isSpoofed);
                }
            } catch (e) {
                console.error("Chat message error: ", e);
            }

            // Permettre la continuation
            const btnStart = document.getElementById("mitm-btn-start");
            btnStart.innerHTML = `<i class="fa-solid fa-reply me-2"></i> Répondre (Bob)`;
            btnStart.disabled = false;

            setMitMInputAuthor("Bob", false, "");

            // Réactiver les contrôles de configuration pour modifications entre étapes
            document.getElementById("mitm-method").disabled = false;
            document.getElementById("mitm-scenario").disabled = false;
            const optIv = document.getElementById("mitm-aes-iv-check");
            const optTag = document.getElementById("mitm-aes-tag-check");
            const optSize = document.getElementById("mitm-rsa-size");
            const optAuth = document.getElementById("mitm-rsa-auth-check");
            if (optIv) optIv.disabled = false;
            if (optTag) optTag.disabled = false;
            if (optSize) optSize.disabled = false;
            if (optAuth) optAuth.disabled = false;

            isSimulationRunning = false;
            currentDirection = "backward";
        });
    });
}

// Déplacement d'un paquet de données d'un point A à un point B
function animatePacket(from, to, duration, callback) {
    const packet = document.getElementById("packet");
    packet.style.left = from;

    // Utilisation de la transition CSS pour plus de fluidité
    packet.style.transition = `left ${duration}ms linear`;

    // Forcer le reflow
    packet.offsetHeight;

    packet.style.left = to;

    simulationTimeout = setTimeout(callback, duration);
}
function simulateEveBehavior(sc, direction, callback) {
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    setTimeout(() => {
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
            } else if (sc.id === "aes-b") {
                addLog("eve", `Clé secrète obtenue ! Déchiffrement AES-${isGcm ? "GCM" : "CBC"} du message en clair réussi.`);
                addLog("eve", `Text: ${messageText}`);
            } else if (sc.id === "aes-c") {
                addLog("eve", "Altération arbitraire de quelques bits dans le texte chiffré intercepté.");
                if (isGcm) {
                    addLog("eve", "Eve ne peut pas forger un tag d'authentification GCM valide sans la clé secrète.");
                } else {
                    addLog("eve", "Comme le mode est CBC (sans tag), Eve espère que l'altération passera inaperçue.");
                }
            }
        }
        else if (sc.id.startsWith("rsa")) {
            const keySize = document.getElementById("mitm-rsa-size").value;
            const isAuth = document.getElementById("mitm-rsa-auth-check").checked;

            if (sc.id === "rsa-a") {
                addLog("eve", `Copie de la clé publique de Bob (${keySize} bits) interceptée.`);
                if (keySize === "1024") {
                    addLog("eve", "⚠️ Clé de 1024 bits interceptée ! Eve pourrait tenter une attaque par factorisation mathématique avec des supercalculateurs.");
                } else {
                    addLog("eve", `Clé robuste de ${keySize} bits interceptée. La factorisation de la clé publique est impossible.`);
                }
                addLog("eve", "Cryptogramme intercepté, mais la clé privée de Bob reste secrète. Lecture impossible.");
            } else if (sc.id === "rsa-b" || sc.id === "rsa-c") {
                addLog("eve", "Interception de la clé publique de Bob en transit.");
                addLog("eve", `Substitution de clé : Eve transmet sa propre clé publique (${keySize} bits) à Alice.`);
                addLog("eve", "Message d'Alice chiffré sous la clé d'Eve reçu. Déchiffrement avec la clé privée d'Eve : Lecture et modification.");
                addLog("eve", `Text: ${messageText}`);
                addLog("eve", `Re-chiffrement du message modifié avec la vraie clé publique de Bob (${keySize} bits).`);
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
            } else if (sc.id === "sig-c") {
                addLog("eve", "Création d'un faux message et d'une signature forgée de toutes pièces par Eve.");
            } else if (sc.id === "sig-d") {
                addLog("eve", "Substitution de la clé publique de signature d'Alice par celle d'Eve chez Bob.");
                addLog("eve", "Envoi d'un message malveillant signé avec la clé privée d'Eve.");
            }
        }

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
}

// Simule le traitement de Bob à la réception du message
function simulateBobBehavior(sc, direction, callback) {
    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    setTimeout(() => {
        if (sc.id.startsWith("aes")) {
            const isIv = document.getElementById("mitm-aes-iv-check").checked;
            const isGcm = document.getElementById("mitm-aes-tag-check").checked;

            if (sc.id === "aes-a") {
                if (isGcm) {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-GCM réussi. Message intègre reçu.");
                } else {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-CBC réussi. Attention : Pas de validation d'intégrité (GCM inactif).");
                }
                addActorConsoleLog("bob", `Texte: "${messageText}"`);
            } else if (sc.id === "aes-b") {
                if (isGcm) {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-GCM réussi. Bob reçoit le message original d'Alice, ignorant qu'Eve l'a également intercepté et lu.");
                } else {
                    addLog("bob", "Clé secrète appliquée. Déchiffrement AES-CBC réussi. Bob reçoit le message original d'Alice, ignorant qu'Eve l'a également intercepté et lu.");
                }
                addActorConsoleLog("bob", `Texte: "${messageText}"`);
            } else if (sc.id === "aes-c") {
                addLog("bob", "Tentative de déchiffrement...");
                if (isGcm) {
                    addLog("bob", "❌ Échec de l'authentification GCM (tag de contrôle invalide) ! Le message a été altéré et a été REJETÉ.");
                } else {
                    addLog("bob", "Mode AES-CBC alternatif : Le déchiffrement s'opère mais le texte est corrompu (garbage text). Aucune alerte d'intégrité levée !");
                    addActorConsoleLog("bob", `Texte: "${messageText}"`);
                }
            }
        }
        else if (sc.id.startsWith("rsa")) {
            const keySize = document.getElementById("mitm-rsa-size").value;
            const isAuth = document.getElementById("mitm-rsa-auth-check").checked;

            if (sc.id === "rsa-a") {
                addLog("bob", `Déchiffrement réussi avec la clé privée de Bob (${keySize} bits). Message confidentiel reçu.`);
            } else if (sc.id === "rsa-b" || sc.id === "rsa-c") {
                addLog("bob", `Déchiffrement avec la clé privée de Bob (${keySize} bits) réussi.`);
                addLog("bob", "Le message semble techniquement correct, mais l'expéditeur a été usurpé en transit par substitution de clé publique !");
            }
            addActorConsoleLog("bob", `Texte: "${messageText}"`);
        }
        else if (sc.id.startsWith("sha")) {
            if (sc.id === "sha-a") {
                addLog("bob", "Empreinte calculée sur le document = empreinte d'Alice. Intégrité validée.");
            } else if (sc.id === "sha-b") {
                addLog("bob", "Empreinte calculée ne correspond pas à l'empreinte reçue. Le message a été altéré !");
            } else if (sc.id === "sha-c") {
                addLog("bob", "Réception de l'empreinte de contrôle.");
            } else if (sc.id === "sha-d") {
                addLog("bob", "Empreinte calculée correspond à l'empreinte reçue par le même canal. Bob accepte le message falsifié.");
            }
            addActorConsoleLog("bob", `Texte: "${messageText}"`);
        }
        else if (sc.id.startsWith("sig")) {
            if (sc.id === "sig-a") {
                addLog("bob", "Vérification de la signature d'Alice avec sa clé publique. Signature valide. Identité authentifiée.");
            } else if (sc.id === "sig-b") {
                addLog("bob", "Vérification de la signature d'Alice. Échec : la signature ne correspond pas au contenu modifié.");
            } else if (sc.id === "sig-c") {
                addLog("bob", "Vérification de la signature avec la clé d'Alice. Échec : la signature a été falsifiée par Eve.");
            } else if (sc.id === "sig-d") {
                addLog("bob", "Vérification de la signature avec la clé publique (qui est celle d'Eve). Signature valide. Usurpation réussie !");
            }
            addActorConsoleLog("bob", `Texte: "${messageText}"`);
        }
        callback();
    }, 1800);
}

// Lance la simulation de réponse de Bob vers Alice en repassant par Eve
function startReplySimulation() {
    isSimulationRunning = true;
    currentDirection = "backward";

    // Auto-scroll window to place the animation track in the center
    const track = document.querySelector(".animation-track-container");
    if (track) {
        track.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    document.getElementById("mitm-btn-start").disabled = true;
    document.getElementById("mitm-btn-stop").disabled = false;

    const method = document.getElementById("mitm-method").value;
    const scenarioId = document.getElementById("mitm-scenario").value;
    const sc = getDynamicState(method, scenarioId);
    updateAvatarShadows(sc.risk);

    resetActorCards();
    const roleAlice = document.getElementById("role-alice");
    const roleBob = document.getElementById("role-bob");
    if (roleAlice) roleAlice.textContent = "Destinataire";
    if (roleBob) roleBob.textContent = "Émetteur";

    document.getElementById("card-bob").classList.add("border-success");
    document.getElementById("state-bob").textContent = "Réponse en cours...";

    const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
    setMitMInputAuthor("Bob", true); // Lock during transit

    addLog("system", `Lancement de la communication de retour (Étape ${simulationStepCount} : Bob ➔ Alice).`);
    addActorConsoleLog("bob", "Création et préparation de la réponse.", "console-header");
    addActorConsoleLog("bob", `Texte: "${messageText}"`);

    const packet = document.getElementById("packet");
    packet.style.display = "flex";
    packet.className = "data-packet";
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

    addLog("bob", "Envoi d'une réponse à Alice.");

    // Animation Bob -> Eve
    animatePacket("83.33%", "50%", 1500, () => {
        if (!isSimulationRunning) return;

        setActiveNode("node-eve");

        document.getElementById("state-bob").textContent = "Réponse envoyée";
        document.getElementById("state-eve").textContent = "Interception de retour...";
        document.getElementById("card-eve").classList.add("active-eve");

        addLog("eve", "Interception de la réponse en transit.");

        setTimeout(() => {
            if (!isSimulationRunning) return;

            let canPause = false;
            if (sc.id === "aes-c" || sc.id === "rsa-b" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui" || sc.id === "rsa-c") {
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

function resumeFromEveBackward(sc = null) {
    isSimulationRunning = true;
    currentDirection = "backward";

    if (!sc) {
        const method = document.getElementById("mitm-method").value;
        const scenarioId = document.getElementById("mitm-scenario").value;
        sc = getDynamicState(method, scenarioId);
    }

    const packet = document.getElementById("packet");

    document.getElementById("mitm-btn-start").disabled = true;
    setMitMInputAuthor("Eve", true);

    if (sc.id === "rsa-b" || sc.id === "rsa-c" || sc.id === "aes-c" || sc.id === "sha-b" || sc.id === "sha-d" || sc.id === "sig-b" || sc.id === "sig-d" || sc.canModify === "Oui") {
        addLog("eve", "Eve transmet la réponse (éventuellement modifiée).");
        packet.className = "data-packet compromised";
    } else {
        addLog("eve", "Interception passive du flux chiffré de retour.");
    }

    addLog("eve", "Reroutage de la réponse vers Alice.");
    document.getElementById("state-eve").textContent = "Transmis";
    document.getElementById("state-alice").textContent = "Réception réponse...";

    // Animation Eve -> Alice
    animatePacket("50%", "16.66%", 1500, () => {
        if (!isSimulationRunning) return;

        setActiveNode("node-alice");

        document.getElementById("state-alice").textContent = "Traitement...";
        document.getElementById("card-alice").classList.add("border-primary");

        setTimeout(() => {
            if (!isSimulationRunning) return;

            const method = document.getElementById("mitm-method").value;
            const messageText = document.getElementById("mitm-message-input").value || "(Message vide)";
            let showMessageText = true;

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
            }
            
            // Add Chat Message for Backward Journey
            try {
                let isSpoofed = false;
                const trace = typeof currentSimulationTrace !== 'undefined' ? currentSimulationTrace : null;
                let originalReply = (trace && trace.sender && trace.sender["Message Réponse"]) ? trace.sender["Message Réponse"] : "";
                
                if (originalReply && messageText && originalReply !== messageText) {
                    isSpoofed = true; // Eve modified the input field
                }
                
                if (window.addChatMessage) {
                    window.addChatMessage("Bob", messageText, isSpoofed);
                }
            } catch (e) {
                console.error("Chat message error (backward): ", e);
            }

            addLog("system", "Étape Bob ➔ Alice (Réponse) terminée. Prêt pour le message suivant.");

            // Permettre la continuation
            const btnStart = document.getElementById("mitm-btn-start");
            btnStart.innerHTML = `<i class="fa-solid fa-play me-2"></i> Démarrer la communication (Alice)`;
            btnStart.disabled = false;

            setMitMInputAuthor("Alice", false, "");

            // Réactiver les contrôles de configuration
            document.getElementById("mitm-method").disabled = false;
            document.getElementById("mitm-scenario").disabled = false;
            const optIv = document.getElementById("mitm-aes-iv-check");
            const optTag = document.getElementById("mitm-aes-tag-check");
            const optSize = document.getElementById("mitm-rsa-size");
            const optAuth = document.getElementById("mitm-rsa-auth-check");
            if (optIv) optIv.disabled = false;
            if (optTag) optTag.disabled = false;
            if (optSize) optSize.disabled = false;
            if (optAuth) optAuth.disabled = false;

            isSimulationRunning = false;
            currentDirection = "forward";
        }, 1500);
    });
}

// Arrête la simulation en cours
function stopSimulation() {
    resetSimulation();
}

// Rétablit l'état des boutons hors simulation
function stopSimulationState() {
    isSimulationRunning = false;
    isSimulationActive = false;
    simulationStepCount = 0;
    currentDirection = "forward";

    const btnStart = document.getElementById("mitm-btn-start");
    btnStart.innerHTML = `<i class="fa-solid fa-play me-2"></i> Démarrer la communication`;
    btnStart.disabled = false;

    document.getElementById("mitm-btn-stop").disabled = true;
    document.getElementById("mitm-method").disabled = false;
    document.getElementById("mitm-scenario").disabled = false;
    document.getElementById("card-eve").classList.remove("active-eve");

    const optIv = document.getElementById("mitm-aes-iv-check");
    const optTag = document.getElementById("mitm-aes-tag-check");
    const optSize = document.getElementById("mitm-rsa-size");
    const optAuth = document.getElementById("mitm-rsa-auth-check");
    if (optIv) optIv.disabled = false;
    if (optTag) optTag.disabled = false;
    if (optSize) optSize.disabled = false;
    if (optAuth) optAuth.disabled = false;

    resetAvatarShadows();
    setMitMInputAuthor("Alice", false);
}

// Réinitialise complètement la zone de simulation
function resetSimulation() {
    clearTimeout(simulationTimeout);
    isSimulationRunning = false;
    isSimulationActive = false;
    simulationStepCount = 0;
    currentDirection = "forward";

    const btnStart = document.getElementById("mitm-btn-start");
    btnStart.innerHTML = `<i class="fa-solid fa-play me-2"></i> Démarrer la communication`;
    btnStart.disabled = false;

    document.getElementById("mitm-btn-stop").disabled = true;
    document.getElementById("mitm-method").disabled = false;
    document.getElementById("mitm-scenario").disabled = false;

    const optIv = document.getElementById("mitm-aes-iv-check");
    const optTag = document.getElementById("mitm-aes-tag-check");
    const optSize = document.getElementById("mitm-rsa-size");
    const optAuth = document.getElementById("mitm-rsa-auth-check");
    if (optIv) optIv.disabled = false;
    if (optTag) optTag.disabled = false;
    if (optSize) optSize.disabled = false;
    if (optAuth) optAuth.disabled = false;

    document.getElementById("packet").style.display = "none";
    document.getElementById("mitm-logs").innerHTML = `<div class="log-entry log-system"><span class="log-time">[${new Date().toTimeString().split(' ')[0]}]</span> Console réinitialisée. Prêt.</div>`;
    
    // Vider le textarea de message
    const msgInput = document.getElementById("mitm-message-input");
    if (msgInput) msgInput.value = "";

    resetActorCards();
    updateScenarioDescription();
    resetAvatarShadows();
    clearActorConsoles();
    setMitMInputAuthor("Alice", false, "");
}

function resetActorCards() {
    const cards = ["card-alice", "card-eve", "card-bob"];
    cards.forEach(c => {
        const el = document.getElementById(c);
        if (el) {
            el.className = el.className.replace(/\bborder-\w+\b/g, '');
            el.classList.remove("active-eve");
        }
    });

    document.getElementById("state-alice").textContent = "En attente";
    document.getElementById("state-eve").textContent = "En écoute passive";
    document.getElementById("state-bob").textContent = "En attente";
    
    const roleAlice = document.getElementById("role-alice");
    const roleBob = document.getElementById("role-bob");
    if (roleAlice) roleAlice.textContent = "Émetteur";
    if (roleBob) roleBob.textContent = "Destinataire";

    setActiveNode(null);
}

function setActiveNode(nodeId) {
    document.querySelectorAll(".animation-actor-point").forEach(node => {
        node.classList.remove("active-node");
    });
    if (nodeId) {
        const el = document.getElementById(nodeId);
        if (el) el.classList.add("active-node");
    }
}

// Met à jour la couleur d'ombrage des avatars d'Alice et Bob selon le niveau de risque de la communication
function updateAvatarShadows(risk) {
    const aliceAvatar = document.getElementById("avatar-alice");
    const bobAvatar = document.getElementById("avatar-bob");
    if (!aliceAvatar || !bobAvatar) return;

    // Supprimer les classes d'ombrage de risque existantes
    aliceAvatar.className = aliceAvatar.className.replace(/\bavatar-shadow-\w+\b/g, "").trim();
    bobAvatar.className = bobAvatar.className.replace(/\bavatar-shadow-\w+\b/g, "").trim();

    if (risk) {
        // Enlever les accents pour correspondre aux classes CSS
        const cleanRisk = risk.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // "Élevé" -> "Eleve"
        aliceAvatar.classList.add(`avatar-shadow-${cleanRisk}`);
        bobAvatar.classList.add(`avatar-shadow-${cleanRisk}`);
    } else {
        aliceAvatar.classList.add("avatar-shadow-default");
        bobAvatar.classList.add("avatar-shadow-default");
    }
}

// Réinitialise l'ombrage des avatars d'Alice et Bob à l'état par défaut (noir)
function resetAvatarShadows() {
    const aliceAvatar = document.getElementById("avatar-alice");
    const bobAvatar = document.getElementById("avatar-bob");
    if (!aliceAvatar || !bobAvatar) return;

    aliceAvatar.className = aliceAvatar.className.replace(/\bavatar-shadow-\w+\b/g, "").trim();
    bobAvatar.className = bobAvatar.className.replace(/\bavatar-shadow-\w+\b/g, "").trim();

    aliceAvatar.classList.add("avatar-shadow-default");
    bobAvatar.classList.add("avatar-shadow-default");
}

// --- Fonctions pour les Consoles des Acteurs et l'Input ---

const consoleQueues = {
    alice: [],
    eve: [],
    bob: []
};
const consoleTyping = {
    alice: false,
    eve: false,
    bob: false
};

function addActorConsoleLog(actor, message, alertClass = "") {
    const consoleEl = document.getElementById(`console-${actor}`);
    if (!consoleEl) return;

    consoleQueues[actor].push({ message, alertClass });

    if (!consoleTyping[actor]) {
        processConsoleQueue(actor);
    }
}

function processConsoleQueue(actor) {
    const consoleEl = document.getElementById(`console-${actor}`);
    if (!consoleEl || consoleQueues[actor].length === 0) {
        consoleTyping[actor] = false;
        if (actor === "eve" && !isSimulationRunning && (currentDirection === "eve_forward" || currentDirection === "eve_backward")) {
            injectEveTerminalInput();
        }
        return;
    }

    consoleTyping[actor] = true;
    const { message, alertClass } = consoleQueues[actor].shift();

    const timeStr = new Date().toTimeString().split(' ')[0];
    const logDiv = document.createElement("div");
    logDiv.className = `console-line ${alertClass}`;
    consoleEl.appendChild(logDiv);
    consoleEl.scrollTop = consoleEl.scrollHeight;

    if (alertClass === "console-header") {
        typeText(logDiv, message, 12, () => {
            processConsoleQueue(actor);
        });
    } else {
        const timePrefix = `[${timeStr}] `;
        const plainMsg = message.replace(/<[^>]*>?/gm, '');

        logDiv.innerHTML = `<span style="opacity:0.5">${timePrefix}</span><span class="typing-text"></span>`;
        const textSpan = logDiv.querySelector(".typing-text");

        typeText(textSpan, plainMsg, 8, () => {
            processConsoleQueue(actor);
        });
    }
}

function typeText(element, text, speed, callback) {
    let index = 0;
    function type() {
        if (index < text.length) {
            element.textContent += text.charAt(index);
            index++;
            const parentConsole = element.closest(".actor-console");
            if (parentConsole) {
                parentConsole.scrollTop = parentConsole.scrollHeight;
            }
            setTimeout(type, speed);
        } else {
            if (callback) callback();
        }
    }
    type();
}
function injectEveTerminalInput() {
    const consoleEl = document.getElementById("console-eve");
    if (!consoleEl) return;

    if (document.getElementById("eve-cli-container")) return;

    const currentMsg = document.getElementById("mitm-message-input").value;

    const cliContainer = document.createElement("div");
    cliContainer.id = "eve-cli-container";
    cliContainer.className = "console-line mt-2 p-2 border border-danger rounded bg-black";
    cliContainer.style.fontFamily = "var(--font-mono)";
    
    cliContainer.innerHTML = `
        <div class="text-danger fw-bold mb-1" style="font-size: 0.72rem;"><i class="fa-solid fa-user-ninja me-1"></i> INTERCEPT_CLI v1.0.4</div>
        <div class="d-flex align-items-center mb-1" style="font-size: 0.72rem;">
            <span class="text-success me-1">eve@mitm:~$</span>
            <span class="text-white small">edit-msg:</span>
        </div>
        <div class="d-flex gap-2">
            <input type="text" id="eve-cli-input" class="form-control form-control-sm bg-dark text-white border-secondary" value="${currentMsg.replace(/"/g, '&quot;')}" style="font-family: var(--font-mono); font-size: 0.72rem; flex-grow: 1; height: 24px; padding: 2px 6px;">
            <button id="eve-cli-send-btn" class="btn btn-danger btn-sm px-2 py-0 d-flex align-items-center" style="font-size: 0.7rem; font-weight: bold; height: 24px;"><i class="fa-solid fa-paper-plane me-1"></i>Transmettre</button>
        </div>
    `;

    consoleEl.appendChild(cliContainer);
    consoleEl.scrollTop = consoleEl.scrollHeight;

    const cliInput = cliContainer.querySelector("#eve-cli-input");
    const cliSendBtn = cliContainer.querySelector("#eve-cli-send-btn");

    cliInput.focus();

    cliInput?.addEventListener("input", (e) => {
        document.getElementById("mitm-message-input").value = e.target.value;
    });

    const handleTransmit = () => {
        const value = cliInput.value;
        document.getElementById("mitm-message-input").value = value;
        
        cliContainer.remove();
        addActorConsoleLog("eve", `> transmit --message="${value}"`, "text-muted");
        addActorConsoleLog("eve", `Message transmis: "${value}"`, "console-alert-success");
        
        document.getElementById("mitm-btn-start").click();
    };

    cliInput?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            handleTransmit();
        }
    });

    cliSendBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        handleTransmit();
    });
}

function clearActorConsoles() {
    consoleQueues.alice = [];
    consoleQueues.eve = [];
    consoleQueues.bob = [];
    consoleTyping.alice = false;
    consoleTyping.eve = false;
    consoleTyping.bob = false;
    ["alice", "eve", "bob"].forEach(actor => {
        const el = document.getElementById(`console-${actor}`);
        if (el) el.innerHTML = "";
    });

    const chatContainer = document.getElementById("chat-messages");
    if (chatContainer) {
        chatContainer.innerHTML = `
            <div class="text-center text-muted small w-100 my-auto" id="chat-placeholder">
                <i class="fa-regular fa-message fa-2x mb-2 opacity-50"></i><br>
                Aucun message. Démarrez la simulation.
            </div>
        `;
    }
}

function setMitMInputAuthor(author, readonly = false, text = null) {
    const badge = document.getElementById("mitm-input-author-badge");
    const input = document.getElementById("mitm-message-input");

    if (badge) {
        badge.textContent = author;
        badge.className = "badge px-3 py-1 text-uppercase";
        if (author.toLowerCase() === "alice") badge.classList.add("bg-primary");
        else if (author.toLowerCase() === "bob") badge.classList.add("bg-success");
        else badge.classList.add("badge-eve-glass");
    }

    if (input) {
        input.disabled = readonly;
        if (text !== null) {
            input.value = text;
        }
    }
}
