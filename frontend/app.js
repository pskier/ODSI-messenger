const API_URL = "http://localhost:8080";

function showMessage(elementId, text, isError = false) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerText = text;
    el.className = isError ? "message error" : "message success";
    setTimeout(() => { el.innerText = ""; }, 5000);
}

function handleError(elementId, error) {
    console.error("Szczegóły błędu:", error);

    let msg = "Wystąpił nieznany błąd.";

    if (typeof error === 'string') {
        msg = error;
    } else if (error.message) {
        msg = error.message;
    }

    if (msg.includes("reading 'target'") || msg.includes("null (reading 'value')")) {
        console.warn("Zignorowano błąd wtyczki przeglądarki:", msg);
        return;
    }

    showMessage(elementId, `Błąd: ${msg}`, true);
}

function switchView(viewName) {
    document.getElementById("view-inbox").style.display = "none";
    document.getElementById("view-compose").style.display = "none";
    document.getElementById("view-2fa").style.display = "none";

    document.getElementById("nav-inbox").classList.remove("active");
    document.getElementById("nav-compose").classList.remove("active");
    document.getElementById("nav-2fa").classList.remove("active");

    if (viewName === 'inbox') {
        document.getElementById("view-inbox").style.display = "flex";
        document.getElementById("nav-inbox").classList.add("active");
        loadMessages(); 
    } else if (viewName === 'compose') {
        document.getElementById("view-compose").style.display = "flex";
        document.getElementById("nav-compose").classList.add("active");
    } else if (viewName === '2fa') {
        document.getElementById("view-2fa").style.display = "flex";
        document.getElementById("nav-2fa").classList.add("active");
    }
}

document.getElementById("nav-inbox").addEventListener("click", () => switchView('inbox'));
document.getElementById("nav-compose").addEventListener("click", () => switchView('compose'));
document.getElementById("nav-2fa").addEventListener("click", () => switchView('2fa'));

function checkAuth() {
    const username = localStorage.getItem("username");
    const authSection = document.getElementById("auth-section");
    const dashboardSection = document.getElementById("dashboard-section");
    const sidebar = document.getElementById("sidebar");
    const usernameDisplay = document.getElementById("username-display");

    if (username) {
        authSection.style.display = "none";
        dashboardSection.style.display = "block";
        sidebar.style.display = "flex";
        if(usernameDisplay) usernameDisplay.innerText = username;
        switchView('inbox');   
    } else {
        authSection.style.display = "block";
        dashboardSection.style.display = "none";
        sidebar.style.display = "none";
    }
}

document.getElementById("register-btn").addEventListener("click", async (e) => {
    if(e) e.preventDefault(); 

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;
    const btn = document.getElementById("register-btn");
    
    if (!username || !password) {
        showMessage("auth-message", "Podaj login i hasło!", true);
        return;
    }

    btn.disabled = true;
    btn.innerText = "Generowanie kluczy...";
    showMessage("auth-message", "Trwa generowanie bezpiecznych kluczy RSA...");

    try {
        const keypair = await new Promise((resolve, reject) => {
            forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
                if (err) reject(err); else resolve(keypair);
            });
        });

        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const encryptedPrivateKey = forge.pki.encryptRsaPrivateKey(keypair.privateKey, password);

        const response = await fetch(`${API_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                username: username, 
                password: password,
                public_key: publicKeyPem,
                encrypted_private_key: encryptedPrivateKey
            })
        });
        
        if (response.ok) {
            showMessage("auth-message", "Rejestracja udana! Zaloguj się.");
            const loginTabBtn = document.querySelector('.tab-btn[onclick="showTab(\'login\')"]');
            if(loginTabBtn) loginTabBtn.click();
        } else {
            const errorData = await response.json();
            let errorMsg = "Wystąpił błąd.";
            if (Array.isArray(errorData.detail)) {
                errorMsg = errorData.detail.map(err => err.msg.replace("Value error, ", "")).join(", "); 
            } else if (errorData.detail) {
                errorMsg = errorData.detail;
            }
            showMessage("auth-message", `Błąd: ${errorMsg}`, true);
        }
    } catch (error) {
        handleError("auth-message", error);
    } finally {
        btn.disabled = false;
        btn.innerText = "UTWÓRZ KONTO";
    }
});

document.getElementById("login-btn").addEventListener("click", async (e) => {
    if(e) e.preventDefault();

    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;
    const totp = document.getElementById("login-totp").value;

    const formData = new URLSearchParams();
    formData.append("username", username);
    formData.append("password", password);
    if (totp) formData.append("totp_code", totp);
    
    try {
        const response = await fetch(`${API_URL}/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });
        
        if(response.ok) {
            localStorage.setItem("username", username);
            showMessage("auth-message", "Logowanie udane. Pobieranie kluczy szyfrujących...");

            const keyResponse = await fetch(`${API_URL}/users/me/private_key`);
            if (keyResponse.ok) {
                const keyData = await keyResponse.json();
                try {
                    console.log("Próba odszyfrowania klucza prywatnego...");
                    const privateKey = forge.pki.decryptRsaPrivateKey(keyData.encrypted_private_key, password);
                    const pem = forge.pki.privateKeyToPem(privateKey);
                    sessionStorage.setItem("my_private_key", pem);
                    console.log("Klucz prywatny odzyskany pomyślnie! ✅");
                } catch (e) {
                    console.error("Błąd kryptograficzny:", e);
                    alert("BŁĄD KRYTYCZNY: Nie udało się odszyfrować klucza prywatnego. Czy hasło jest poprawne?");
                }
            }
            checkAuth();
        } else {
            const errorData = await response.json();
            showMessage("auth-message", `Błąd: ${errorData.detail}`, true);
        }
    } catch (error) {
        handleError("auth-message", error);
    }
});

document.getElementById("logout-btn").addEventListener("click", () => {
    localStorage.removeItem("username");
    sessionStorage.removeItem("my_private_key");
    document.cookie = "access_token=; Max-Age=0; path=/;";
    location.reload();
});

document.getElementById("setup-2fa-btn").addEventListener("click", async () => {
    try {
        const response = await fetch(`${API_URL}/2fa/setup`);
        if(response.ok) {
            const blob = await response.blob();
            const imageUrl = URL.createObjectURL(blob);
            document.getElementById("qr-image").src = imageUrl;
            document.getElementById("qr-container").style.display = "inline-block";
        } else {
            const errorData = await response.json();
            alert(`Błąd 2FA: ${errorData.detail}`);
        }
    } catch (error) {
        alert(`Błąd sieci: ${error.message}`);
    }
});

document.getElementById("message-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const recipientUsername = document.getElementById("msg-recipient").value;
    const content = document.getElementById("msg-content").value;
    const fileInput = document.getElementById("msg-file");
    
    const myPem = sessionStorage.getItem("my_private_key");
    if (!myPem) {
        showMessage("msg-status", "Błąd: Brak klucza prywatnego. Zaloguj się ponownie.", true);
        return;
    }

    try {
        showMessage("msg-status", "Pobieranie klucza odbiorcy...");

        const keyRes = await fetch(`${API_URL}/users/${recipientUsername}/public_key`);
        if (!keyRes.ok) throw new Error("Nie znaleziono użytkownika");
        const keyData = await keyRes.json();

        const recipientPublicKey = forge.pki.publicKeyFromPem(keyData.public_key);
        const myPrivateKey = forge.pki.privateKeyFromPem(myPem);

        const aesKey = forge.random.getBytesSync(32);
        const iv = forge.random.getBytesSync(16);

        const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(content, 'utf8'));
        cipher.finish();
        const encryptedContentAES = cipher.output.getBytes();

        const encryptedAesKeyRSA = recipientPublicKey.encrypt(aesKey, 'RSA-OAEP');

        const payload = {
            k: forge.util.encode64(encryptedAesKeyRSA), 
            iv: forge.util.encode64(iv),              
            c: forge.util.encode64(encryptedContentAES) 
        };
        const finalPayloadString = JSON.stringify(payload);

        const md = forge.md.sha256.create();
        md.update(finalPayloadString, 'utf8');
        const signature = forge.util.encode64(myPrivateKey.sign(md));

        const formData = new FormData();
        formData.append("recipient_username", recipientUsername);
        formData.append("encrypted_content", finalPayloadString); 
        formData.append("signature", signature);

        if (fileInput.files.length > 0) {
            formData.append("file", fileInput.files[0]);
        }
        
        const response = await fetch(`${API_URL}/messages`, {
            method: "POST", body: formData
        });

        if(response.ok) {
            showMessage("msg-status", "Wiadomość zaszyfrowana i wysłana bezpiecznie.");
            document.getElementById("message-form").reset();
            switchView('inbox'); 
        } else {
            const errorData = await response.json();
            showMessage("msg-status", `Błąd: ${errorData.detail}`, true);
        }

    } catch (error) {
        handleError("msg-status", error);
    }
});

async function loadMessages() {
    const myPem = sessionStorage.getItem("my_private_key");
    let myPrivateKey = null;
    if (myPem) {
        try {
            myPrivateKey = forge.pki.privateKeyFromPem(myPem);
        } catch(e) { console.error("Błąd parsowania klucza prywatnego", e); }
    }

    try {
        const response = await fetch(`${API_URL}/messages`);
        if(response.ok) {
            const messages = await response.json();
            const messagesList = document.getElementById("messages-list");
            messagesList.innerHTML = "";

            if (messages.length === 0) {
                messagesList.innerHTML = '<p style="text-align:center; color:#666; padding:20px;">Brak wiadomości</p>';
                return;
            }

            messages.forEach(msg => {
                const li = document.createElement("li");
                li.className = "msg-item";

                if (msg.is_read) {
                    li.style.borderLeftColor = "#10b981"; 
                    li.style.opacity = "0.8"; 
                } else {
                    li.style.borderLeftColor = "#ef4444"; 
                    li.style.backgroundColor = "#263042";
                    li.style.boxShadow = "0 4px 6px -1px rgba(239, 68, 68, 0.1)";
                }

                let displayedContent = "<i>Brak klucza prywatnego</i>";
                
                if (myPrivateKey) {
                    try {
                        const payload = JSON.parse(msg.encrypted_content);
                        if (!payload.k || !payload.iv || !payload.c) throw new Error("Format");

                        const encryptedAesKey = forge.util.decode64(payload.k);
                        const aesKey = myPrivateKey.decrypt(encryptedAesKey, 'RSA-OAEP');

                        const iv = forge.util.decode64(payload.iv);
                        const encryptedContent = forge.util.decode64(payload.c);

                        const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
                        decipher.start({iv: iv});
                        decipher.update(forge.util.createBuffer(encryptedContent));
                        
                        if(decipher.finish()) {
                            displayedContent = decipher.output.toString('utf8').replace(/</g, "&lt;").replace(/>/g, "&gt;");
                        } else {
                            displayedContent = "Błąd integralności AES";
                        }
                    } catch (err) {
                        displayedContent = "<i>Wiadomość uszkodzona lub zły klucz</i>";
                    }
                }
                
                let attachmentHtml = "";
                if (msg.attachment_path) {
                    const fileName = msg.attachment_path.split("/").pop();
                    attachmentHtml = `<div style="margin-top: 10px;"><a href="/${msg.attachment_path}" target="_blank" download class="secondary-btn" style="text-decoration: none; font-size: 0.85em; padding: 6px 12px; display: inline-block; color: white;"><i class="fas fa-download"></i> Pobierz: ${fileName}</a></div>`;
                }

                const safeContent = encodeURIComponent(msg.encrypted_content);
                const safeSignature = encodeURIComponent(msg.signature);

                li.innerHTML = `
                    <div class="msg-meta">
                        <span id="msg-sender-${msg.id}"><i class="fas fa-user"></i> ${msg.sender_username}</span>
                        <span>${new Date(msg.created_at).toLocaleString()}</span>
                    </div>
                    <div style="margin-top: 10px; font-size: 1rem; color: #e2e8f0; word-break: break-word;">
                        ${displayedContent}
                        ${attachmentHtml}
                    </div>
                    
                    <div style="margin-top: 15px; display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap;">
                        
                        <button id="btn-verify-${msg.id}" onclick="verifyMessageSignature(${msg.id}, '${msg.sender_username}', '${safeContent}', '${safeSignature}')" 
                                class="secondary-btn" style="width:auto; font-size:0.8em; padding: 5px 10px; border-color: #3b82f6; color: #3b82f6;">
                            <i class="fas fa-shield-check"></i> Weryfikuj
                        </button>

                        ${!msg.is_read ? `
                        <button onclick="markAsRead(${msg.id})" class="secondary-btn" style="width:auto; font-size:0.8em; padding: 5px 10px;">
                            <i class="fas fa-eye"></i> Oznacz jako przeczytane
                        </button>` : '<span style="color:#10b981; font-size:0.8em; align-self:center;"><i class="fas fa-check"></i> Przeczytano</span>'}
                        
                        <button onclick="deleteMessage(${msg.id})" class="secondary-btn" style="width:auto; font-size:0.8em; padding: 5px 10px; border-color: #ef4444; color: #ef4444;">
                            <i class="fas fa-trash"></i> Usuń
                        </button>
                    </div>
                `;
                messagesList.appendChild(li);
            });
        }
    } catch (err) {
        console.error("Błąd pobierania wiadomości", err);
    }
}

document.getElementById("refresh-msgs-btn").addEventListener("click", loadMessages);

globalThis.verifyMessageSignature = async (messageId, senderUsername, encodedContent, encodedSignature) => {
    try {
        const encryptedContent = decodeURIComponent(encodedContent);
        const signatureBase64 = decodeURIComponent(encodedSignature);

        const keyRes = await fetch(`${API_URL}/users/${senderUsername}/public_key`);
        if (!keyRes.ok) {
            alert("Błąd: Nie można pobrać klucza nadawcy.");
            return;
        }
        const keyData = await keyRes.json();
        const senderPublicKey = forge.pki.publicKeyFromPem(keyData.public_key);

        const md = forge.md.sha256.create();
        md.update(encryptedContent, 'utf8');

        const signature = forge.util.decode64(signatureBase64);
        const verified = senderPublicKey.verify(md.digest().bytes(), signature);

        if (verified) {            
            const senderEl = document.getElementById(`msg-sender-${messageId}`);
            if (senderEl) {
                senderEl.innerHTML += ' <i class="fas fa-lock" style="color: #10b981;" title="Zweryfikowany nadawca"></i>';
            }

            const btnEl = document.getElementById(`btn-verify-${messageId}`);
            if (btnEl) {
                btnEl.remove();
            }

        } else {
            alert(`OSTRZEŻENIE\n\nPodpis NIEPRAWIDŁOWY! Wiadomość mogła zostać sfałszowana.`);
        }
    } catch (e) {
        console.error(e);
        alert("Błąd podczas weryfikacji.");
    }
};

globalThis.deleteMessage = async (id) => {
    if(!confirm("Czy na pewno usunąć tę wiadomość?")) return;
    try {
        const res = await fetch(`${API_URL}/messages/${id}`, { method: 'DELETE' });
        if(res.ok) loadMessages();
    } catch(e) { console.error(e); }
};

globalThis.markAsRead = async (id) => {
    try {
        const res = await fetch(`${API_URL}/messages/${id}/read`, { method: 'POST' });
        if(res.ok) loadMessages();
    } catch(e) { console.error(e); }
};

checkAuth();