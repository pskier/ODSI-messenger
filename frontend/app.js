const API_URL = "http://localhost:8080";

function showMessage(elementId, text, isError = false) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerText = text;
    el.className = isError ? "message error" : "message success";
    setTimeout(() => { el.innerText = ""; }, 5000);
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
    } 
    else if (viewName === 'compose') {
        document.getElementById("view-compose").style.display = "flex";
        document.getElementById("nav-compose").classList.add("active");
    } 
    else if (viewName === '2fa') {
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

document.getElementById("register-btn").addEventListener("click", async () => {
    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;
    const btn = document.getElementById("register-btn");
    
    if (!username || !password) {
        showMessage("auth-message", "Podaj login i hasło!", true);
        return;
    }

    btn.disabled = true;
    btn.innerText = "Generowanie kluczy...";
    showMessage("auth-message", "Trwa generowanie kluczy RSA...");

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
            showTab('login');
        } else {
            const errorData = await response.json();
            showMessage("auth-message", `Błąd: ${errorData.detail}`, true);
        }

    } catch (error) {
        console.error(error);
        showMessage("auth-message", `Błąd: ${error.message}`, true);
    } finally {
        btn.disabled = false;
        btn.innerText = "UTWÓRZ KONTO";
    }
});

document.getElementById("login-btn").addEventListener("click", async () => {
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
            checkAuth();
        } else {
            const errorData = await response.json();
            showMessage("auth-message", `Błąd: ${errorData.detail}`, true);
        }
    } catch (error) {
        showMessage("auth-message", `Błąd połączenia`, true);
    }
});

document.getElementById("logout-btn").addEventListener("click", () => {
    localStorage.removeItem("username");
    document.cookie = "access_token=; Max-Age=0; path=/;";
    location.reload();
});

document.getElementById("setup-2fa-btn").addEventListener("click", async () => {
    try {
        const response = await fetch(`${API_URL}/2fa/setup`);
        if(response.ok) {
            const blob = await response.blob();
            const imageUrl = URL.createObjectURL(blob);
            
            const imgEl = document.getElementById("qr-image"); 
            imgEl.src = imageUrl;
            
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
    const recipient = document.getElementById("msg-recipient").value;
    const content = document.getElementById("msg-content").value;
    const signature = document.getElementById("msg-signature").value;
    const fileInput = document.getElementById("msg-file");

    const formData = new FormData();
    formData.append("recipient_username", recipient);
    formData.append("encrypted_content", content);
    formData.append("signature", signature);

    if (fileInput.files.length > 0) {
        formData.append("file", fileInput.files[0]);
    }
    
    try {
        const response = await fetch(`${API_URL}/messages`, {
            method: "POST", body: formData
        });

        if(response.ok) {
            showMessage("msg-status", "Wiadomość wysłana.");
            document.getElementById("message-form").reset();
        } else {
            const errorData = await response.json();
            showMessage("msg-status", `Błąd: ${errorData.detail}`, true);
        }
    } catch (error) {
        showMessage("msg-status", "Błąd wysyłania", true);
    }
});

async function loadMessages() {
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

                let attachmentHtml = "";
                if (msg.attachment_path) {
                    const fileName = msg.attachment_path.split("/").pop();
                    attachmentHtml = `
                        <div style="margin-top: 10px;">
                            <a href="/${msg.attachment_path}" target="_blank" download class="secondary-btn" style="text-decoration: none; font-size: 0.85em; padding: 6px 12px; display: inline-block; color: white; border-color: #555;">
                                <i class="fas fa-download"></i> Pobierz: ${fileName}
                            </a>
                        </div>
                    `;
                }
                
                li.innerHTML = `
                    <div class="msg-meta">
                        <span><i class="fas fa-user"></i> ${msg.sender_username}</span>
                        <span>${new Date(msg.created_at).toLocaleString()}</span>
                    </div>
                    <div style="margin-top: 5px; font-size: 1rem;">
                        ${msg.encrypted_content}
                        ${attachmentHtml}
                    </div>
                    <small style="color: #64748b; display:block; margin-top:8px;">Podpis: ${msg.signature}</small>
                `;
                messagesList.appendChild(li);
            });
        }
    } catch (err) {
        console.error("Błąd pobierania", err);
    }
}

document.getElementById("refresh-msgs-btn").addEventListener("click", loadMessages);

checkAuth();