class AegisHttpSDK {
    initialized = false;
    config = {
        challengeUrl: "/api/challenge",
        loginUrl: "/api/login",
    };
    /**
     * Initializes the SDK with custom configuration or force tunneling mode.
     */
    init(config) {
        this.initialized = true;
        this.config = { ...this.config, ...config };
        if (this.config.forceTunneling) {
            let tunnelMeta = document.querySelector('meta[name="gpg-tunnel"]');
            if (!tunnelMeta) {
                tunnelMeta = document.createElement('meta');
                tunnelMeta.setAttribute('name', 'gpg-tunnel');
                tunnelMeta.setAttribute('content', 'true');
                document.head.appendChild(tunnelMeta);
            }
        }
        // Ensure gpg-auto meta tag is present if not already, to let extension know
        let meta = document.querySelector('meta[name="gpg-auto"]');
        if (!meta) {
            meta = document.createElement('meta');
            meta.setAttribute('name', 'gpg-auto');
            meta.setAttribute('content', 'true');
            document.head.appendChild(meta);
        }
    }
    /**
     * Initiates the login process using Aegis Http GPG Extension.
     * @returns The authenticated email address on success
     */
    async login() {
        // 1. Check if extension natively provides window.gpgLogin
        if (typeof window.gpgLogin !== "function") {
            this.showInstallDialog();
            throw new Error("GPG Browser Extension is not installed or active.");
        }
        // 2. Fetch challenge
        const challengeRes = await fetch(this.config.challengeUrl);
        if (!challengeRes.ok) {
            throw new Error("Failed to get challenge from backend at " + this.config.challengeUrl);
        }
        if (challengeRes.headers.get("x-gpg-support") !== "true") {
            throw new Error("Server does restricted GPG login (x-gpg-support header missing)");
        }
        const data = await challengeRes.json();
        const challenge = data.challenge;
        // 3. Request native extension to sign the challenge
        const loginResult = await window.gpgLogin(challenge);
        // 4. Send the signed payload back to backend
        const loginRes = await fetch(this.config.loginUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                email: loginResult.email,
                challenge: challenge,
                signature: loginResult.signature,
                public_key: loginResult.public_key,
            }),
        });
        const loginData = await loginRes.json();
        if (!loginRes.ok) {
            throw new Error(loginData.error || "Login failed on backend verification");
        }
        // Emit an empty GET to help the extension register server-id securely
        try {
            await fetch(this.config.challengeUrl, { headers: { "x-gpg-id": loginData.email } });
        }
        catch (e) { }
        return loginData.email;
    }
    /**
     * Displays a dialog prompting the user to install the browser extension.
     */
    showInstallDialog() {
        const overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100vw";
        overlay.style.height = "100vh";
        overlay.style.backgroundColor = "rgba(0, 0, 0, 0.6)";
        overlay.style.zIndex = "999999";
        overlay.style.display = "flex";
        overlay.style.alignItems = "center";
        overlay.style.justifyContent = "center";
        overlay.style.fontFamily = "sans-serif";
        const modal = document.createElement("div");
        modal.style.backgroundColor = "white";
        modal.style.padding = "30px";
        modal.style.borderRadius = "8px";
        modal.style.maxWidth = "400px";
        modal.style.textAlign = "center";
        modal.style.boxShadow = "0 10px 25px rgba(0,0,0,0.2)";
        const title = document.createElement("h2");
        title.innerText = "Aegis Http Extension Required";
        title.style.margin = "0 0 15px";
        title.style.color = "#333";
        const text = document.createElement("p");
        text.innerText = "To authenticate using Zero Trust GPG, you must install the Aegis Http Browser Extension for Chrome or Firefox.";
        text.style.color = "#666";
        text.style.lineHeight = "1.5";
        text.style.marginBottom = "20px";
        const actionContainer = document.createElement("div");
        actionContainer.style.display = "flex";
        actionContainer.style.gap = "10px";
        actionContainer.style.justifyContent = "center";
        const closeBtn = document.createElement("button");
        closeBtn.innerText = "Close";
        closeBtn.style.padding = "10px 20px";
        closeBtn.style.border = "none";
        closeBtn.style.borderRadius = "4px";
        closeBtn.style.background = "#ddd";
        closeBtn.style.cursor = "pointer";
        closeBtn.onclick = () => document.body.removeChild(overlay);
        const installBtn = document.createElement("a");
        installBtn.innerText = "Install Extension";
        installBtn.href = "https://github.com/AegisHttp/chrome-extension"; // Replace with your actual webstore URL later
        installBtn.target = "_blank";
        installBtn.style.padding = "10px 20px";
        installBtn.style.border = "none";
        installBtn.style.borderRadius = "4px";
        installBtn.style.background = "#007bff";
        installBtn.style.color = "white";
        installBtn.style.textDecoration = "none";
        installBtn.style.cursor = "pointer";
        actionContainer.appendChild(closeBtn);
        actionContainer.appendChild(installBtn);
        modal.appendChild(title);
        modal.appendChild(text);
        modal.appendChild(actionContainer);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
    }
}
// Bind to window.aegis to be used by any script globally
window.aegis = new AegisHttpSDK();
export {};
//# sourceMappingURL=index.js.map