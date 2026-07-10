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
     * @param email Optional email to directly login with a specific GPG key bypassing the selector
     * @returns The authenticated email address on success
     */
    async login(email) {
        // 1. Check if extension natively provides window.gpgLogin
        if (typeof window.gpgLogin !== "function") {
            this.showInstallDialog();
            throw new Error("GPG Browser Extension is not installed or active.");
        }
        try {
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
            // 3. Request native extension to sign the challenge (passing optional email)
            const loginResult = await window.gpgLogin(challenge, email);
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
        catch (err) {
            const errMsg = err.message || "";
            if (errMsg.includes("No such native application") ||
                errMsg.includes("no_native_host") ||
                errMsg.includes("not_found") ||
                errMsg.includes("not found") ||
                errMsg.includes("disconnected") ||
                errMsg.includes("disconnect") ||
                errMsg.includes("general_error")) {
                this.showInstallDialog(true);
            }
            throw err;
        }
    }
    /**
     * Detects user's operating system to show targeted installation commands.
     */
    getOSInfo() {
        const userAgent = navigator.userAgent.toLowerCase();
        if (userAgent.indexOf("win") !== -1) {
            return {
                name: "Windows",
                link: "https://github.com/AegisHttp/native-host-rust/releases/latest"
            };
        }
        if (userAgent.indexOf("mac") !== -1) {
            return {
                name: "macOS",
                cmd: "brew tap AegisHttp/tap && brew install aegis-host"
            };
        }
        if (userAgent.indexOf("linux") !== -1) {
            if (userAgent.indexOf("ubuntu") !== -1) {
                return {
                    name: "Ubuntu",
                    cmd: "sudo snap install aegis-host"
                };
            }
            if (userAgent.indexOf("debian") !== -1) {
                return {
                    name: "Debian",
                    cmd: "sudo add-apt-repository ppa:aegis-http/ppa && sudo apt update && sudo apt install aegis-host"
                };
            }
            return {
                name: "Linux",
                cmd: "sudo snap install aegis-host"
            };
        }
        return {
            name: "detected platform"
        };
    }
    /**
     * Displays a dialog prompting the user to install the browser extension and native host daemon.
     */
    showInstallDialog(extensionInstalled = false) {
        const osInfo = this.getOSInfo();
        const overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100vw";
        overlay.style.height = "100vh";
        overlay.style.backgroundColor = "rgba(15, 23, 42, 0.75)";
        overlay.style.backdropFilter = "blur(4px)";
        overlay.style.zIndex = "999999";
        overlay.style.display = "flex";
        overlay.style.alignItems = "center";
        overlay.style.justifyContent = "center";
        overlay.style.fontFamily = "system-ui, -apple-system, sans-serif";
        const modal = document.createElement("div");
        modal.style.backgroundColor = "#1e293b";
        modal.style.color = "#f8fafc";
        modal.style.padding = "30px";
        modal.style.borderRadius = "12px";
        modal.style.maxWidth = "460px";
        modal.style.width = "90%";
        modal.style.boxShadow = "0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.4)";
        modal.style.border = "1px solid #334155";
        const title = document.createElement("h3");
        title.innerText = "🛡️ Aegis HTTP Gateway Required";
        title.style.margin = "0 0 10px";
        title.style.fontSize = "1.25rem";
        title.style.fontWeight = "600";
        const desc = document.createElement("p");
        desc.innerText = extensionInstalled
            ? "To authenticate using E2E GPG keys, you need to install the local native daemon (aegis-host)."
            : "To authenticate using E2E GPG keys, you need to install both the browser extension and the local native daemon.";
        desc.style.color = "#94a3b8";
        desc.style.fontSize = "0.9rem";
        desc.style.lineHeight = "1.5";
        desc.style.margin = "0 0 20px";
        // Step 1: Extension
        const step1Title = document.createElement("div");
        step1Title.innerHTML = "<strong>Step 1:</strong> Install Browser Extension";
        step1Title.style.fontSize = "0.95rem";
        step1Title.style.marginBottom = "8px";
        const userAgent = navigator.userAgent.toLowerCase();
        const isFirefox = userAgent.indexOf("firefox") !== -1;
        const extLink = document.createElement("a");
        extLink.href = isFirefox
            ? "https://github.com/AegisHttp/firefox-extension"
            : "https://chromewebstore.google.com/detail/lappbcambkogfmigiphapgjcglafcfnd";
        extLink.target = "_blank";
        extLink.style.display = "inline-flex";
        extLink.style.alignItems = "center";
        extLink.style.gap = "8px";
        extLink.style.padding = "10px 16px";
        extLink.style.background = "#0284c7";
        extLink.style.color = "white";
        extLink.style.textDecoration = "none";
        extLink.style.borderRadius = "6px";
        extLink.style.fontSize = "0.85rem";
        extLink.style.fontWeight = "500";
        extLink.style.marginBottom = "20px";
        extLink.innerText = isFirefox ? "Add to Firefox" : "Add to Chrome";
        // Step 2: Native Daemon
        const step2Title = document.createElement("div");
        step2Title.innerHTML = extensionInstalled
            ? "<strong>Install Local Native Daemon (aegis-host)</strong>"
            : "<strong>Step 2:</strong> Install Local Native Daemon (aegis-host)";
        step2Title.style.fontSize = "0.95rem";
        step2Title.style.marginBottom = "10px";
        // Dropdown to select OS
        const osSelect = document.createElement("select");
        osSelect.style.width = "100%";
        osSelect.style.padding = "8px 12px";
        osSelect.style.background = "#0f172a";
        osSelect.style.color = "#f8fafc";
        osSelect.style.border = "1px solid #334155";
        osSelect.style.borderRadius = "6px";
        osSelect.style.fontSize = "0.85rem";
        osSelect.style.marginBottom = "12px";
        osSelect.style.outline = "none";
        const options = [
            { text: "Ubuntu (Snap)", value: "ubuntu" },
            { text: "Debian (PPA)", value: "debian" },
            { text: "macOS (Homebrew)", value: "macos" },
            { text: "Windows (Installer)", value: "windows" }
        ];
        options.forEach(opt => {
            const el = document.createElement("option");
            el.text = opt.text;
            el.value = opt.value;
            osSelect.add(el);
        });
        // Set default value based on detection
        let defaultVal = "ubuntu";
        if (osInfo.name === "Windows")
            defaultVal = "windows";
        else if (osInfo.name === "macOS")
            defaultVal = "macos";
        else if (osInfo.name === "Debian")
            defaultVal = "debian";
        osSelect.value = defaultVal;
        // Command / Download container
        const cmdContainer = document.createElement("div");
        cmdContainer.style.background = "#0f172a";
        cmdContainer.style.padding = "12px";
        cmdContainer.style.borderRadius = "6px";
        cmdContainer.style.border = "1px solid #334155";
        cmdContainer.style.marginBottom = "25px";
        cmdContainer.style.position = "relative";
        const updateContent = (os) => {
            cmdContainer.innerHTML = "";
            if (os === "windows") {
                const winDesc = document.createElement("div");
                winDesc.innerText = "Download and run the Windows NSIS Setup installer:";
                winDesc.style.fontSize = "0.8rem";
                winDesc.style.color = "#94a3b8";
                winDesc.style.marginBottom = "8px";
                const winLink = document.createElement("a");
                winLink.href = "https://github.com/AegisHttp/native-host-rust/releases/latest";
                winLink.target = "_blank";
                winLink.innerText = "📥 Download aegis-host-installer.exe";
                winLink.style.display = "inline-block";
                winLink.style.color = "#38bdf8";
                winLink.style.fontSize = "0.85rem";
                winLink.style.fontWeight = "500";
                winLink.style.textDecoration = "none";
                cmdContainer.appendChild(winDesc);
                cmdContainer.appendChild(winLink);
            }
            else {
                let command = "";
                if (os === "ubuntu") {
                    command = "sudo snap install aegis-host";
                }
                else if (os === "debian") {
                    command = "sudo add-apt-repository ppa:aegis-http/ppa && sudo apt update && sudo apt install aegis-host";
                }
                else if (os === "macos") {
                    command = "brew tap AegisHttp/tap && brew install aegis-host";
                }
                const code = document.createElement("code");
                code.innerText = command;
                code.style.fontFamily = "monospace";
                code.style.fontSize = "0.8rem";
                code.style.color = "#38bdf8";
                code.style.wordBreak = "break-all";
                code.style.display = "block";
                code.style.paddingRight = "80px";
                const copyBtn = document.createElement("button");
                copyBtn.innerText = "📋 Copy";
                copyBtn.style.position = "absolute";
                copyBtn.style.right = "8px";
                copyBtn.style.top = "50%";
                copyBtn.style.transform = "translateY(-50%)";
                copyBtn.style.width = "auto";
                copyBtn.style.marginTop = "0";
                copyBtn.style.background = "#334155";
                copyBtn.style.color = "white";
                copyBtn.style.border = "none";
                copyBtn.style.padding = "6px 10px";
                copyBtn.style.borderRadius = "4px";
                copyBtn.style.fontSize = "0.75rem";
                copyBtn.style.cursor = "pointer";
                copyBtn.onclick = () => {
                    navigator.clipboard.writeText(command);
                    copyBtn.innerText = "Copied!";
                    setTimeout(() => copyBtn.innerText = "📋 Copy", 2000);
                };
                cmdContainer.appendChild(code);
                cmdContainer.appendChild(copyBtn);
            }
        };
        osSelect.onchange = (e) => {
            updateContent(e.target.value);
        };
        // Initialize content
        updateContent(defaultVal);
        // Actions
        const footer = document.createElement("div");
        footer.style.display = "flex";
        footer.style.justifyContent = "flex-end";
        const closeBtn = document.createElement("button");
        closeBtn.innerText = "Close";
        closeBtn.style.padding = "8px 16px";
        closeBtn.style.background = "transparent";
        closeBtn.style.color = "#94a3b8";
        closeBtn.style.border = "1px solid #334155";
        closeBtn.style.borderRadius = "6px";
        closeBtn.style.fontSize = "0.85rem";
        closeBtn.style.cursor = "pointer";
        closeBtn.onclick = () => document.body.removeChild(overlay);
        footer.appendChild(closeBtn);
        modal.appendChild(title);
        modal.appendChild(desc);
        if (!extensionInstalled) {
            modal.appendChild(step1Title);
            modal.appendChild(extLink);
        }
        modal.appendChild(step2Title);
        modal.appendChild(osSelect);
        modal.appendChild(cmdContainer);
        modal.appendChild(footer);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
    }
}
// Bind to window.aegis to be used by any script globally
window.aegis = new AegisHttpSDK();
export {};
//# sourceMappingURL=index.js.map