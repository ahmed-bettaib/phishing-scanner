/**
 * logs.js
 * -------
 * Gère la page d'analyse de logs : chargement de l'exemple,
 * envoi du texte au backend, affichage des incidents détectés
 * et de l'historique des alertes envoyées.
 */

const logInput = document.getElementById("log-input");
const thresholdInput = document.getElementById("threshold");
const windowInput = document.getElementById("window");
const loadSampleBtn = document.getElementById("load-sample-btn");
const analyzeBtn = document.getElementById("analyze-log-btn");
const logError = document.getElementById("log-error");
const resultPanel = document.getElementById("log-result-panel");
const logSummary = document.getElementById("log-summary");
const incidentsList = document.getElementById("incidents-list");
const alertsList = document.getElementById("alerts-list");

loadSampleBtn.addEventListener("click", async () => {
    try {
        const res = await fetch("/logs/sample");
        const data = await res.json();
        logInput.value = data.content;
    } catch (err) {
        logError.textContent = "Impossible de charger l'exemple.";
    }
});

analyzeBtn.addEventListener("click", async () => {
    const logText = logInput.value.trim();
    logError.textContent = "";

    if (!logText) {
        logError.textContent = "Colle du contenu de log ou charge l'exemple d'abord.";
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyse...";

    try {
        const res = await fetch("/logs/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                log_text: logText,
                threshold: parseInt(thresholdInput.value, 10),
                window_seconds: parseInt(windowInput.value, 10),
            }),
        });

        const data = await res.json();

        if (!res.ok) {
            logError.textContent = data.error || "Erreur lors de l'analyse";
            return;
        }

        renderReport(data);
        loadAlerts();
    } catch (err) {
        logError.textContent = "Impossible de contacter le serveur.";
        console.error(err);
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyser";
    }
});

function renderReport(data) {
    resultPanel.classList.remove("hidden");

    logSummary.textContent =
        `${data.total_lines} lignes analysées, ${data.failed_login_events} echecs de connexion trouvés, ` +
        `${data.incidents.length} incident(s) détecté(s) (seuil: ${data.threshold_used} tentatives / ${data.window_seconds_used}s)`;

    incidentsList.innerHTML = "";

    if (data.incidents.length === 0) {
        incidentsList.innerHTML = '<p style="color:#7d8b9a; font-size:13px;">Aucun incident détecté.</p>';
        return;
    }

    data.incidents.forEach((incident) => {
        const card = document.createElement("div");
        card.className = "incident-card";
        card.innerHTML = `
            <div class="incident-header">
                <span class="incident-ip">${incident.ip}</span>
                <span class="incident-badge">${incident.attempts} tentatives</span>
            </div>
            <p class="incident-detail">Comptes ciblés : ${incident.users_targeted.join(", ")}</p>
            <p class="incident-detail">Première tentative : ${incident.first_attempt}</p>
            <p class="incident-detail">Dernière tentative : ${incident.last_attempt}</p>
        `;
        incidentsList.appendChild(card);
    });
}

async function loadAlerts() {
    try {
        const res = await fetch("/alerts");
        const alerts = await res.json();
        renderAlerts(alerts);
    } catch (err) {
        console.error("Erreur de chargement des alertes", err);
    }
}

function renderAlerts(alerts) {
    alertsList.innerHTML = "";

    if (alerts.length === 0) {
        alertsList.innerHTML = '<p style="color:#7d8b9a; font-size:13px;">Aucune alerte envoyée pour le moment.</p>';
        return;
    }

    alerts.forEach((alert) => {
        const row = document.createElement("div");
        row.className = "history-item";

        const subject = document.createElement("span");
        subject.className = "history-url";
        subject.textContent = alert.subject;

        const status = document.createElement("span");
        status.className = "history-score";
        const statusLabel = alert.status === "sent" ? "Envoyée" :
            alert.status === "dry_run" ? "Simulée" : "Échec";
        status.textContent = statusLabel;
        status.style.background = alert.status === "sent" ? "#00e5a022" : "#ffb84d22";
        status.style.color = alert.status === "sent" ? "#00e5a0" : "#ffb84d";

        row.appendChild(subject);
        row.appendChild(status);
        alertsList.appendChild(row);
    });
}

loadAlerts();
