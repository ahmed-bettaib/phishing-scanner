/**
 * scanner.js
 * ----------
 * Gère l'interaction côté client :
 *  - envoi de l'URL au backend via fetch (AJAX)
 *  - animation de la jauge de risque en fonction du score reçu
 *  - affichage des raisons du score et de l'historique
 */

const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const errorMsg = document.getElementById("error-msg");
const resultPanel = document.getElementById("result-panel");
const gaugeFill = document.getElementById("gauge-fill");
const scoreValue = document.getElementById("score-value");
const riskBadge = document.getElementById("risk-badge");
const scannedDomain = document.getElementById("scanned-domain");
const reasonsList = document.getElementById("reasons-list");
const historyList = document.getElementById("history-list");

const GAUGE_CIRCUMFERENCE = 283; // longueur du demi-cercle SVG (rayon 90)

const RISK_COLORS = {
    low: "#00e5a0",
    medium: "#ffb84d",
    high: "#ff4d5e",
};

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();

    if (!url) return;

    errorMsg.textContent = "";
    scanBtn.disabled = true;
    scanBtn.textContent = "Analyse...";

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        const data = await response.json();

        if (!response.ok) {
            errorMsg.textContent = data.error || "Erreur lors de l'analyse";
            return;
        }

        renderResult(data);
        loadHistory();
    } catch (err) {
        errorMsg.textContent = "Impossible de contacter le serveur.";
        console.error(err);
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Analyser";
    }
});

function renderResult(data) {
    resultPanel.classList.remove("hidden");

    // Animation de la jauge : on calcule l'offset en fonction du score (0-100)
    const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * data.score) / 100;
    const color = RISK_COLORS[data.risk_level] || RISK_COLORS.low;

    // Reset pour permettre de rejouer l'animation à chaque scan
    gaugeFill.style.transition = "none";
    gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
    gaugeFill.style.stroke = color;

    requestAnimationFrame(() => {
        gaugeFill.style.transition = "stroke-dashoffset 1s cubic-bezier(0.65,0,0.35,1)";
        gaugeFill.style.strokeDashoffset = offset;
    });

    animateScoreCounter(data.score);

    riskBadge.textContent =
        data.risk_level === "high" ? "Risque élevé" :
        data.risk_level === "medium" ? "Risque moyen" : "Risque faible";
    riskBadge.className = `risk-badge ${data.risk_level}`;

    scannedDomain.textContent = data.domain;

    reasonsList.innerHTML = "";
    data.reasons.forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsList.appendChild(li);
    });
}

function animateScoreCounter(target) {
    let current = 0;
    const step = Math.max(1, Math.round(target / 30));
    const interval = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(interval);
        }
        scoreValue.textContent = current;
    }, 20);
}

async function loadHistory() {
    try {
        const response = await fetch("/history");
        const items = await response.json();
        renderHistory(items);
    } catch (err) {
        console.error("Erreur de chargement de l'historique", err);
    }
}

function renderHistory(items) {
    historyList.innerHTML = "";

    if (items.length === 0) {
        historyList.innerHTML = '<p style="color:#7d8b9a; font-size:13px;">Aucun scan pour le moment.</p>';
        return;
    }

    items.forEach((item) => {
        const row = document.createElement("div");
        row.className = "history-item";

        const url = document.createElement("span");
        url.className = "history-url";
        url.textContent = item.url;

        const score = document.createElement("span");
        score.className = "history-score";
        score.textContent = `${item.score}/100`;
        score.style.background = `${RISK_COLORS[item.risk_level]}22`;
        score.style.color = RISK_COLORS[item.risk_level];

        row.appendChild(url);
        row.appendChild(score);
        historyList.appendChild(row);
    });
}

// Chargement de l'historique au démarrage
loadHistory();
