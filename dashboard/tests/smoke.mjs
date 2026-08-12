/**
 * Test de rendu de la console SOC dans un vrai navigateur.
 *
 * Le build Vite ne détecte pas les erreurs de rendu : un composant absent, une
 * propriété lue sur `undefined` ou un contrat d'API mal interprété ne se voient
 * qu'à l'exécution. Ce script ouvre chaque onglet dans Chromium, échoue sur la
 * moindre erreur console, et enregistre une capture de la vue d'ensemble.
 *
 *   node tests/smoke.mjs                          # dev, port 5173
 *   node tests/smoke.mjs --origin http://srv:8080 # production nginx
 *
 * Le compte utilisé est créé au préalable par `python -m scripts.ui_check --keep`
 * ou passé explicitement via --email / --password.
 */

import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index !== -1 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const ORIGIN = arg('origin', 'http://localhost:5173').replace(/\/$/, '');
const EMAIL = arg('email', 'ui-check@soc.edr.local');
const PASSWORD = arg('password', 'UiCheck!2026#Soc');
const SHOTS = resolve(arg('shots', 'tests/screenshots'));

// Bruit connu, sans rapport avec un défaut de l'application.
const IGNORED = [
  /Download the React DevTools/i,
  /\[vite\] connect(ing|ed)/i,
  /favicon/i,
  // React StrictMode monte, démonte puis remonte chaque composant en
  // développement : le premier WebSocket est fermé pendant sa négociation.
  /WebSocket is closed before the connection is established/i,
];

const TABS = [
  { label: "Vue d'ensemble", nav: 'Dashboard', expect: 'Score de risque du parc' },
  { label: 'Terminaux', nav: 'Terminaux', expect: 'Terminaux' },
  { label: 'Alertes', nav: 'Alertes de sécurité', expect: 'alerte' },
  { label: 'Réponses', nav: 'Journal des réponses', expect: 'réponses actives' },
  { label: 'Moteur ML', nav: 'Statistiques ML', expect: 'modèle' },
  { label: 'Règles', nav: 'Moteur heuristique', expect: 'Règles comportementales' },
  { label: 'Exclusions', nav: "Règles d'exclusion", expect: 'exclusion' },
  { label: 'Audit', nav: "Journal d'audit", expect: 'audit' },
  { label: 'Équipe', nav: 'Équipe SOC', expect: 'Équipe' },
  { label: 'Configuration', nav: 'Configuration', expect: 'Moteur de détection' },
  { label: 'Documentation', nav: 'Documentation', expect: 'Chaîne de traitement' },
];

const failures = [];
const consoleErrors = [];

// Avant la connexion, l'application interroge /auth/me pour savoir si une
// session existe : le 401 attendu est journalisé par le navigateur. Après
// authentification, en revanche, un 401 signale un vrai problème.
let authenticated = false;

function check(label, condition, detail = '') {
  const mark = condition ? '[OK]' : '[KO]';
  console.log(`  ${mark} ${label}${detail ? ` — ${detail}` : ''}`);
  if (!condition) failures.push(label);
}

function section(title) {
  console.log(`\n${title}\n${'-'.repeat(title.length)}`);
}

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
const page = await context.newPage();

page.on('console', (message) => {
  if (message.type() !== 'error' && message.type() !== 'warning') return;
  const text = message.text();
  if (IGNORED.some((pattern) => pattern.test(text))) return;
  if (!authenticated && /status of 401/.test(text)) return;
  consoleErrors.push(`[${message.type()}] ${text}`);
});
page.on('pageerror', (error) => consoleErrors.push(`[pageerror] ${error.message}`));

try {
  mkdirSync(SHOTS, { recursive: true });

  console.log('='.repeat(74));
  console.log(`  RENDU DE LA CONSOLE SOC DANS CHROMIUM — ${ORIGIN}`);
  console.log('='.repeat(74));

  section('1. Écran de connexion');

  await page.goto(ORIGIN, { waitUntil: 'networkidle' });
  const submit = page.getByRole('button', { name: /ouvrir la session/i });
  check("L'application se charge", await submit.isVisible());

  // La console SOC n'est pas un service en libre-service : aucune inscription
  // ni choix de rôle ne doit être proposé à un visiteur non authentifié.
  const body = (await page.textContent('body')).toLowerCase();
  check(
    "Aucune inscription libre n'est proposée",
    !body.includes('créer un compte') && !body.includes('inscription'),
    'la création de compte est réservée au SOC Manager',
  );

  await page.screenshot({ path: `${SHOTS}/01-connexion.png` });

  section('2. Authentification');

  await page.getByLabel(/adresse professionnelle/i).fill(EMAIL);
  await page.getByLabel(/mot de passe/i).fill(PASSWORD);
  await submit.click();
  await page.waitForSelector("text=Vue d'ensemble du SOC", { timeout: 20000 });
  authenticated = true;
  check('Connexion réussie et console affichée', true, EMAIL);

  // Le cookie de session doit rester invisible du JavaScript : c'est ce qui
  // empêche un XSS de voler la session d'un analyste.
  const visibleCookies = await page.evaluate(() => document.cookie);
  check(
    'Le cookie de session est inaccessible au JavaScript',
    !visibleCookies.includes('edr_session'),
    visibleCookies ? `document.cookie = "${visibleCookies}"` : 'document.cookie vide',
  );

  await page.waitForTimeout(1500);
  const realtime = await page.textContent('header');
  check(
    'Le canal temps réel est actif',
    /Temps réel actif/.test(realtime),
    realtime.includes('dégradé') ? 'mode dégradé signalé' : 'WebSocket connecté',
  );

  await page.screenshot({ path: `${SHOTS}/02-vue-ensemble.png`, fullPage: true });

  section('3. Chaque onglet se rend sans erreur');

  for (const tab of TABS) {
    await page.getByRole('button', { name: tab.nav, exact: false }).first().click();
    await page.waitForTimeout(900);

    const content = await page.textContent('main');
    const rendered = new RegExp(tab.expect, 'i').test(content);
    const broken = /Impossible de charger|Erreur 5\d\d|Liaison avec l'API/.test(content);

    check(
      `Onglet « ${tab.label} »`,
      rendered && !broken,
      broken ? 'état d\'erreur affiché' : '',
    );

    await page.screenshot({
      path: `${SHOTS}/03-${tab.label.toLowerCase().replace(/[^a-z]+/g, '-')}.png`,
      fullPage: true,
    });
  }

  section('4. Cohérence des chiffres entre deux analystes');

  // Deux onglets navigateur distincts doivent afficher le même score : c'est
  // l'exigence de départ, et elle ne tient que si la valeur vient du serveur.
  await page.getByRole('button', { name: 'Dashboard' }).first().click();
  await page.waitForTimeout(1200);
  const firstScore = await page.textContent('main');

  const second = await context.newPage();
  await second.goto(ORIGIN, { waitUntil: 'networkidle' });
  await second.waitForTimeout(1800);
  const secondScore = await second.textContent('main');

  const extract = (text) => (text.match(/(\d+)\s*\/100/) || [])[1];
  check(
    'Deux sessions affichent le même score de risque',
    extract(firstScore) !== undefined && extract(firstScore) === extract(secondScore),
    `${extract(firstScore)}/100 dans les deux onglets`,
  );
  await second.close();

  section('5. Journal de la console navigateur');

  check(
    'Aucune erreur JavaScript pendant le parcours',
    consoleErrors.length === 0,
    consoleErrors.length ? `${consoleErrors.length} message(s)` : 'console propre',
  );
  consoleErrors.slice(0, 12).forEach((error) => console.log(`       ${error}`));
} catch (error) {
  check('Parcours complet', false, error.message.split('\n')[0]);
  await page.screenshot({ path: `${SHOTS}/99-echec.png`, fullPage: true }).catch(() => {});
} finally {
  await browser.close();
}

console.log(`\n${'='.repeat(74)}`);
if (failures.length) {
  console.log(`  ${failures.length} CONTRÔLE(S) EN ÉCHEC`);
  failures.forEach((failure) => console.log(`    - ${failure}`));
  console.log(`  Captures : ${SHOTS}`);
  console.log('='.repeat(74));
  process.exit(1);
}
console.log('  TOUS LES CONTRÔLES PASSENT');
console.log(`  Captures : ${SHOTS}`);
console.log('='.repeat(74));
