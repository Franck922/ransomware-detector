/**
 * Documentation du moteur heuristique.
 *
 * Les règles décrites ici correspondent exactement à celles implémentées dans
 * detector/rules_engine.py. L'ancien onglet proposait des curseurs qui
 * n'écrivaient nulle part ; les seuils réellement appliqués sont dans l'onglet
 * Configuration et dans le fichier .env.
 */

import { List } from 'lucide-react';
import { settings as settingsApi } from '../api/endpoints';
import { useResource } from '../hooks/useResource';
import { Panel, StatCard } from '../components/ui';

const RULES = [
  {
    id: 1,
    name: 'Création massive de fichiers',
    points: 30,
    condition: 'Plus de 30 fichiers créés sur 10 s ET Z-score > 3 par rapport à la baseline',
    rationale:
      "Un chiffrement de masse produit un fichier par document traité. Le Z-score évite de sanctionner un poste dont l'activité fichier normale est déjà élevée.",
  },
  {
    id: 2,
    name: 'Suppression massive de fichiers',
    points: 30,
    condition: 'Plus de 30 fichiers supprimés sur 10 s ET Z-score > 3',
    rationale:
      "Les rançongiciels suppriment les originaux après chiffrement, et effacent les clichés instantanés pour empêcher la restauration.",
  },
  {
    id: 3,
    name: 'Entropie des noms de fichiers',
    points: 40,
    condition: 'Au moins un fichier créé ET entropie de Shannon > 5.0',
    rationale:
      "Un nom généré aléatoirement atteint 5,5 bits/caractère, contre 3,0 à 3,5 pour un nom métier comme rapport_2026.docx. C'est le signal le plus discriminant, d'où la pondération la plus forte.",
  },
  {
    id: 4,
    name: 'Processus enfant suspect',
    points: 20,
    condition: 'Au moins un processus enfant créé pendant une activité fichier soutenue',
    rationale:
      "Motif classique : le binaire malveillant lance vssadmin ou bcdedit pour saboter les sauvegardes pendant qu'il chiffre.",
  },
  {
    id: 5,
    name: 'Connexion réseau concomitante',
    points: 10,
    condition: 'Au moins une connexion réseau pendant une activité fichier soutenue',
    rationale:
      "Exfiltration avant chiffrement ou contact du serveur de commande et contrôle pour récupérer la clé.",
  },
];

export default function Rules() {
  const totalPoints = RULES.reduce((total, rule) => total + rule.points, 0);

  // Les seuils réellement appliqués sont lus côté serveur : les afficher en dur
  // reviendrait à documenter une configuration qui n'est peut-être plus celle du
  // moteur.
  const { data } = useResource((signal) => settingsApi.list(signal), { channels: [] });
  const detection = (data || []).find((entry) => entry.key === 'detection')?.value;
  const alertScore =
    detection?.rules_alert_threshold !== undefined
      ? Math.round(detection.rules_alert_threshold * 100)
      : null;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 sm:gap-5">
        <StatCard label="Règles actives" value={RULES.length} hint="Évaluées à chaque fenêtre" />
        <StatCard
          label="Seuil d'alerte"
          value={alertScore !== null ? `${alertScore}/100` : '—'}
          hint={`Total des règles : ${totalPoints} points, plafonné à 100`}
          tone="warning"
        />
        <StatCard
          label="Seuil d'arrêt automatique"
          value={
            detection?.auto_kill_score_threshold !== undefined
              ? `${detection.auto_kill_score_threshold}/100`
              : '—'
          }
          hint="Au-delà, le processus est arrêté sans validation humaine"
          tone="danger"
        />
        <StatCard
          label="Fenêtre d'analyse"
          value="10 s"
          hint="Fenêtre glissante, cloisonnée par terminal"
        />
      </div>

      <Panel
        title="Règles comportementales"
        subtitle="Chaque règle ajoute des points ; le total normalisé constitue le score de risque"
      >
        <div className="space-y-4">
          {RULES.map((rule) => (
            <div
              key={rule.id}
              className="border border-border rounded-xl p-5 hover:shadow-sm transition-shadow"
            >
              <div className="flex items-start justify-between gap-4 mb-3">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 rounded-md bg-brand-primaryGlow text-brand-primary flex items-center justify-center text-[10px] font-bold">
                    {rule.id}
                  </span>
                  <h3 className="text-sm font-bold tracking-tight">{rule.name}</h3>
                </div>
                <span className="badge badge-warning shrink-0">+{rule.points} points</span>
              </div>

              <div className="space-y-2 pl-9">
                <div>
                  <span className="stat-label">Condition de déclenchement</span>
                  <p className="text-xs text-slate-700 mt-0.5 font-mono">{rule.condition}</p>
                </div>
                <div>
                  <span className="stat-label">Pourquoi cette règle</span>
                  <p className="text-xs text-text-muted mt-0.5 leading-relaxed">{rule.rationale}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Du score à la décision">
        <div className="text-xs text-text-muted leading-relaxed space-y-2">
          <p>
            Une alerte est levée si <strong>l'un des deux moteurs</strong> se déclenche : les règles
            ci-dessus, ou le modèle Random Forest. Le score porté par l'alerte est le maximum entre
            le score heuristique normalisé et la probabilité rendue par le modèle, ce qui garantit
            qu'une détection purement statistique n'arrive pas avec un score nul.
          </p>
          <p>
            Ce score est distinct du compteur d'activité du processus suspect, conservé dans la
            fiche d'alerte comme élément de preuve. Ce dernier n'est pas borné : il compte les
            fichiers touchés et ne peut donc pas servir de niveau de gravité, sous peine de faire
            passer un serveur de fichiers actif pour un rançongiciel.
          </p>
        </div>
      </Panel>

      <Panel title="Phase d'apprentissage">
        <div className="flex items-start gap-3">
          <List className="w-4 h-4 text-text-muted mt-0.5 shrink-0" />
          <div className="text-xs text-text-muted leading-relaxed space-y-2">
            <p>
              Chaque terminal dispose de sa propre baseline. Tant que le nombre de fenêtres observées
              est insuffisant, le moteur enregistre les métriques sans lever d'alerte : les règles 1
              et 2 dépendent d'un Z-score qui n'a pas de sens sans référence.
            </p>
            <p>
              Cette séparation par machine est nécessaire : un serveur de fichiers et un poste
              bureautique n'ont pas le même volume d'activité normal, et une baseline commune
              produirait des faux positifs sur l'un et des faux négatifs sur l'autre.
            </p>
          </div>
        </div>
      </Panel>
    </div>
  );
}
