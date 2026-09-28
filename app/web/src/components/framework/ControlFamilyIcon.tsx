import {
  Activity,
  Bot,
  Boxes,
  Bug,
  Building2,
  CheckCheck,
  Code2,
  Database,
  FileClock,
  Fingerprint,
  GitBranch,
  HeartPulse,
  Landmark,
  Layers,
  LockKeyhole,
  Network,
  Radar,
  Scale,
  ShieldAlert,
  SlidersHorizontal,
  UserCheck,
  Users,
  Workflow,
  Wrench,
} from "lucide-react";

const FAMILIES = {
  identity: { label: "Identity & access", icon: Fingerprint },
  "data-protection": { label: "Data protection", icon: Database },
  "change-management": { label: "Change management", icon: GitBranch },
  governance: { label: "Governance", icon: Landmark },
  detection: { label: "Detection", icon: Radar },
  logging: { label: "Logging", icon: FileClock },
  "vulnerability-management": { label: "Vulnerability management", icon: Bug },
  "third-party-risk": { label: "Third-party risk", icon: Users },
  "risk-management": { label: "Risk management", icon: Scale },
  availability: { label: "Availability", icon: HeartPulse },
  "ai-governance": { label: "AI governance", icon: Bot },
  "incident-response": { label: "Incident response", icon: ShieldAlert },
  privacy: { label: "Privacy", icon: LockKeyhole },
  "controls-operations": { label: "Control operations", icon: Workflow },
  monitoring: { label: "Monitoring", icon: Activity },
  "configuration-management": {
    label: "Configuration management",
    icon: SlidersHorizontal,
  },
  "secure-development": { label: "Secure development", icon: Code2 },
  "secure-architecture": { label: "Secure architecture", icon: Boxes },
  "network-security": { label: "Network security", icon: Network },
  "people-security": { label: "People security", icon: UserCheck },
  "physical-security": { label: "Physical security", icon: Building2 },
  "system-maintenance": { label: "System maintenance", icon: Wrench },
  "processing-integrity": { label: "Processing integrity", icon: CheckCheck },
};

export function controlFamily(domain: string) {
  return (
    FAMILIES[domain as keyof typeof FAMILIES] ?? {
      label: domain.replaceAll("-", " "),
      icon: Layers,
    }
  );
}

export function ControlFamilyIcon({ domain }: { domain: string }) {
  const { icon: Icon } = controlFamily(domain);
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surfaceMuted text-muted"
    >
      <Icon className="h-[18px] w-[18px]" />
    </span>
  );
}
