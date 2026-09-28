"use client";

import Image from "next/image";
import {
  Bot,
  BrainCircuit,
  Cloud,
  CreditCard,
  HeartPulse,
  Landmark,
  Layers,
  LockKeyhole,
  Scale,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { frameworkVisual } from "@/lib/framework-visuals";
import { cn } from "@/lib/utils";

const ICONS = {
  shield: ShieldCheck,
  brain: BrainCircuit,
  lock: LockKeyhole,
  sparkles: Sparkles,
  "heart-pulse": HeartPulse,
  "credit-card": CreditCard,
  scale: Scale,
  bot: Bot,
  cloud: Cloud,
  landmark: Landmark,
  layers: Layers,
};

export function FrameworkMark({
  frameworkId,
  fallbackLabel,
  size = 40,
  className,
}: {
  frameworkId: string;
  fallbackLabel?: string;
  size?: number;
  className?: string;
}) {
  const visual = frameworkVisual(frameworkId, fallbackLabel);
  const Icon = ICONS[visual.icon];

  return (
    <span
      className={cn(
        "relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full border font-semibold",
        className,
      )}
      style={{
        width: size,
        height: size,
        background: visual.badge ? "#12365a" : visual.gradient,
        borderColor: "#ffffff40",
        color: "#ffffff",
      }}
      role="img"
      aria-label={`${visual.label} framework`}
    >
      {visual.badge ? (
        <Image
          src={visual.badge}
          alt=""
          width={size}
          height={size}
          className="h-full w-full object-cover"
        />
      ) : (
        <span className="grid place-items-center" aria-hidden="true">
          {size >= 36 ? (
            <Icon style={{ width: size * 0.46, height: size * 0.46 }} />
          ) : (
            <span style={{ fontSize: Math.max(8, size * 0.27) }}>
              {visual.mark}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
